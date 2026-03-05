package sync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
)

func upsertScopedRowsWithChanges(
	ctx context.Context,
	sf *snowflake.Client,
	logger *slog.Logger,
	table string,
	rows []map[string]interface{},
	scopeColumn string,
	scopeValues []string,
	hashFn func(map[string]interface{}) string,
) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	if len(rows) == 0 {
		existing := getExistingHashesByScope(ctx, sf, table, scopeColumn, scopeValues)
		changes = detectRowChanges(existing, map[string]string{}, false)
		if len(changes.Removed) > 0 {
			if err := deleteScopedRowsByScope(ctx, sf, table, scopeColumn, scopeValues); err != nil {
				logger.Debug("delete failed", "table", table, "error", err)
			}
		}
		return changes, nil
	}

	existing := getExistingHashesByScope(ctx, sf, table, scopeColumn, scopeValues)
	newRows := buildRowHashes(rows, hashFn)
	changes = detectRowChanges(existing, newRows, false)

	if err := deleteScopedRowsByScope(ctx, sf, table, scopeColumn, scopeValues); err != nil {
		logger.Debug("delete failed", "table", table, "error", err)
	}

	insertRows := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := hashFn(row)
		newRow := make(map[string]interface{}, len(row)+1)
		newRow["_cq_id"] = id
		newRow["_cq_hash"] = hash
		for key, value := range row {
			if key == "_cq_id" || key == "_cq_hash" {
				continue
			}
			newRow[key] = value
		}
		insertRows = append(insertRows, newRow)
	}

	if err := insertRowsBatch(ctx, sf, table, insertRows); err != nil {
		return changes, fmt.Errorf("insert rows: %w", err)
	}

	return changes, nil
}

func getExistingHashesByScope(ctx context.Context, sf *snowflake.Client, table, scopeColumn string, scopeValues []string) map[string]string {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result
	}

	whereClause, args := scopedWhereClause(scopeColumn, scopeValues)
	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s%s", table, whereClause)
	rows, err := sf.Query(ctx, query, args...)
	if err != nil {
		return result
	}

	return decodeExistingHashes(rows.Rows)
}

func deleteScopedRowsByScope(ctx context.Context, sf *snowflake.Client, table, scopeColumn string, scopeValues []string) error {
	whereClause, args := scopedWhereClause(scopeColumn, scopeValues)
	if whereClause == "" {
		if _, err := sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
			if _, err := sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
				return err
			}
		}
		return nil
	}

	query := fmt.Sprintf("DELETE FROM %s%s", table, whereClause)
	_, err := sf.Exec(ctx, query, args...)
	return err
}

func scopedWhereClause(column string, values []string) (string, []interface{}) {
	if column == "" || len(values) == 0 {
		return "", nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
	args := make([]interface{}, len(values))
	for i, value := range values {
		args[i] = value
	}

	return fmt.Sprintf(" WHERE %s IN (%s)", column, placeholders), args
}

func persistProviderChangeHistory(ctx context.Context, sf *snowflake.Client, logger *slog.Logger, provider string, results []SyncResult) error {
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
		id VARCHAR PRIMARY KEY,
		table_name VARCHAR,
		change_type VARCHAR,
		resource_id VARCHAR,
		sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		provider VARCHAR
	)`

	if _, err := sf.Exec(ctx, createQuery); err != nil {
		return err
	}

	alterQueries := []string{
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS change_type VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS provider VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()",
	}
	for _, query := range alterQueries {
		if _, err := sf.Exec(ctx, query); err != nil {
			logger.Debug("failed to ensure change history column", "query", query, "error", err)
		}
	}

	for _, result := range results {
		if result.Changes == nil {
			continue
		}

		syncTime := result.SyncTime
		if syncTime.IsZero() {
			syncTime = time.Now().UTC()
		}

		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "added", result.Changes.Added, syncTime)
		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "modified", result.Changes.Modified, syncTime)
		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "removed", result.Changes.Removed, syncTime)
	}

	return nil
}

func insertProviderChangeRecord(ctx context.Context, sf *snowflake.Client, logger *slog.Logger, provider, table, changeType string, resourceIDs []string, syncTime time.Time) {
	for _, resourceID := range resourceIDs {
		id := fmt.Sprintf("%s-%s-%s-%d", table, changeType, resourceID, syncTime.UnixNano())
		query := `INSERT INTO _sync_change_history (id, table_name, change_type, resource_id, sync_time, provider)
			SELECT ?, ?, ?, ?, ?, ?`
		if _, err := sf.Exec(ctx, query, id, table, changeType, resourceID, syncTime, provider); err != nil {
			logger.Debug("failed to insert change record", "provider", provider, "table", table, "error", err)
		}
	}
}
