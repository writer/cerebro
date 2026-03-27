package sync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

func upsertScopedRowsWithChanges(
	ctx context.Context,
	sf warehouse.SyncWarehouse,
	logger *slog.Logger,
	table string,
	rows []map[string]interface{},
	scopeColumn string,
	scopeValues []string,
	hashFn func(map[string]interface{}) string,
	incremental bool,
) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	if len(rows) == 0 {
		if incremental {
			return changes, nil
		}
		existing, err := getExistingHashesByScope(ctx, sf, table, scopeColumn, scopeValues)
		if err != nil {
			return changes, fmt.Errorf("get existing hashes: %w", err)
		}
		changes = detectRowChanges(existing, map[string]string{}, false)
		if len(changes.Removed) > 0 {
			if err := deleteScopedRowsByScope(ctx, sf, table, scopeColumn, scopeValues); err != nil {
				return changes, fmt.Errorf("delete scoped rows: %w", err)
			}
		}
		return changes, nil
	}

	rows = dedupeRowsByID(rows)
	existing, err := getExistingHashesByScope(ctx, sf, table, scopeColumn, scopeValues)
	if err != nil {
		return changes, fmt.Errorf("get existing hashes: %w", err)
	}
	newRows := buildRowHashes(rows, hashFn)
	changes = detectRowChanges(existing, newRows, incremental)

	mergeRows := make([]map[string]interface{}, 0, len(rows))
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
		mergeRows = append(mergeRows, newRow)
	}

	// Atomic upsert via MERGE - no delete-before-insert window.
	if err := mergeRowsBatch(ctx, sf, table, mergeRows); err != nil {
		return changes, fmt.Errorf("merge rows: %w", err)
	}

	if !incremental && len(changes.Removed) > 0 {
		removed := make(map[string]string, len(changes.Removed))
		for _, id := range changes.Removed {
			removed[id] = ""
		}
		if err := deleteRowsByIDByScope(ctx, sf, table, removed, scopeColumn, scopeValues); err != nil {
			return changes, fmt.Errorf("delete removed rows: %w", err)
		}
	}

	return changes, nil
}

func getExistingHashesByScope(ctx context.Context, sf warehouse.SyncWarehouse, table, scopeColumn string, scopeValues []string) (map[string]string, error) {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result, err
	}

	whereClause, args := scopedWhereClauseForWarehouse(sf, scopeColumn, scopeValues)
	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s%s", table, whereClause)
	rows, err := sf.Query(ctx, query, args...)
	if err != nil {
		return result, err
	}

	return decodeExistingHashes(rows.Rows), nil
}

func deleteRowsByIDByScope(ctx context.Context, sf warehouse.SyncWarehouse, table string, ids map[string]string, scopeColumn string, scopeValues []string) error {
	if len(ids) == 0 {
		return nil
	}

	keys := make([]string, 0, len(ids))
	for id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		keys = append(keys, id)
	}
	if len(keys) == 0 {
		return nil
	}

	scopeWhere, scopeArgs := scopedWhereClauseForWarehouse(sf, scopeColumn, scopeValues)
	scopeCondition := strings.TrimPrefix(scopeWhere, " WHERE ")

	for start := 0; start < len(keys); start += insertBatchSize {
		end := start + insertBatchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[start:end]
		placeholders := strings.Join(warehouse.Placeholders(sf, 1, len(batch)), ",")
		args := make([]interface{}, 0, len(batch)+len(scopeArgs))
		for _, id := range batch {
			args = append(args, id)
		}

		query := fmt.Sprintf("DELETE FROM %s WHERE _CQ_ID IN (%s)", table, placeholders)
		if scopeCondition != "" {
			query = fmt.Sprintf("%s AND %s", query, scopeCondition)
			args = append(args, scopeArgs...)
		}

		if _, err := sf.Exec(ctx, query, args...); err != nil {
			return err
		}
	}

	return nil
}

func deleteScopedRowsByScope(ctx context.Context, sf warehouse.SyncWarehouse, table, scopeColumn string, scopeValues []string) error {
	whereClause, args := scopedWhereClauseForWarehouse(sf, scopeColumn, scopeValues)
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
	return scopedWhereClauseWithTarget(nil, column, values)
}

func scopedWhereClauseForWarehouse(sf warehouse.SyncWarehouse, column string, values []string) (string, []interface{}) {
	return scopedWhereClauseWithTarget(sf, column, values)
}

func scopedWhereClauseWithTarget(target any, column string, values []string) (string, []interface{}) {
	if column == "" || len(values) == 0 {
		return "", nil
	}

	placeholders := strings.Join(warehouse.Placeholders(target, 1, len(values)), ",")
	args := make([]interface{}, len(values))
	for i, value := range values {
		args[i] = value
	}

	return fmt.Sprintf(" WHERE %s IN (%s)", column, placeholders), args
}

func persistProviderChangeHistory(ctx context.Context, sf warehouse.SyncWarehouse, logger *slog.Logger, provider string, results []SyncResult) error {
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
		id VARCHAR PRIMARY KEY,
		table_name VARCHAR,
		resource_id VARCHAR,
		operation VARCHAR,
		region VARCHAR,
		account_id VARCHAR,
		provider VARCHAR,
		timestamp ` + warehouse.TimestampColumnType(sf) + `,
		_cq_sync_time ` + warehouse.TimestampColumnType(sf) + ` DEFAULT CURRENT_TIMESTAMP()
	)`

	if _, err := sf.Exec(ctx, createQuery); err != nil {
		return err
	}

	alterQueries := []string{
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS operation VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS region VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS account_id VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS provider VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS timestamp " + warehouse.TimestampColumnType(sf),
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

		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "add", result.Region, result.Changes.Added, syncTime)
		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "modify", result.Region, result.Changes.Modified, syncTime)
		insertProviderChangeRecord(ctx, sf, logger, provider, result.Table, "remove", result.Region, result.Changes.Removed, syncTime)
	}

	return nil
}

func insertProviderChangeRecord(ctx context.Context, sf warehouse.SyncWarehouse, logger *slog.Logger, provider, table, operation, region string, resourceIDs []string, syncTime time.Time) {
	for _, resourceID := range resourceIDs {
		id := fmt.Sprintf("%s-%s-%s-%d", table, operation, resourceID, syncTime.UnixNano())
		query := fmt.Sprintf(
			"INSERT INTO _sync_change_history (id, table_name, resource_id, operation, region, account_id, provider, timestamp) VALUES (%s)",
			strings.Join(warehouse.Placeholders(sf, 1, 8), ", "),
		)
		if _, err := sf.Exec(ctx, query, id, table, resourceID, operation, region, "", provider, syncTime); err != nil {
			logger.Debug("failed to insert change record", "provider", provider, "table", table, "error", err)
		}
	}
}
