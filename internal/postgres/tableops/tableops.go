package tableops

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/warehouse"
)

// DefaultInsertBatchSize is the default number of rows per batch insert.
const DefaultInsertBatchSize = 200

// ExecClient is the interface for executing SQL statements.
type ExecClient interface {
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// QueryExecClient extends ExecClient with query capabilities.
type QueryExecClient interface {
	ExecClient
	Query(ctx context.Context, query string, args ...interface{}) (*warehouse.QueryResult, error)
}

// EnsureVariantTableOptions configures EnsureTable behavior.
type EnsureVariantTableOptions struct {
	ReservedColumns       map[string]struct{}
	AddMissingColumns     bool
	IgnoreLookupError     bool
	IgnoreAddColumnErrors bool
}

// EnsureTable creates a table with JSONB columns if it does not exist.
// Uses Postgres JSONB instead of Snowflake VARIANT.
func EnsureTable(ctx context.Context, client QueryExecClient, table string, columns []string, options EnsureVariantTableOptions) error {
	if err := postgres.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	reserved := normalizeReserved(options.ReservedColumns)
	filtered := filteredColumns(columns, reserved)
	if err := validateColumns(filtered); err != nil {
		return err
	}

	colDefs := make([]string, 0, len(filtered)+3)
	colDefs = append(colDefs,
		"_cq_id VARCHAR PRIMARY KEY",
		"_cq_sync_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
	)
	colDefs = append(colDefs, "_cq_hash VARCHAR")
	for _, col := range filtered {
		colDefs = append(colDefs, fmt.Sprintf("%s JSONB", col))
	}

	createQuery := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n\t%s\n)", table, strings.Join(colDefs, ",\n\t"))
	if _, err := client.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	if !options.AddMissingColumns {
		return nil
	}

	existingCols, err := tableColumns(ctx, client, table)
	if err != nil {
		if options.IgnoreLookupError {
			return nil
		}
		return fmt.Errorf("get table columns: %w", err)
	}

	desired := make([]string, 0, len(filtered)+1)
	desired = append(desired, "_cq_hash")
	desired = append(desired, filtered...)

	for _, col := range columnsMissingFromSchema(existingCols, desired) {
		columnType := "JSONB"
		if strings.EqualFold(col, "_cq_hash") {
			columnType = "VARCHAR"
		}
		query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s", table, col, columnType)
		if _, err := client.Exec(ctx, query); err != nil {
			if options.IgnoreAddColumnErrors {
				continue
			}
			return fmt.Errorf("add column %s: %w", col, err)
		}
	}

	return nil
}

// InsertRowsBatch inserts rows into a Postgres table using $N placeholders
// and $N::jsonb for JSONB columns.
func InsertRowsBatch(ctx context.Context, client ExecClient, table string, rows []map[string]interface{}, reservedColumns map[string]struct{}, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if err := postgres.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	if batchSize <= 0 {
		batchSize = DefaultInsertBatchSize
	}

	reserved := normalizeReserved(reservedColumns)
	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			upper := strings.ToUpper(key)
			if _, skip := reserved[upper]; skip {
				continue
			}
			columnSet[upper] = struct{}{}
		}
	}

	columns := make([]string, 0, len(columnSet))
	for col := range columnSet {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	allColumns := append([]string{"_CQ_ID", "_CQ_HASH"}, columns...)
	if err := validateColumns(allColumns); err != nil {
		return err
	}

	// Use lowercase column names for Postgres.
	lowerColumns := make([]string, len(allColumns))
	for i, c := range allColumns {
		lowerColumns[i] = strings.ToLower(c)
	}

	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		valuePlaceholders := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*len(allColumns))
		argIdx := 1

		for _, row := range batch {
			rowUpper := make(map[string]interface{}, len(row))
			for key, value := range row {
				rowUpper[strings.ToUpper(key)] = value
			}

			id := strings.TrimSpace(stringValue(rowUpper["_CQ_ID"]))
			if id == "" {
				continue
			}
			hash := stringValue(rowUpper["_CQ_HASH"])

			placeholders := make([]string, 0, len(allColumns))
			// _CQ_ID
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIdx))
			args = append(args, id)
			argIdx++
			// _CQ_HASH
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIdx))
			args = append(args, hash)
			argIdx++

			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				placeholders = append(placeholders, fmt.Sprintf("$%d::jsonb", argIdx))
				args = append(args, string(jsonVal))
				argIdx++
			}

			valuePlaceholders = append(valuePlaceholders, "("+strings.Join(placeholders, ", ")+")")
		}

		if len(valuePlaceholders) == 0 {
			continue
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s",
			table, strings.Join(lowerColumns, ", "), strings.Join(valuePlaceholders, ", "))
		if _, err := client.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("insert rows: %w", err)
		}
	}

	return nil
}

// MergeRowsBatch atomically upserts rows using INSERT ON CONFLICT (_cq_id) DO UPDATE.
// Replaces Snowflake's MERGE INTO pattern.
func MergeRowsBatch(ctx context.Context, client ExecClient, table string, rows []map[string]interface{}, reservedColumns map[string]struct{}, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if err := postgres.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	if batchSize <= 0 {
		batchSize = DefaultInsertBatchSize
	}

	reserved := normalizeReserved(reservedColumns)
	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			upper := strings.ToUpper(key)
			if _, skip := reserved[upper]; skip {
				continue
			}
			columnSet[upper] = struct{}{}
		}
	}

	columns := make([]string, 0, len(columnSet))
	for col := range columnSet {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	allColumns := append([]string{"_CQ_ID", "_CQ_HASH"}, columns...)
	if err := validateColumns(allColumns); err != nil {
		return err
	}

	lowerColumns := make([]string, len(allColumns))
	for i, c := range allColumns {
		lowerColumns[i] = strings.ToLower(c)
	}

	// Build UPDATE SET clause for ON CONFLICT.
	updateParts := make([]string, 0, len(columns)+1)
	updateParts = append(updateParts, "_cq_hash = EXCLUDED._cq_hash")
	for _, col := range columns {
		lower := strings.ToLower(col)
		updateParts = append(updateParts, fmt.Sprintf("%s = EXCLUDED.%s", lower, lower))
	}

	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		valuePlaceholders := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*len(allColumns))
		argIdx := 1

		for _, row := range batch {
			rowUpper := make(map[string]interface{}, len(row))
			for key, value := range row {
				rowUpper[strings.ToUpper(key)] = value
			}

			id := strings.TrimSpace(stringValue(rowUpper["_CQ_ID"]))
			if id == "" {
				continue
			}
			hash := stringValue(rowUpper["_CQ_HASH"])

			placeholders := make([]string, 0, len(allColumns))
			// _CQ_ID
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIdx))
			args = append(args, id)
			argIdx++
			// _CQ_HASH
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIdx))
			args = append(args, hash)
			argIdx++

			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				placeholders = append(placeholders, fmt.Sprintf("$%d::jsonb", argIdx))
				args = append(args, string(jsonVal))
				argIdx++
			}

			valuePlaceholders = append(valuePlaceholders, "("+strings.Join(placeholders, ", ")+")")
		}

		if len(valuePlaceholders) == 0 {
			continue
		}

		query := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES %s ON CONFLICT (_cq_id) DO UPDATE SET %s",
			table,
			strings.Join(lowerColumns, ", "),
			strings.Join(valuePlaceholders, ", "),
			strings.Join(updateParts, ", "),
		)

		if _, err := client.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("merge rows: %w", err)
		}
	}

	return nil
}

func normalizeReserved(custom map[string]struct{}) map[string]struct{} {
	reserved := map[string]struct{}{
		"_CQ_ID":        {},
		"_CQ_HASH":      {},
		"_CQ_SYNC_TIME": {},
	}
	for key := range custom {
		reserved[strings.ToUpper(key)] = struct{}{}
	}
	return reserved
}

func filteredColumns(columns []string, reserved map[string]struct{}) []string {
	seen := make(map[string]struct{}, len(columns))
	filtered := make([]string, 0, len(columns))
	for _, col := range columns {
		upper := strings.ToUpper(strings.TrimSpace(col))
		if upper == "" {
			continue
		}
		if _, skip := reserved[upper]; skip {
			continue
		}
		if _, exists := seen[upper]; exists {
			continue
		}
		seen[upper] = struct{}{}
		filtered = append(filtered, strings.ToLower(upper))
	}
	return filtered
}

func validateColumns(columns []string) error {
	for _, col := range columns {
		if err := postgres.ValidateColumnName(strings.ToLower(col)); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}
	return nil
}

func tableColumns(ctx context.Context, client QueryExecClient, table string) ([]string, error) {
	query := `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = $1
		AND table_schema = CURRENT_SCHEMA
	`

	result, err := client.Query(ctx, query, strings.ToLower(table))
	if err != nil {
		return nil, err
	}

	columns := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		if col := strings.TrimSpace(stringValue(lookupCaseInsensitive(row, "column_name"))); col != "" {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func columnsMissingFromSchema(existing, desired []string) []string {
	existingSet := make(map[string]struct{}, len(existing))
	for _, col := range existing {
		existingSet[strings.ToLower(strings.TrimSpace(col))] = struct{}{}
	}

	var missing []string
	for _, col := range desired {
		lower := strings.ToLower(strings.TrimSpace(col))
		if lower == "" {
			continue
		}
		if _, ok := existingSet[lower]; !ok {
			missing = append(missing, lower)
		}
	}
	return missing
}

func lookupCaseInsensitive(row map[string]interface{}, key string) interface{} {
	if row == nil {
		return nil
	}
	if value, ok := row[key]; ok {
		return value
	}
	for existingKey, value := range row {
		if strings.EqualFold(existingKey, key) {
			return value
		}
	}
	return nil
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
