package tableops

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

const DefaultInsertBatchSize = 200

type ExecClient interface {
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type QueryExecClient interface {
	ExecClient
	Query(ctx context.Context, query string, args ...interface{}) (*snowflake.QueryResult, error)
}

type EnsureVariantTableOptions struct {
	ReservedColumns       map[string]struct{}
	AddMissingColumns     bool
	IgnoreLookupError     bool
	IgnoreAddColumnErrors bool
}

func EnsureVariantTable(ctx context.Context, client QueryExecClient, table string, columns []string, options EnsureVariantTableOptions) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	reserved := normalizeReserved(options.ReservedColumns)
	filtered := filteredColumns(columns, reserved)
	if err := validateColumns(filtered); err != nil {
		return err
	}

	colDefs := make([]string, 0, len(filtered)+3)
	colDefs = append(colDefs,
		"_CQ_ID VARCHAR PRIMARY KEY",
		fmt.Sprintf("_CQ_SYNC_TIME %s DEFAULT CURRENT_TIMESTAMP()", warehouse.TimestampColumnType(client)),
	)
	colDefs = append(colDefs, "_CQ_HASH VARCHAR")
	for _, col := range filtered {
		colDefs = append(colDefs, fmt.Sprintf("%s %s", col, warehouse.JSONColumnType(client)))
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
	desired = append(desired, "_CQ_HASH")
	desired = append(desired, filtered...)

	for _, col := range columnsMissingFromSchema(existingCols, desired) {
		columnType := warehouse.JSONColumnType(client)
		if col == "_CQ_HASH" {
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

func InsertVariantRowsBatch(ctx context.Context, client ExecClient, table string, rows []map[string]interface{}, reservedColumns map[string]struct{}, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	if batchSize <= 0 {
		batchSize = DefaultInsertBatchSize
	}

	reserved := normalizeReserved(reservedColumns)
	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			if _, skip := reserved[strings.ToUpper(key)]; skip {
				continue
			}
			columnSet[strings.ToUpper(key)] = struct{}{}
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

	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		values := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*len(allColumns))

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

			valueParts := make([]string, 0, len(allColumns))
			valueParts = append(valueParts, warehouse.Placeholder(client, len(args)+1), warehouse.Placeholder(client, len(args)+2))
			args = append(args, id, hash)

			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				valueParts = append(valueParts, warehouse.JSONPlaceholder(client, len(args)+1))
				args = append(args, string(jsonVal))
			}

			values = append(values, "("+strings.Join(valueParts, ", ")+")")
		}

		if len(values) == 0 {
			continue
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s", table, strings.Join(allColumns, ", "), strings.Join(values, ", "))
		if _, err := client.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("insert rows: %w", err)
		}
	}

	return nil
}

// MergeVariantRowsBatch atomically upserts rows using MERGE INTO so that a
// failed batch never leaves the target table with missing data (no
// delete-before-insert window). Rows are matched on _CQ_ID.
func MergeVariantRowsBatch(ctx context.Context, client ExecClient, table string, rows []map[string]interface{}, reservedColumns map[string]struct{}, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	if batchSize <= 0 {
		batchSize = DefaultInsertBatchSize
	}

	reserved := normalizeReserved(reservedColumns)
	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			if _, skip := reserved[strings.ToUpper(key)]; skip {
				continue
			}
			columnSet[strings.ToUpper(key)] = struct{}{}
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

	dialect := warehouse.Dialect(client)
	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		var (
			query string
			args  []interface{}
		)
		if dialect == warehouse.SQLDialectSnowflake {
			query, args = buildSnowflakeMergeQuery(batch, columns, allColumns, client, table)
		} else {
			query, args = buildUpsertQuery(batch, columns, allColumns, client, table)
		}
		if strings.TrimSpace(query) == "" {
			continue
		}
		if _, err := client.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("merge rows: %w", err)
		}
	}

	return nil
}

func buildSnowflakeMergeQuery(batch []map[string]interface{}, columns, allColumns []string, client ExecClient, table string) (string, []interface{}) {
	selects := make([]string, 0, len(batch))
	args := make([]interface{}, 0, len(batch)*len(allColumns))
	firstSelect := true

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

		parts := make([]string, 0, len(allColumns))
		args = append(args, id, hash)

		if firstSelect {
			parts = append(parts, "? AS _CQ_ID", "? AS _CQ_HASH")
			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				parts = append(parts, fmt.Sprintf("PARSE_JSON(?) AS %s", col))
				args = append(args, string(jsonVal))
			}
			firstSelect = false
		} else {
			parts = append(parts, "?", "?")
			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				parts = append(parts, "PARSE_JSON(?)")
				args = append(args, string(jsonVal))
			}
		}

		selects = append(selects, "SELECT "+strings.Join(parts, ", "))
	}

	if len(selects) == 0 {
		return "", nil
	}

	usingClause := strings.Join(selects, " UNION ALL ")
	updateParts := make([]string, 0, len(columns)+1)
	updateParts = append(updateParts, "t._CQ_HASH = s._CQ_HASH")
	for _, col := range columns {
		updateParts = append(updateParts, fmt.Sprintf("t.%s = s.%s", col, col))
	}

	insertCols := strings.Join(allColumns, ", ")
	insertVals := make([]string, 0, len(allColumns))
	for _, col := range allColumns {
		insertVals = append(insertVals, "s."+col)
	}

	query := fmt.Sprintf(
		"MERGE INTO %s t USING (%s) s ON t._CQ_ID = s._CQ_ID "+
			"WHEN MATCHED THEN UPDATE SET %s "+
			"WHEN NOT MATCHED THEN INSERT (%s) VALUES (%s)",
		table, usingClause, strings.Join(updateParts, ", "),
		insertCols, strings.Join(insertVals, ", "),
	)
	return query, args
}

func buildUpsertQuery(batch []map[string]interface{}, columns, allColumns []string, client ExecClient, table string) (string, []interface{}) {
	values := make([]string, 0, len(batch))
	args := make([]interface{}, 0, len(batch)*len(allColumns))

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

		valueParts := make([]string, 0, len(allColumns))
		valueParts = append(valueParts, warehouse.Placeholder(client, len(args)+1), warehouse.Placeholder(client, len(args)+2))
		args = append(args, id, hash)

		for _, col := range columns {
			jsonVal, _ := json.Marshal(rowUpper[col])
			valueParts = append(valueParts, warehouse.JSONPlaceholder(client, len(args)+1))
			args = append(args, string(jsonVal))
		}

		values = append(values, "("+strings.Join(valueParts, ", ")+")")
	}

	if len(values) == 0 {
		return "", nil
	}

	updateParts := make([]string, 0, len(columns)+1)
	updateParts = append(updateParts, "_CQ_HASH = EXCLUDED._CQ_HASH")
	for _, col := range columns {
		updateParts = append(updateParts, fmt.Sprintf("%s = EXCLUDED.%s", col, col))
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s ON CONFLICT (_CQ_ID) DO UPDATE SET %s",
		table,
		strings.Join(allColumns, ", "),
		strings.Join(values, ", "),
		strings.Join(updateParts, ", "),
	)
	return query, args
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
		filtered = append(filtered, upper)
	}
	return filtered
}

func validateColumns(columns []string) error {
	for _, col := range columns {
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}
	return nil
}

func tableColumns(ctx context.Context, client QueryExecClient, table string) ([]string, error) {
	if memory, ok := any(client).(*warehouse.MemoryWarehouse); ok && memory.DescribeColumnsFunc == nil {
		// Preserve query-based behavior for tests that stub INFORMATION_SCHEMA reads
		// via QueryFunc without wiring DescribeColumnsFunc explicitly.
	} else if describer, ok := any(client).(interface {
		DescribeColumns(context.Context, string) ([]string, error)
	}); ok {
		return describer.DescribeColumns(ctx, table)
	}

	query := `
		SELECT COLUMN_NAME
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_NAME = ` + warehouse.Placeholder(client, 1) + `
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`

	result, err := client.Query(ctx, query, strings.ToUpper(table))
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
		existingSet[strings.ToUpper(strings.TrimSpace(col))] = struct{}{}
	}

	missing := make([]string, 0)
	for _, col := range desired {
		upper := strings.ToUpper(strings.TrimSpace(col))
		if upper == "" {
			continue
		}
		if _, ok := existingSet[upper]; !ok {
			missing = append(missing, upper)
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
