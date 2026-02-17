package providers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

const providerInsertBatchSize = 200

type providerSnowflakeClient interface {
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	Query(ctx context.Context, query string, args ...interface{}) (*snowflake.QueryResult, error)
}

func (b *BaseProvider) SetSnowflakeClient(client *snowflake.Client) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.snowflake = client
}

func (b *BaseProvider) getSnowflakeClient() *snowflake.Client {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.snowflake
}

func (b *BaseProvider) syncTable(ctx context.Context, schema TableSchema, rows []map[string]interface{}) (*TableResult, error) {
	result := &TableResult{Name: schema.Name, Rows: int64(len(rows))}
	sf := b.getSnowflakeClient()
	if sf == nil {
		result.Inserted = result.Rows
		return result, nil
	}

	columns := schemaColumnNames(schema.Columns)
	if err := ensureProviderTable(ctx, sf, schema.Name, columns); err != nil {
		return result, err
	}

	prepared, skipped := prepareProviderRows(schema, rows)
	if skipped > 0 {
		result.Rows = int64(len(prepared))
	}

	if err := truncateProviderTable(ctx, sf, schema.Name); err != nil {
		return result, err
	}
	if err := insertProviderRows(ctx, sf, schema.Name, prepared); err != nil {
		return result, err
	}

	result.Rows = int64(len(prepared))
	result.Inserted = result.Rows
	return result, nil
}

func schemaColumnNames(columns []ColumnSchema) []string {
	names := make([]string, 0, len(columns))
	for _, column := range columns {
		names = append(names, column.Name)
	}
	return names
}

func ensureProviderTable(ctx context.Context, sf providerSnowflakeClient, table string, columns []string) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	filtered := make([]string, 0, len(columns))
	for _, col := range columns {
		if isProviderReservedColumn(col) {
			continue
		}
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
		filtered = append(filtered, col)
	}

	colDefs := make([]string, len(filtered))
	for i, col := range filtered {
		colDefs[i] = fmt.Sprintf("%s VARIANT", strings.ToUpper(col))
	}

	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		_CQ_HASH VARCHAR,
		%s
	)`, table, strings.Join(colDefs, ", "))

	if _, err := sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	existingCols, err := getProviderTableColumns(ctx, sf, table)
	if err != nil {
		return fmt.Errorf("get existing columns: %w", err)
	}

	existingSet := make(map[string]bool)
	for _, col := range existingCols {
		existingSet[strings.ToUpper(col)] = true
	}

	if !existingSet["_CQ_HASH"] {
		if _, err := sf.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS _CQ_HASH VARCHAR", table)); err != nil {
			return fmt.Errorf("add _CQ_HASH column: %w", err)
		}
	}

	for _, col := range filtered {
		upper := strings.ToUpper(col)
		if existingSet[upper] {
			continue
		}
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s VARIANT", table, upper)
		if _, err := sf.Exec(ctx, alterQuery); err != nil {
			return fmt.Errorf("add column %s: %w", col, err)
		}
	}

	return nil
}

func getProviderTableColumns(ctx context.Context, sf providerSnowflakeClient, table string) ([]string, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, err
	}

	query := `
		SELECT COLUMN_NAME
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_NAME = ?
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`

	result, err := sf.Query(ctx, query, strings.ToUpper(table))
	if err != nil {
		return nil, err
	}

	columns := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		if col, ok := row["column_name"].(string); ok {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func truncateProviderTable(ctx context.Context, sf providerSnowflakeClient, table string) error {
	if _, err := sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
		if _, err := sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			return fmt.Errorf("truncate table: %w", err)
		}
	}
	return nil
}

func prepareProviderRows(schema TableSchema, rows []map[string]interface{}) ([]map[string]interface{}, int) {
	prepared := make([]map[string]interface{}, 0, len(rows))
	skipped := 0
	for _, row := range rows {
		projected := projectProviderRow(row, schema.Columns)
		id, ok := buildProviderRowID(projected, schema.PrimaryKey)
		if !ok {
			skipped++
			continue
		}
		projected["_cq_id"] = id
		projected["_cq_hash"] = hashProviderRow(projected)
		prepared = append(prepared, projected)
	}
	return prepared, skipped
}

func projectProviderRow(row map[string]interface{}, columns []ColumnSchema) map[string]interface{} {
	projected := make(map[string]interface{}, len(columns))
	for _, column := range columns {
		if value, ok := lookupProviderValue(row, column.Name); ok {
			projected[column.Name] = value
		}
	}
	return projected
}

func lookupProviderValue(row map[string]interface{}, column string) (interface{}, bool) {
	if value, ok := row[column]; ok {
		return value, true
	}
	lower := strings.ToLower(column)
	if value, ok := row[lower]; ok {
		return value, true
	}
	for key, value := range row {
		if strings.EqualFold(key, column) {
			return value, true
		}
	}
	return nil, false
}

func buildProviderRowID(row map[string]interface{}, keys []string) (string, bool) {
	if len(keys) == 0 {
		return "", false
	}

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := lookupProviderValue(row, key)
		if !ok {
			return "", false
		}
		text := formatProviderIDValue(value)
		if text == "" {
			return "", false
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "|"), true
}

func formatProviderIDValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case fmt.Stringer:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	default:
		encoded, err := json.Marshal(v)
		if err == nil {
			return string(encoded)
		}
		return fmt.Sprint(v)
	}
}

func insertProviderRows(ctx context.Context, sf providerSnowflakeClient, table string, rows []map[string]interface{}) error {
	if len(rows) == 0 {
		return nil
	}

	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			if isProviderReservedColumn(key) {
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

	for _, col := range allColumns {
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}

	for start := 0; start < len(rows); start += providerInsertBatchSize {
		end := start + providerInsertBatchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		selects := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*len(allColumns))

		for _, row := range batch {
			id, _ := row["_cq_id"].(string)
			hash, _ := row["_cq_hash"].(string)
			if id == "" {
				continue
			}

			rowUpper := make(map[string]interface{}, len(row))
			for key, value := range row {
				rowUpper[strings.ToUpper(key)] = value
			}

			selectParts := make([]string, 0, len(allColumns))
			selectParts = append(selectParts, "?", "?")
			args = append(args, id, hash)

			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				selectParts = append(selectParts, "PARSE_JSON(?)")
				args = append(args, string(jsonVal))
			}

			selects = append(selects, "SELECT "+strings.Join(selectParts, ", "))
		}

		if len(selects) == 0 {
			continue
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) %s",
			table, strings.Join(allColumns, ", "), strings.Join(selects, " UNION ALL "))

		if _, err := sf.Exec(ctx, query, args...); err != nil {
			return err
		}
	}

	return nil
}

func hashProviderRow(row map[string]interface{}) string {
	keys := make([]string, 0, len(row))
	for key := range row {
		if isProviderReservedColumn(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, _ := json.Marshal(row[key])
		parts = append(parts, fmt.Sprintf("%q:%s", key, string(value)))
	}

	data := "{" + strings.Join(parts, ",") + "}"
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func isProviderReservedColumn(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "_CQ_ID", "_CQ_HASH", "_CQ_SYNC_TIME":
		return true
	default:
		return false
	}
}

func schemaByName(schemas []TableSchema, name string) (TableSchema, bool) {
	for _, schema := range schemas {
		if schema.Name == name {
			return schema, true
		}
	}
	return TableSchema{}, false
}
