package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

func ensureTypedProviderTable(ctx context.Context, store providerWarehouseClient, table string, columns []ColumnSchema) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	normalizedColumns := normalizedProviderColumns(columns)
	if err := validateProviderColumns(normalizedColumns); err != nil {
		return err
	}

	columnDefs := make([]string, 0, len(normalizedColumns)+3)
	columnDefs = append(columnDefs,
		"_CQ_ID VARCHAR PRIMARY KEY",
		fmt.Sprintf("_CQ_SYNC_TIME %s DEFAULT CURRENT_TIMESTAMP()", warehouse.TimestampColumnType(store)),
		"_CQ_HASH VARCHAR",
	)
	for _, column := range normalizedColumns {
		columnDefs = append(columnDefs, fmt.Sprintf("%s %s", column.Name, providerColumnSQLType(store, column)))
	}

	createQuery := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n\t%s\n)", table, strings.Join(columnDefs, ",\n\t"))
	if _, err := store.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	existingColumns, err := providerTableColumns(ctx, store, table)
	if err != nil {
		return fmt.Errorf("get existing columns: %w", err)
	}

	desiredColumns := append([]ColumnSchema{{Name: "_CQ_HASH", Type: "string"}}, normalizedColumns...)
	for _, column := range providerColumnsMissingFromSchema(existingColumns, desiredColumns) {
		query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s", table, column.Name, providerColumnSQLType(store, column))
		if _, err := store.Exec(ctx, query); err != nil {
			return fmt.Errorf("add column %s: %w", column.Name, err)
		}
	}

	return nil
}

func mergeTypedProviderRows(ctx context.Context, store providerWarehouseClient, table string, columns []ColumnSchema, rows []map[string]interface{}) error {
	if len(rows) == 0 {
		return nil
	}
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	normalizedColumns := normalizedProviderColumns(columns)
	if err := validateProviderColumns(normalizedColumns); err != nil {
		return err
	}

	for start := 0; start < len(rows); start += providerInsertBatchSize {
		end := start + providerInsertBatchSize
		if end > len(rows) {
			end = len(rows)
		}

		query, args, err := buildTypedProviderUpsertQuery(rows[start:end], normalizedColumns, store, table)
		if err != nil {
			return err
		}
		if strings.TrimSpace(query) == "" {
			continue
		}
		if _, err := store.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("merge rows: %w", err)
		}
	}

	return nil
}

func buildTypedProviderUpsertQuery(batch []map[string]interface{}, columns []ColumnSchema, store providerWarehouseClient, table string) (string, []interface{}, error) {
	allColumns := make([]string, 0, len(columns)+2)
	allColumns = append(allColumns, "_CQ_ID", "_CQ_HASH")
	for _, column := range columns {
		allColumns = append(allColumns, column.Name)
	}

	values := make([]string, 0, len(batch))
	args := make([]interface{}, 0, len(batch)*len(allColumns))

	for _, row := range batch {
		idValue, _ := lookupProviderValue(row, "_cq_id")
		id := strings.TrimSpace(providerStringValue(idValue))
		if id == "" {
			continue
		}

		hashValue, _ := lookupProviderValue(row, "_cq_hash")
		hash := providerStringValue(hashValue)

		valueParts := make([]string, 0, len(allColumns))
		valueParts = append(valueParts, warehouse.Placeholder(store, len(args)+1), warehouse.Placeholder(store, len(args)+2))
		args = append(args, id, hash)

		for _, column := range columns {
			rawValue, _ := lookupProviderValue(row, column.Name)
			valueParts = append(valueParts, providerColumnPlaceholder(store, column, len(args)+1))
			args = append(args, coerceProviderColumnValue(column, rawValue))
		}

		values = append(values, "("+strings.Join(valueParts, ", ")+")")
	}

	if len(values) == 0 {
		return "", nil, nil
	}

	updateParts := make([]string, 0, len(columns)+1)
	updateParts = append(updateParts, "_CQ_HASH = EXCLUDED._CQ_HASH")
	for _, column := range columns {
		updateParts = append(updateParts, fmt.Sprintf("%s = EXCLUDED.%s", column.Name, column.Name))
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s ON CONFLICT (_CQ_ID) DO UPDATE SET %s",
		table,
		strings.Join(allColumns, ", "),
		strings.Join(values, ", "),
		strings.Join(updateParts, ", "),
	)
	return query, args, nil
}

func providerTableColumns(ctx context.Context, store providerWarehouseClient, table string) ([]string, error) {
	query := `
		SELECT COLUMN_NAME
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_NAME = ` + warehouse.Placeholder(store, 1) + `
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`

	result, err := store.Query(ctx, query, strings.ToUpper(table))
	if err != nil {
		return nil, err
	}

	columns := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		value, _ := lookupProviderValue(row, "column_name")
		if name := strings.TrimSpace(providerStringValue(value)); name != "" {
			columns = append(columns, name)
		}
	}
	return columns, nil
}

func normalizedProviderColumns(columns []ColumnSchema) []ColumnSchema {
	seen := make(map[string]struct{}, len(columns))
	normalized := make([]ColumnSchema, 0, len(columns))
	for _, column := range columns {
		name := strings.ToUpper(strings.TrimSpace(column.Name))
		if name == "" || isProviderReservedColumn(name) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		column.Name = name
		normalized = append(normalized, column)
	}
	return normalized
}

func validateProviderColumns(columns []ColumnSchema) error {
	for _, column := range columns {
		if err := snowflake.ValidateColumnName(column.Name); err != nil {
			return fmt.Errorf("invalid column name %q: %w", column.Name, err)
		}
	}
	return nil
}

func providerColumnsMissingFromSchema(existing []string, desired []ColumnSchema) []ColumnSchema {
	existingSet := make(map[string]struct{}, len(existing))
	for _, column := range existing {
		existingSet[strings.ToUpper(strings.TrimSpace(column))] = struct{}{}
	}

	missing := make([]ColumnSchema, 0, len(desired))
	for _, column := range desired {
		name := strings.ToUpper(strings.TrimSpace(column.Name))
		if name == "" {
			continue
		}
		if _, exists := existingSet[name]; exists {
			continue
		}
		column.Name = name
		missing = append(missing, column)
	}
	return missing
}

func providerColumnSQLType(target any, column ColumnSchema) string {
	if strings.EqualFold(column.Name, "_CQ_HASH") {
		return "VARCHAR"
	}

	switch normalizedProviderColumnType(column.Type) {
	case "", "string":
		if warehouse.Dialect(target) == warehouse.SQLDialectSnowflake {
			return "VARCHAR"
		}
		return "TEXT"
	case "boolean":
		return "BOOLEAN"
	case "integer":
		return warehouse.IntegerColumnType(target)
	case "number":
		if warehouse.Dialect(target) == warehouse.SQLDialectSnowflake {
			return "NUMBER"
		}
		return "NUMERIC"
	case "float":
		switch warehouse.Dialect(target) {
		case warehouse.SQLDialectPostgres:
			return "DOUBLE PRECISION"
		case warehouse.SQLDialectSQLite:
			return "REAL"
		default:
			return "FLOAT"
		}
	case "timestamp":
		return warehouse.TimestampColumnType(target)
	case "date":
		if warehouse.Dialect(target) == warehouse.SQLDialectPostgres {
			return "DATE"
		}
		if warehouse.Dialect(target) == warehouse.SQLDialectSnowflake {
			return "DATE"
		}
		return "TEXT"
	case "json", "object", "array", "variant":
		return warehouse.JSONColumnType(target)
	default:
		return warehouse.JSONColumnType(target)
	}
}

func providerColumnPlaceholder(target any, column ColumnSchema, position int) string {
	switch normalizedProviderColumnType(column.Type) {
	case "json", "object", "array", "variant":
		return warehouse.JSONPlaceholder(target, position)
	default:
		return warehouse.Placeholder(target, position)
	}
}

func normalizedProviderColumnType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func coerceProviderColumnValue(column ColumnSchema, value interface{}) interface{} {
	switch normalizedProviderColumnType(column.Type) {
	case "", "string":
		return coerceProviderStringValue(value)
	case "boolean":
		return coerceProviderBooleanValue(value)
	case "integer":
		return coerceProviderIntegerValue(value)
	case "number", "float":
		return coerceProviderFloatValue(value)
	case "timestamp", "date":
		return coerceProviderTimestampValue(value)
	case "json", "object", "array", "variant":
		return coerceProviderJSONValue(value)
	default:
		return coerceProviderJSONValue(value)
	}
}

func coerceProviderStringValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(value)
	}
}

func coerceProviderBooleanValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case bool:
		return typed
	case string:
		if parsed, err := strconv.ParseBool(strings.TrimSpace(typed)); err == nil {
			return parsed
		}
	case []byte:
		if parsed, err := strconv.ParseBool(strings.TrimSpace(string(typed))); err == nil {
			return parsed
		}
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	case float32:
		return typed != 0
	case float64:
		return typed != 0
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed != 0
		}
		if parsed, err := typed.Float64(); err == nil {
			return parsed != 0
		}
	}
	return value
}

func coerceProviderIntegerValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed)
		}
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed
		}
		if parsed, err := typed.Float64(); err == nil {
			return int64(parsed)
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil {
			return parsed
		}
	case []byte:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(string(typed)), 10, 64); err == nil {
			return parsed
		}
	}
	return value
}

func coerceProviderFloatValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case float32:
		return float64(typed)
	case float64:
		return typed
	case int:
		return float64(typed)
	case int8:
		return float64(typed)
	case int16:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case uint:
		return float64(typed)
	case uint8:
		return float64(typed)
	case uint16:
		return float64(typed)
	case uint32:
		return float64(typed)
	case uint64:
		return float64(typed)
	case json.Number:
		if parsed, err := typed.Float64(); err == nil {
			return parsed
		}
		if parsed, err := typed.Int64(); err == nil {
			return float64(parsed)
		}
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil {
			return parsed
		}
	case []byte:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(string(typed)), 64); err == nil {
			return parsed
		}
	}
	return value
}

func coerceProviderTimestampValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	case *time.Time:
		if typed == nil {
			return nil
		}
		return typed.UTC().Format(time.RFC3339Nano)
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return fmt.Sprint(value)
	}
}

func coerceProviderJSONValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case json.RawMessage:
		return string(typed)
	case []byte:
		trimmed := strings.TrimSpace(string(typed))
		if json.Valid([]byte(trimmed)) {
			return trimmed
		}
		value = string(typed)
	case string:
		trimmed := strings.TrimSpace(typed)
		if json.Valid([]byte(trimmed)) {
			return trimmed
		}
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}
