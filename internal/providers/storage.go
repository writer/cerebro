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

	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/postgres/tableops"
	"github.com/writer/cerebro/internal/warehouse"
)

const providerInsertBatchSize = 200

type providerDBClient interface {
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	Query(ctx context.Context, query string, args ...interface{}) (*warehouse.QueryResult, error)
}

func (b *BaseProvider) SetPostgresClient(client *postgres.PostgresClient) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pgClient = client
}

func (b *BaseProvider) getPostgresClient() *postgres.PostgresClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pgClient
}

func (b *BaseProvider) syncTable(ctx context.Context, schema TableSchema, rows []map[string]interface{}) (*TableResult, error) {
	result := &TableResult{Name: schema.Name, Rows: int64(len(rows))}
	pg := b.getPostgresClient()
	if pg == nil {
		result.Inserted = result.Rows
		return result, nil
	}

	columns := schemaColumnNames(schema.Columns)
	if err := ensureProviderTable(ctx, pg, schema.Name, columns); err != nil {
		return result, err
	}

	prepared, skipped := prepareProviderRows(schema, rows)
	if skipped > 0 {
		result.Rows = int64(len(prepared))
	}

	existingIDs, err := listProviderExistingIDs(ctx, pg, schema.Name)
	if err != nil {
		return result, err
	}

	newIDs := providerRowIDSet(prepared)

	// Atomic upsert via INSERT ON CONFLICT - no delete-before-insert window.
	if err := mergeProviderRows(ctx, pg, schema.Name, prepared); err != nil {
		return result, err
	}

	removedIDs := make(map[string]struct{}, len(existingIDs))
	for id := range existingIDs {
		if _, exists := newIDs[id]; !exists {
			removedIDs[id] = struct{}{}
		}
	}
	if err := deleteProviderRowsByID(ctx, pg, schema.Name, removedIDs); err != nil {
		return result, err
	}

	result.Rows = int64(len(prepared))
	result.Inserted = result.Rows
	result.Deleted = int64(len(removedIDs))
	return result, nil
}

func schemaColumnNames(columns []ColumnSchema) []string {
	names := make([]string, 0, len(columns))
	for _, column := range columns {
		names = append(names, column.Name)
	}
	return names
}

func ensureProviderTable(ctx context.Context, pg providerDBClient, table string, columns []string) error {
	err := tableops.EnsureTable(ctx, pg, table, columns, tableops.EnsureVariantTableOptions{
		AddMissingColumns: true,
	})
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "get table columns") {
		return fmt.Errorf("get existing columns: %w", err)
	}
	return err
}

func listProviderExistingIDs(ctx context.Context, pg providerDBClient, table string) (map[string]struct{}, error) {
	if err := postgres.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	query := fmt.Sprintf("SELECT _cq_id FROM %s", table)
	result, err := pg.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list existing provider rows: %w", err)
	}

	ids := make(map[string]struct{}, len(result.Rows))
	for _, row := range result.Rows {
		value, _ := lookupProviderValue(row, "_cq_id")
		id := strings.TrimSpace(providerStringValue(value))
		if id == "" {
			continue
		}
		ids[id] = struct{}{}
	}
	return ids, nil
}

func providerRowIDSet(rows []map[string]interface{}) map[string]struct{} {
	ids := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		value, _ := lookupProviderValue(row, "_cq_id")
		id := strings.TrimSpace(providerStringValue(value))
		if id == "" {
			continue
		}
		ids[id] = struct{}{}
	}
	return ids
}

func deleteProviderRowsByID(ctx context.Context, pg providerDBClient, table string, ids map[string]struct{}) error {
	if len(ids) == 0 {
		return nil
	}
	if err := postgres.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name %s: %w", table, err)
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

	for start := 0; start < len(keys); start += providerInsertBatchSize {
		end := start + providerInsertBatchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[start:end]
		// Use $N placeholders for Postgres
		placeholders := make([]string, len(batch))
		args := make([]interface{}, 0, len(batch))
		for i, id := range batch {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, id)
		}
		query := fmt.Sprintf("DELETE FROM %s WHERE _cq_id IN (%s)", table, strings.Join(placeholders, ","))
		if _, err := pg.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("delete provider rows by id: %w", err)
		}
	}

	return nil
}

func prepareProviderRows(schema TableSchema, rows []map[string]interface{}) ([]map[string]interface{}, int) {
	prepared := make([]map[string]interface{}, 0, len(rows))
	indexByID := make(map[string]int, len(rows))
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
		if idx, exists := indexByID[id]; exists {
			prepared[idx] = projected
			continue
		}
		indexByID[id] = len(prepared)
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

func providerStringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
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

func mergeProviderRows(ctx context.Context, pg providerDBClient, table string, rows []map[string]interface{}) error {
	return tableops.MergeRowsBatch(ctx, pg, table, rows, nil, providerInsertBatchSize)
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
