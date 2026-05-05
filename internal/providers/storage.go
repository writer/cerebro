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
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/snowflake/tableops"
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

	existingRows, err := listProviderExistingRows(ctx, sf, schema.Name)
	if err != nil {
		return result, err
	}

	newIDs := providerRowIDSet(prepared)
	cdcEvents := buildProviderCDCEvents(schema.Name, b.Name(), prepared, existingRows, newIDs)

	// Atomic upsert via MERGE - no delete-before-insert window.
	if err := mergeProviderRows(ctx, sf, schema.Name, prepared); err != nil {
		return result, err
	}

	removedIDs := make(map[string]struct{}, len(existingRows))
	for id := range existingRows {
		if _, exists := newIDs[id]; !exists {
			removedIDs[id] = struct{}{}
		}
	}
	if err := deleteProviderRowsByID(ctx, sf, schema.Name, removedIDs); err != nil {
		return result, err
	}
	if err := sf.InsertCDCEvents(ctx, cdcEvents); err != nil {
		return result, fmt.Errorf("insert provider cdc events: %w", err)
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

func ensureProviderTable(ctx context.Context, sf providerSnowflakeClient, table string, columns []string) error {
	err := tableops.EnsureVariantTable(ctx, sf, table, columns, tableops.EnsureVariantTableOptions{
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

type providerExistingRow struct {
	Hash string
}

func listProviderExistingRows(ctx context.Context, sf providerSnowflakeClient, table string) (map[string]providerExistingRow, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s", table)
	result, err := sf.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list existing provider rows: %w", err)
	}

	rows := make(map[string]providerExistingRow, len(result.Rows))
	for _, row := range result.Rows {
		value, _ := lookupProviderValue(row, "_cq_id")
		id := strings.TrimSpace(providerStringValue(value))
		if id == "" {
			continue
		}
		hashValue, _ := lookupProviderValue(row, "_cq_hash")
		rows[id] = providerExistingRow{
			Hash: strings.TrimSpace(providerStringValue(hashValue)),
		}
	}
	return rows, nil
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

func deleteProviderRowsByID(ctx context.Context, sf providerSnowflakeClient, table string, ids map[string]struct{}) error {
	if len(ids) == 0 {
		return nil
	}
	if err := snowflake.ValidateTableName(table); err != nil {
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
		placeholders := strings.TrimRight(strings.Repeat("?,", len(batch)), ",")
		args := make([]interface{}, 0, len(batch))
		for _, id := range batch {
			args = append(args, id)
		}
		query := fmt.Sprintf("DELETE FROM %s WHERE _CQ_ID IN (%s)", table, placeholders)
		if _, err := sf.Exec(ctx, query, args...); err != nil {
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

func buildProviderCDCEvents(table, provider string, prepared []map[string]interface{}, existingRows map[string]providerExistingRow, newIDs map[string]struct{}) []snowflake.CDCEvent {
	now := time.Now().UTC()
	events := make([]snowflake.CDCEvent, 0, len(prepared))

	for _, row := range prepared {
		id := strings.TrimSpace(providerStringValue(row["_cq_id"]))
		if id == "" {
			continue
		}
		hash := strings.TrimSpace(providerStringValue(row["_cq_hash"]))
		existing, existed := existingRows[id]
		changeType := "added"
		if existed {
			if existing.Hash == hash {
				continue
			}
			changeType = "modified"
		}
		events = append(events, snowflake.CDCEvent{
			TableName:   table,
			ResourceID:  id,
			ChangeType:  changeType,
			Provider:    provider,
			AccountID:   firstProviderCDCValue(row, "account_id", "site_id", "tenant_id"),
			Payload:     row,
			PayloadHash: hash,
			EventTime:   now,
		})
	}

	for id, existing := range existingRows {
		if _, exists := newIDs[id]; exists {
			continue
		}
		events = append(events, snowflake.CDCEvent{
			TableName:   table,
			ResourceID:  id,
			ChangeType:  "removed",
			Provider:    provider,
			PayloadHash: existing.Hash,
			EventTime:   now,
		})
	}

	return events
}

func firstProviderCDCValue(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := lookupProviderValue(row, key)
		if !ok {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text != "" {
			return text
		}
	}
	return ""
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

func mergeProviderRows(ctx context.Context, sf providerSnowflakeClient, table string, rows []map[string]interface{}) error {
	return tableops.MergeVariantRowsBatch(ctx, sf, table, rows, nil, providerInsertBatchSize)
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
