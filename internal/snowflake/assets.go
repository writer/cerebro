package snowflake

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Asset struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Account    string                 `json:"account"`
	Region     string                 `json:"region"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
}

type AssetFilter struct {
	Provider       string
	Type           string
	Account        string
	Region         string
	Limit          int
	Offset         int // Deprecated: use cursor fields instead
	Since          time.Time
	SinceID        string
	Columns        []string  // If set, only SELECT these columns instead of *
	CursorSyncTime time.Time // Keyset cursor: sync time of last seen row
	CursorID       string    // Keyset cursor: _cq_id of last seen row
}

func selectClause(columns []string) string {
	if len(columns) == 0 {
		return "*"
	}
	validated := make([]string, 0, len(columns))
	for _, col := range columns {
		if err := ValidateColumnName(col); err != nil {
			continue
		}
		validated = append(validated, strings.ToUpper(col))
	}
	if len(validated) == 0 {
		return "*"
	}
	return strings.Join(validated, ", ")
}

func (c *Client) GetAssets(ctx context.Context, table string, filter AssetFilter) ([]map[string]interface{}, error) {
	// Use strict validation to ensure table is a known asset table
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.database, c.schema, table)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + selectClause(filter.Columns) + " FROM " + tableRef

	var conditions []string
	var args []interface{}

	if filter.Account != "" {
		conditions = append(conditions, "account_id = ?")
		args = append(args, filter.Account)
	}
	if filter.Region != "" {
		conditions = append(conditions, "region = ?")
		args = append(args, filter.Region)
	}
	if !filter.Since.IsZero() {
		if filter.SinceID != "" {
			conditions = append(conditions, "(_cq_sync_time > ? OR (_cq_sync_time = ? AND _cq_id > ?))")
			args = append(args, filter.Since, filter.Since, filter.SinceID)
		} else {
			conditions = append(conditions, "_cq_sync_time > ?")
			args = append(args, filter.Since)
		}
	}
	if !filter.CursorSyncTime.IsZero() {
		if filter.CursorID != "" {
			conditions = append(conditions, "(_cq_sync_time > ? OR (_cq_sync_time = ? AND _cq_id > ?))")
			args = append(args, filter.CursorSyncTime, filter.CursorSyncTime, filter.CursorID)
		} else {
			conditions = append(conditions, "_cq_sync_time > ?")
			args = append(args, filter.CursorSyncTime)
		}
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += cond
		}
	}

	// Always use stable ordering for deterministic pagination.
	orderBy := " ORDER BY _cq_sync_time ASC, _cq_id ASC"

	// Deduplicate: keep only the latest row per _cq_id (handles re-synced data)
	query += " QUALIFY ROW_NUMBER() OVER (PARTITION BY _cq_id ORDER BY _cq_sync_time DESC) = 1"
	query += orderBy

	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	if filter.Offset > 0 && filter.Since.IsZero() && filter.CursorSyncTime.IsZero() {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	result, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	// Add table name to each asset for policy matching
	for i := range result.Rows {
		result.Rows[i]["_cq_table"] = table
	}
	return result.Rows, nil
}

// GetAssetsByIDs returns assets matching the provided IDs.
func (c *Client) GetAssetsByIDs(ctx context.Context, table string, ids []string, columns []string) ([]map[string]interface{}, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	// Use strict validation to ensure table is a known CloudQuery/Cerebro table
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.database, c.schema, table)
	if err != nil {
		return nil, err
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf("SELECT %s FROM %s WHERE _CQ_ID IN (%s)", selectClause(columns), tableRef, strings.Join(placeholders, ", "))
	result, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	for i := range result.Rows {
		result.Rows[i]["_cq_table"] = table
	}

	return result.Rows, nil
}

func (c *Client) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	// Use strict validation to ensure table is a known asset table
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.database, c.schema, table)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("SELECT * FROM %s WHERE _cq_id = ? LIMIT 1", tableRef)
	result, err := c.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, fmt.Errorf("asset not found")
	}
	return result.Rows[0], nil
}

func (c *Client) CountAssets(ctx context.Context, table string) (int64, error) {
	// Use strict validation for table names
	if err := ValidateTableNameStrict(table); err != nil {
		return 0, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.database, c.schema, table)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("SELECT COUNT(*) as count FROM %s", tableRef)
	result, err := c.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	if len(result.Rows) == 0 {
		return 0, nil
	}

	// Handle various numeric types that Snowflake may return
	countVal, ok := queryRowValue(result.Rows[0], "count")
	if !ok {
		return 0, nil
	}
	switch v := countVal.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case string:
		var count int64
		if _, err := fmt.Sscanf(v, "%d", &count); err == nil {
			return count, nil
		}
	}
	return 0, nil
}

// DescribeColumns returns the column names for a table. Used for safe column projection.
func (c *Client) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}
	if err := ValidateTableName(c.database); err != nil {
		return nil, fmt.Errorf("invalid database name: %w", err)
	}
	if err := ValidateTableName(c.schema); err != nil {
		return nil, fmt.Errorf("invalid schema name: %w", err)
	}
	query := fmt.Sprintf(
		"SELECT column_name FROM %s.information_schema.columns WHERE table_name = ? AND table_schema = ?",
		strings.ToUpper(c.database),
	)
	result, err := c.Query(ctx, query, strings.ToUpper(table), strings.ToUpper(c.schema))
	if err != nil {
		return nil, err
	}
	cols := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		if name := queryRowString(row, "column_name"); name != "" {
			cols = append(cols, strings.ToLower(name))
		}
	}
	return cols, nil
}
