package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/warehouse"
)

const (
	opQuery      = cerrors.Op("postgres.Query")
	opExec       = cerrors.Op("postgres.Exec")
	opListTables = cerrors.Op("postgres.ListTables")
)

var _ warehouse.DataWarehouse = (*PostgresClient)(nil)

// PostgresClient wraps database/sql.DB with Postgres-specific functionality.
type PostgresClient struct {
	db        *sql.DB
	schema    string
	appSchema string

	cdcSchemaMu    sync.Mutex
	cdcSchemaReady bool
}

// NewPostgresClient creates a new Postgres client wrapping an existing *sql.DB.
func NewPostgresClient(db *sql.DB, schema, appSchema string) *PostgresClient {
	if appSchema == "" {
		appSchema = SchemaName
	}
	return &PostgresClient{
		db:        db,
		schema:    schema,
		appSchema: appSchema,
	}
}

// Close closes the database connection.
func (c *PostgresClient) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// DB returns the underlying database connection.
func (c *PostgresClient) DB() *sql.DB {
	return c.db
}

// Database returns an empty string; Postgres doesn't use a database prefix
// in table references the way Snowflake does.
func (c *PostgresClient) Database() string {
	return ""
}

// Schema returns the configured schema name for asset tables.
func (c *PostgresClient) Schema() string {
	return c.schema
}

// AppSchema returns the configured app schema name (for Cerebro tables).
func (c *PostgresClient) AppSchema() string {
	return c.appSchema
}

// Ping verifies the database connection is alive.
func (c *PostgresClient) Ping(ctx context.Context) error {
	if err := c.db.PingContext(ctx); err != nil {
		if ctx.Err() != nil {
			return cerrors.E(cerrors.Op("postgres.Ping"), cerrors.ErrContextTimeout, ctx.Err())
		}
		return cerrors.E(cerrors.Op("postgres.Ping"), cerrors.ErrDBConnection, err)
	}
	return nil
}

// Query executes a query and returns structured results.
// Scans rows generically using sql.Rows.Columns() + sql.Rows.Scan() with
// []interface{} and converts to map[string]interface{}.
func (c *PostgresClient) Query(ctx context.Context, query string, args ...interface{}) (*warehouse.QueryResult, error) {
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, cerrors.E(opQuery, cerrors.ErrDBTimeout, ctx.Err())
		}
		return nil, cerrors.E(opQuery, cerrors.ErrDBQuery, err)
	}
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to get columns: %w", err)
	}

	colCount := len(columns)
	lowerColumns := make([]string, colCount)
	for i, col := range columns {
		lowerColumns[i] = strings.ToLower(col)
	}

	values := make([]interface{}, colCount)
	valuePtrs := make([]interface{}, colCount)
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	result := &warehouse.QueryResult{
		Columns: columns,
		Rows:    make([]map[string]interface{}, 0, 64),
	}

	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("postgres: failed to scan row: %w", err)
		}

		row := make(map[string]interface{}, colCount)
		for i, col := range lowerColumns {
			row[col] = values[i]
		}
		result.Rows = append(result.Rows, row)

		for i := range values {
			values[i] = nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: row iteration error: %w", err)
	}

	result.Count = len(result.Rows)
	return result, nil
}

// Exec executes a query that doesn't return rows.
func (c *PostgresClient) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := c.db.ExecContext(ctx, query, args...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, cerrors.E(opExec, cerrors.ErrDBTimeout, ctx.Err())
		}
		return nil, cerrors.E(opExec, cerrors.ErrDBQuery, err)
	}
	return result, nil
}

// ListTables returns all tables in the configured schema.
func (c *PostgresClient) ListTables(ctx context.Context) ([]string, error) {
	query := `SELECT tablename FROM pg_tables WHERE schemaname = $1`
	rows, err := c.db.QueryContext(ctx, query, c.schema)
	if err != nil {
		return nil, cerrors.E(opListTables, cerrors.ErrDBQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return tables, fmt.Errorf("postgres: list tables row iteration error: %w", err)
	}
	return tables, nil
}

// ListAvailableTables returns all base tables in the configured schema as lowercase names.
func (c *PostgresClient) ListAvailableTables(ctx context.Context) ([]string, error) {
	query := `SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`
	rows, err := c.db.QueryContext(ctx, query, c.schema)
	if err != nil {
		return nil, fmt.Errorf("postgres: list available tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]bool)
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		lower := strings.ToLower(name)
		if !seen[lower] {
			seen[lower] = true
			tables = append(tables, lower)
		}
	}
	if err := rows.Err(); err != nil {
		return tables, fmt.Errorf("postgres: list available tables row iteration error: %w", err)
	}
	return tables, nil
}

// DescribeColumns returns the column names for a table in the configured schema.
func (c *PostgresClient) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}
	query := `SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`
	rows, err := c.db.QueryContext(ctx, query, c.schema, strings.ToLower(table))
	if err != nil {
		return nil, fmt.Errorf("postgres: describe columns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		cols = append(cols, strings.ToLower(name))
	}
	if err := rows.Err(); err != nil {
		return cols, fmt.Errorf("postgres: describe columns row iteration error: %w", err)
	}
	return cols, nil
}

// GetAssets retrieves assets from a table with pagination and filtering.
// Uses DISTINCT ON (_cq_id) to deduplicate re-synced rows, replacing
// Snowflake's QUALIFY ROW_NUMBER() OVER (PARTITION BY ...).
func (c *PostgresClient) GetAssets(ctx context.Context, table string, filter warehouse.AssetFilter) ([]map[string]interface{}, error) {
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.schema, table)
	if err != nil {
		return nil, err
	}

	selectCols := selectClause(filter.Columns)
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.Account != "" {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", argIdx))
		args = append(args, filter.Account)
		argIdx++
	}
	if filter.Region != "" {
		conditions = append(conditions, fmt.Sprintf("region = $%d", argIdx))
		args = append(args, filter.Region)
		argIdx++
	}
	if !filter.Since.IsZero() {
		if filter.SinceID != "" {
			conditions = append(conditions, fmt.Sprintf("(_cq_sync_time > $%d OR (_cq_sync_time = $%d AND _cq_id > $%d))", argIdx, argIdx+1, argIdx+2))
			args = append(args, filter.Since, filter.Since, filter.SinceID)
			argIdx += 3
		} else {
			conditions = append(conditions, fmt.Sprintf("_cq_sync_time > $%d", argIdx))
			args = append(args, filter.Since)
			argIdx++
		}
	}
	if !filter.CursorSyncTime.IsZero() {
		if filter.CursorID != "" {
			conditions = append(conditions, fmt.Sprintf("(_cq_sync_time > $%d OR (_cq_sync_time = $%d AND _cq_id > $%d))", argIdx, argIdx+1, argIdx+2))
			args = append(args, filter.CursorSyncTime, filter.CursorSyncTime, filter.CursorID)
			argIdx += 3
		} else {
			conditions = append(conditions, fmt.Sprintf("_cq_sync_time > $%d", argIdx))
			args = append(args, filter.CursorSyncTime)
			argIdx++
		}
	}

	// Use DISTINCT ON (_cq_id) to keep only the latest row per _cq_id,
	// ordered by _cq_sync_time DESC within each group.
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}

	// Subquery with DISTINCT ON for deduplication, then outer query for pagination ordering.
	query := fmt.Sprintf(
		`SELECT %s FROM (
			SELECT DISTINCT ON (_cq_id) *
			FROM %s%s
			ORDER BY _cq_id, _cq_sync_time DESC
		) deduped
		ORDER BY _cq_sync_time ASC, _cq_id ASC
		LIMIT $%d`,
		selectCols, tableRef, whereClause, argIdx,
	)
	args = append(args, limit)
	argIdx++

	if filter.Offset > 0 && filter.Since.IsZero() && filter.CursorSyncTime.IsZero() {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	result, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	for i := range result.Rows {
		result.Rows[i]["_cq_table"] = table
	}
	return result.Rows, nil
}

// GetAssetByID returns a single asset by its _cq_id.
func (c *PostgresClient) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	if err := ValidateTableNameStrict(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	tableRef, err := SafeTableRef(c.schema, table)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE _cq_id = $1 LIMIT 1", tableRef)
	result, err := c.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, fmt.Errorf("asset not found")
	}
	return result.Rows[0], nil
}

// InsertCDCEvents writes CDC events idempotently using INSERT ON CONFLICT.
func (c *PostgresClient) InsertCDCEvents(ctx context.Context, events []warehouse.CDCEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := c.EnsureCDCEventsTable(ctx); err != nil {
		return err
	}

	const batchSize = 500
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		if err := c.insertCDCEventBatch(ctx, events[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *PostgresClient) insertCDCEventBatch(ctx context.Context, events []warehouse.CDCEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Build a multi-row INSERT ON CONFLICT DO UPDATE.
	valuePlaceholders := make([]string, 0, len(events))
	args := make([]interface{}, 0, len(events)*10)
	argIdx := 1

	for _, event := range events {
		eventTime := event.EventTime
		if eventTime.IsZero() {
			eventTime = time.Now().UTC()
		}
		eventID := event.EventID
		if eventID == "" {
			eventID = buildCDCEventID(event.TableName, event.ResourceID, event.ChangeType, event.PayloadHash, eventTime)
		}

		var payloadJSON []byte
		if event.Payload != nil {
			payloadJSON, _ = json.Marshal(event.Payload)
		}

		valuePlaceholders = append(valuePlaceholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d, $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5, argIdx+6, argIdx+7, argIdx+8, argIdx+9))

		args = append(args,
			eventID,
			event.TableName,
			event.ResourceID,
			event.ChangeType,
			event.Provider,
			event.Region,
			event.AccountID,
			nullableString(payloadJSON),
			event.PayloadHash,
			eventTime.UTC(),
		)
		argIdx += 10
	}

	cdcTable := c.appSchema + ".cdc_events"

	query := fmt.Sprintf(`
		INSERT INTO %s (
			event_id, table_name, resource_id, change_type, provider, region, account_id, payload, payload_hash, event_time
		) VALUES %s
		ON CONFLICT (event_id) DO UPDATE SET
			payload = EXCLUDED.payload,
			payload_hash = EXCLUDED.payload_hash,
			event_time = EXCLUDED.event_time`,
		cdcTable, strings.Join(valuePlaceholders, ", "))

	_, err := c.Exec(ctx, query, args...)
	return err
}

// selectClause builds a SELECT column list from the filter columns.
func selectClause(columns []string) string {
	if len(columns) == 0 {
		return "*"
	}
	validated := make([]string, 0, len(columns))
	for _, col := range columns {
		if err := ValidateColumnName(col); err != nil {
			continue
		}
		validated = append(validated, strings.ToLower(col))
	}
	if len(validated) == 0 {
		return "*"
	}
	return strings.Join(validated, ", ")
}

func buildCDCEventID(table, resourceID, changeType, payloadHash string, eventTime time.Time) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", table, resourceID, changeType, payloadHash, eventTime.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func nullableString(b []byte) interface{} {
	if b == nil {
		return nil
	}
	return string(b)
}
