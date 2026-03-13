package warehouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/evalops/cerebro/internal/snowflake"
)

var sqliteIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type SQLiteWarehouseConfig struct {
	Path      string
	Database  string
	Schema    string
	AppSchema string
}

// SQLiteWarehouse provides a zero-dependency DataWarehouse backend for local development.
type SQLiteWarehouse struct {
	db        *sql.DB
	path      string
	database  string
	schema    string
	appSchema string

	cdcMu    sync.Mutex
	cdcReady bool
}

func NewSQLiteWarehouse(config SQLiteWarehouseConfig) (*SQLiteWarehouse, error) {
	path := strings.TrimSpace(config.Path)
	if path == "" {
		return nil, fmt.Errorf("sqlite warehouse path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create sqlite warehouse dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite warehouse: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLiteWarehousePingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite warehouse: %w", err)
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("restrict sqlite warehouse file: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		_ = db.Close()
		return nil, fmt.Errorf("inspect sqlite warehouse file: %w", err)
	}

	databaseName := strings.TrimSpace(config.Database)
	if databaseName == "" {
		databaseName = "sqlite"
	}
	schemaName := strings.TrimSpace(config.Schema)
	if schemaName == "" {
		schemaName = "RAW"
	}
	appSchemaName := strings.TrimSpace(config.AppSchema)
	if appSchemaName == "" {
		appSchemaName = "CEREBRO"
	}

	return &SQLiteWarehouse{
		db:        db,
		path:      path,
		database:  databaseName,
		schema:    schemaName,
		appSchema: appSchemaName,
	}, nil
}

const defaultSQLiteWarehousePingTimeout = 2 * time.Second

func (w *SQLiteWarehouse) Close() error {
	if w == nil || w.db == nil {
		return nil
	}
	return w.db.Close()
}

func (w *SQLiteWarehouse) Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return &snowflake.QueryResult{}, nil
	}
	if isInformationSchemaTablesQuery(query) {
		return w.queryInformationSchemaTables(ctx)
	}

	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanRows(rows)
}

func (w *SQLiteWarehouse) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	return w.db.ExecContext(ctx, query, args...)
}

func (w *SQLiteWarehouse) DB() *sql.DB {
	if w == nil {
		return nil
	}
	return w.db
}

func (w *SQLiteWarehouse) Database() string {
	if w == nil {
		return ""
	}
	return w.database
}

func (w *SQLiteWarehouse) Schema() string {
	if w == nil {
		return ""
	}
	return w.schema
}

func (w *SQLiteWarehouse) AppSchema() string {
	if w == nil {
		return ""
	}
	return w.appSchema
}

func (w *SQLiteWarehouse) ListTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *SQLiteWarehouse) ListAvailableTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *SQLiteWarehouse) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	table, err := normalizeSQLiteIdentifier(table)
	if err != nil {
		return nil, err
	}
	rows, err := w.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", quoteSQLiteIdentifier(table)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []string
	for rows.Next() {
		var (
			cid        int
			name       string
			typ        string
			notNull    int
			defaultV   any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultV, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func (w *SQLiteWarehouse) GetAssets(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}

	selectExpr := "*"
	if len(filter.Columns) > 0 {
		quoted := make([]string, 0, len(filter.Columns))
		for _, column := range filter.Columns {
			normalized, err := normalizeSQLiteIdentifier(column)
			if err != nil {
				continue
			}
			quoted = append(quoted, quoteSQLiteIdentifier(normalized))
		}
		if len(quoted) > 0 {
			selectExpr = strings.Join(quoted, ", ")
		}
	}

	query := "SELECT " + selectExpr + " FROM " + quoteSQLiteIdentifier(table)
	var (
		conditions []string
		args       []any
	)
	if strings.TrimSpace(filter.Account) != "" {
		conditions = append(conditions, quoteSQLiteIdentifier("account_id")+" = ?")
		args = append(args, filter.Account)
	}
	if strings.TrimSpace(filter.Region) != "" {
		conditions = append(conditions, quoteSQLiteIdentifier("region")+" = ?")
		args = append(args, filter.Region)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	result, err := w.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return result.Rows, nil
}

func (w *SQLiteWarehouse) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}
	result, err := w.Query(ctx, "SELECT * FROM "+quoteSQLiteIdentifier(table)+" WHERE "+quoteSQLiteIdentifier("id")+" = ? LIMIT 1", id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}
	return result.Rows[0], nil
}

func (w *SQLiteWarehouse) InsertCDCEvents(ctx context.Context, events []snowflake.CDCEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := w.ensureCDCEventsTable(ctx); err != nil {
		return err
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO cdc_events (
			event_id, table_name, resource_id, change_type, provider, region, account_id, payload, payload_hash, event_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, event := range events {
		eventTime := event.EventTime
		if eventTime.IsZero() {
			eventTime = time.Now().UTC()
		}
		eventID := strings.TrimSpace(event.EventID)
		if eventID == "" {
			eventID = snowflake.BuildCDCEventID(event.TableName, event.ResourceID, event.ChangeType, event.PayloadHash, eventTime)
		}
		payload := []byte("{}")
		if event.Payload != nil {
			encoded, err := json.Marshal(event.Payload)
			if err != nil {
				return err
			}
			payload = encoded
		}
		if _, err := stmt.ExecContext(
			ctx,
			eventID,
			event.TableName,
			event.ResourceID,
			event.ChangeType,
			event.Provider,
			event.Region,
			event.AccountID,
			string(payload),
			event.PayloadHash,
			eventTime.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (w *SQLiteWarehouse) ensureCDCEventsTable(ctx context.Context) error {
	w.cdcMu.Lock()
	defer w.cdcMu.Unlock()
	if w.cdcReady {
		return nil
	}
	_, err := w.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cdc_events (
			event_id TEXT PRIMARY KEY,
			table_name TEXT,
			resource_id TEXT,
			change_type TEXT,
			provider TEXT,
			region TEXT,
			account_id TEXT,
			payload TEXT,
			payload_hash TEXT,
			event_time TEXT,
			ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	w.cdcReady = true
	return nil
}

func (w *SQLiteWarehouse) queryInformationSchemaTables(ctx context.Context) (*snowflake.QueryResult, error) {
	tables, err := w.listUserTables(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]interface{}, 0, len(tables))
	for _, table := range tables {
		rows = append(rows, map[string]interface{}{"table_name": table})
	}
	return &snowflake.QueryResult{
		Columns: []string{"table_name"},
		Rows:    rows,
		Count:   len(rows),
	}, nil
}

func (w *SQLiteWarehouse) listUserTables(ctx context.Context) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("sqlite warehouse is not initialized")
	}
	rows, err := w.db.QueryContext(ctx, `
		SELECT name
		FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(tables)
	return tables, nil
}

func isInformationSchemaTablesQuery(query string) bool {
	normalized := strings.ToLower(strings.Join(strings.Fields(query), " "))
	return strings.Contains(normalized, "from information_schema.tables")
}

func scanRows(rows *sql.Rows) (*snowflake.QueryResult, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	lowerColumns := make([]string, len(columns))
	for i, column := range columns {
		lowerColumns[i] = strings.ToLower(column)
	}
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	result := &snowflake.QueryResult{
		Columns: columns,
		Rows:    make([]map[string]interface{}, 0, 32),
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{}, len(columns))
		for i, column := range lowerColumns {
			row[column] = values[i]
		}
		result.Rows = append(result.Rows, row)
		for i := range values {
			values[i] = nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result.Count = len(result.Rows)
	return result, nil
}

func normalizeSQLiteIdentifier(identifier string) (string, error) {
	identifier = strings.TrimSpace(identifier)
	if !sqliteIdentifierPattern.MatchString(identifier) {
		return "", fmt.Errorf("invalid sqlite identifier %q", identifier)
	}
	return identifier, nil
}

func quoteSQLiteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
