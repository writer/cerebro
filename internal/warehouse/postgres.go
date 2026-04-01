package warehouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/snowflake"
)

type PostgresWarehouseConfig struct {
	DSN       string
	Database  string
	Schema    string
	AppSchema string
}

// PostgresWarehouse provides a DataWarehouse backend for self-hosted deployments.
type PostgresWarehouse struct {
	db        *sql.DB
	dsn       string
	database  string
	schema    string
	appSchema string

	cdcMu    sync.Mutex
	cdcReady bool
}

func NewPostgresWarehouse(config PostgresWarehouseConfig) (*PostgresWarehouse, error) {
	dsn := strings.TrimSpace(config.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("postgres warehouse dsn is required")
	}

	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres warehouse dsn: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres warehouse: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	ctx, cancel := context.WithTimeout(context.Background(), defaultPostgresWarehousePingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres warehouse: %w", err)
	}

	databaseName := strings.TrimSpace(config.Database)
	if databaseName == "" {
		databaseName = strings.TrimSpace(parsed.Database)
	}
	if databaseName == "" {
		databaseName = "postgres"
	}

	schemaName := strings.TrimSpace(config.Schema)
	if schemaName == "" {
		schemaName = "public"
	}

	appSchemaName := strings.TrimSpace(config.AppSchema)
	if appSchemaName == "" {
		appSchemaName = "cerebro"
	}

	return &PostgresWarehouse{
		db:        db,
		dsn:       dsn,
		database:  databaseName,
		schema:    schemaName,
		appSchema: appSchemaName,
	}, nil
}

const defaultPostgresWarehousePingTimeout = 3 * time.Second

func (w *PostgresWarehouse) Close() error {
	if w == nil || w.db == nil {
		return nil
	}
	return w.db.Close()
}

func (w *PostgresWarehouse) Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return &snowflake.QueryResult{}, nil
	}
	query = RewriteQueryForDialect(query, DialectPostgres)
	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanRows(rows)
}

func (w *PostgresWarehouse) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	query = RewriteQueryForDialect(query, DialectPostgres)
	return w.db.ExecContext(ctx, query, args...)
}

func (w *PostgresWarehouse) DB() *sql.DB {
	if w == nil {
		return nil
	}
	return w.db
}

func (w *PostgresWarehouse) Database() string {
	if w == nil {
		return ""
	}
	return w.database
}

func (w *PostgresWarehouse) Schema() string {
	if w == nil {
		return ""
	}
	return w.schema
}

func (w *PostgresWarehouse) AppSchema() string {
	if w == nil {
		return ""
	}
	return w.appSchema
}

func (w *PostgresWarehouse) ListTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *PostgresWarehouse) ListAvailableTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *PostgresWarehouse) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeSQLiteIdentifier(table)
	if err != nil {
		return nil, err
	}
	rows, err := w.db.QueryContext(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position
	`, w.schema, table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func (w *PostgresWarehouse) GetAssets(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}
	query, args, err := buildGetAssetsQuery(w, table, filter)
	if err != nil {
		return nil, err
	}
	result, err := w.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return finalizeAssetRows(table, result.Rows), nil
}

func (w *PostgresWarehouse) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}
	result, err := w.Query(ctx, "SELECT * FROM "+quoteSQLiteIdentifier(table)+" WHERE "+quoteSQLiteIdentifier("_cq_id")+" = $1 LIMIT 1", id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, fmt.Errorf("asset not found")
	}
	return result.Rows[0], nil
}

func (w *PostgresWarehouse) InsertCDCEvents(ctx context.Context, events []snowflake.CDCEvent) error {
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
		INSERT INTO cdc_events (
			event_id, table_name, resource_id, change_type, provider, region, account_id, payload, payload_hash, event_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (event_id) DO NOTHING
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
			eventTime.UTC(),
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (w *PostgresWarehouse) ensureCDCEventsTable(ctx context.Context) error {
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
			event_time TIMESTAMPTZ,
			ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	w.cdcReady = true
	return nil
}

func (w *PostgresWarehouse) listUserTables(ctx context.Context) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	rows, err := w.db.QueryContext(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, w.schema)
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
	return tables, rows.Err()
}
