package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	sf "github.com/snowflakedb/gosnowflake"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/warehouse"
)

const (
	opNewClient  = cerrors.Op("snowflake.NewClient")
	opParseKey   = cerrors.Op("snowflake.parsePrivateKey")
	opPing       = cerrors.Op("snowflake.Ping")
	opQuery      = cerrors.Op("snowflake.Query")
	opListTables = cerrors.Op("snowflake.ListTables")
)

// ClientConfig holds configuration for creating a Snowflake client.
// Requires key-pair authentication via Account, User, and PrivateKey.
type ClientConfig struct {
	// Account is the Snowflake account identifier (e.g., "ykc27695.us-east-1")
	Account string
	// User is the Snowflake username
	User string
	// PrivateKey is the PEM-encoded private key for key-pair authentication
	PrivateKey string
	// Role is the default role
	Role string
	// Database is the default database
	Database string
	// Schema is the default schema for asset tables (default: CEREBRO)
	Schema string
	// AppSchema is the schema for Cerebro app tables (default: CEREBRO)
	AppSchema string
	// Warehouse is the default warehouse
	Warehouse string
}

// Client wraps database/sql.DB with Snowflake-specific functionality.
type Client struct {
	db        *sql.DB
	database  string
	schema    string
	appSchema string
	warehouse string

	cdcSchemaMu    sync.Mutex
	cdcSchemaReady bool
}

// QueryResult is an alias for warehouse.QueryResult for backward compatibility.
type QueryResult = warehouse.QueryResult

// NewClient creates a new Snowflake client using key-pair authentication.
// Requires Account, User, and PrivateKey to be set.
func NewClient(config ClientConfig) (*Client, error) {
	if config.PrivateKey == "" || config.Account == "" || config.User == "" {
		return nil, cerrors.E(opNewClient, cerrors.ErrMissingRequired, "key-pair auth required: set SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
	}

	privateKey, err := parsePrivateKey(config.PrivateKey)
	if err != nil {
		return nil, cerrors.Wrapf(opNewClient, err, "failed to parse private key")
	}

	cfg := &sf.Config{
		Account:       config.Account,
		User:          config.User,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    privateKey,
		Database:      config.Database,
		Schema:        config.Schema,
		Warehouse:     config.Warehouse,
		Role:          config.Role,
	}

	dsn, err := sf.DSN(cfg)
	if err != nil {
		return nil, cerrors.Wrapf(opNewClient, err, "failed to build DSN")
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return nil, cerrors.E(opNewClient, cerrors.ErrDBConnection, err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	// Default app schema to CEREBRO if not specified
	appSchema := config.AppSchema
	if appSchema == "" {
		appSchema = SchemaName // Use constant default (CEREBRO)
	}

	return &Client{
		db:        db,
		database:  cfg.Database,
		schema:    cfg.Schema,
		appSchema: appSchema,
		warehouse: cfg.Warehouse,
	}, nil
}

// parsePrivateKey parses a PEM-encoded RSA private key.
// Supports both PKCS8 and PKCS1 formats.
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, cerrors.E(opParseKey, cerrors.ErrInvalidInput, "failed to decode PEM block")
	}

	// Try PKCS8 first (most common for Snowflake)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, cerrors.E(opParseKey, cerrors.ErrInvalidInput, "key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, cerrors.Wrapf(opParseKey, err, "failed to parse private key")
	}
	return rsaKey, nil
}

// Close closes the database connection.
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// DB returns the underlying database connection for advanced use cases.
func (c *Client) DB() *sql.DB {
	return c.db
}

// Database returns the configured database name.
func (c *Client) Database() string {
	return c.database
}

// Schema returns the configured schema name for asset tables.
func (c *Client) Schema() string {
	return c.schema
}

// AppSchema returns the configured app schema name (for Cerebro tables).
func (c *Client) AppSchema() string {
	return c.appSchema
}

// Ping verifies the database connection is alive.
func (c *Client) Ping(ctx context.Context) error {
	ctx, span := startSnowflakeSpan(ctx, "snowflake.ping", attribute.String("db.operation", "ping"))
	defer span.End()

	if err := c.db.PingContext(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if ctx.Err() != nil {
			return cerrors.E(opPing, cerrors.ErrContextTimeout, ctx.Err())
		}
		return cerrors.E(opPing, cerrors.ErrDBConnection, err)
	}
	return nil
}

// Query executes a query and returns structured results.
func (c *Client) Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	ctx, span := startSnowflakeSpan(ctx, "snowflake.query",
		attribute.String("db.operation", "query"),
		attribute.String("db.statement", statementForSpan(query)),
		attribute.Int("db.args_count", len(args)),
	)
	defer span.End()

	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if ctx.Err() != nil {
			return nil, cerrors.E(opQuery, cerrors.ErrDBTimeout, ctx.Err())
		}
		return nil, cerrors.E(opQuery, cerrors.ErrDBQuery, err)
	}
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, cerrors.Wrapf(opQuery, err, "failed to get columns")
	}

	// Pre-compute lowercase column names once
	colCount := len(columns)
	lowerColumns := make([]string, colCount)
	for i, col := range columns {
		lowerColumns[i] = strings.ToLower(col)
	}

	// Pre-allocate scan buffers (reused across rows)
	values := make([]interface{}, colCount)
	valuePtrs := make([]interface{}, colCount)
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Pre-allocate result slice with reasonable capacity
	result := &QueryResult{
		Columns: columns,
		Rows:    make([]map[string]interface{}, 0, 64),
	}

	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, cerrors.Wrapf(opQuery, err, "failed to scan row")
		}

		// Create row map with pre-sized capacity
		row := make(map[string]interface{}, colCount)
		for i, col := range lowerColumns {
			row[col] = values[i]
		}
		result.Rows = append(result.Rows, row)

		// Reset values slice for next iteration (prevents data aliasing)
		for i := range values {
			values[i] = nil
		}
	}

	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, cerrors.Wrapf(opQuery, err, "row iteration error")
	}

	result.Count = len(result.Rows)
	span.SetAttributes(attribute.Int("db.rows_returned", result.Count))
	return result, nil
}

// QueryRow executes a query that returns at most one row.
func (c *Client) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return c.db.QueryRowContext(ctx, query, args...)
}

// Exec executes a query that doesn't return rows.
func (c *Client) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	ctx, span := startSnowflakeSpan(ctx, "snowflake.exec",
		attribute.String("db.operation", "exec"),
		attribute.String("db.statement", statementForSpan(query)),
		attribute.Int("db.args_count", len(args)),
	)
	defer span.End()

	result, err := c.db.ExecContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if ctx.Err() != nil {
			return nil, cerrors.E(opQuery, cerrors.ErrDBTimeout, ctx.Err())
		}
		return nil, cerrors.E(opQuery, cerrors.ErrDBQuery, err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr == nil {
		span.SetAttributes(attribute.Int64("db.rows_affected", rows))
	}
	return result, nil
}

// ListTables returns all tables in the configured schema.
func (c *Client) ListTables(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf("SHOW TABLES IN SCHEMA %s.%s", c.database, c.schema)
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, cerrors.E(opListTables, cerrors.ErrDBQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		// SHOW TABLES returns many columns; we only need the name (2nd column)
		var (
			createdOn, name, databaseName, schemaName, kind, comment                                   interface{}
			clusterBy, rowsCount, bytes, owner, retentionTime                                          interface{}
			automaticClustering, changeTracking, searchOptimization, searchOptimizationProgress        interface{}
			searchOptimizationBytes, isExternal, enableSchemaEvolution, ownerRoleType, isEvent, budget interface{}
		)

		err := rows.Scan(
			&createdOn, &name, &databaseName, &schemaName, &kind, &comment,
			&clusterBy, &rowsCount, &bytes, &owner, &retentionTime,
			&automaticClustering, &changeTracking, &searchOptimization, &searchOptimizationProgress,
			&searchOptimizationBytes, &isExternal, &enableSchemaEvolution, &ownerRoleType, &isEvent, &budget,
		)
		if err != nil {
			// Try to extract name even on scan error
			if nameStr, ok := name.(string); ok && nameStr != "" {
				tables = append(tables, nameStr)
			}
			continue
		}

		if nameStr, ok := name.(string); ok {
			tables = append(tables, nameStr)
		}
	}

	if err := rows.Err(); err != nil {
		return tables, cerrors.Wrapf(opListTables, err, "row iteration error")
	}

	return tables, nil
}

// ListAvailableTables returns all tables in the configured schema as lowercase names.
// Uses information_schema for reliable column parsing instead of SHOW TABLES.
func (c *Client) ListAvailableTables(ctx context.Context) ([]string, error) {
	if err := ValidateTableName(c.database); err != nil {
		return nil, fmt.Errorf("invalid database name: %w", err)
	}
	query := fmt.Sprintf(
		"SELECT table_name FROM %s.information_schema.tables WHERE table_schema = ?",
		strings.ToUpper(c.database),
	)
	result, err := c.Query(ctx, query, strings.ToUpper(c.schema))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(result.Rows))
	tables := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		name := queryRowString(row, "table_name")
		if name != "" {
			lower := strings.ToLower(name)
			if !seen[lower] {
				seen[lower] = true
				tables = append(tables, lower)
			}
		}
	}
	return tables, nil
}

// WithTimeout returns a context with the specified timeout, suitable for database operations.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout) // #nosec G118 -- caller receives and owns cancel function lifecycle
}

var snowflakeTracer = otel.Tracer("cerebro.snowflake")

func startSnowflakeSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	defaultAttrs := []attribute.KeyValue{
		attribute.String("db.system", "snowflake"),
	}
	defaultAttrs = append(defaultAttrs, attrs...)
	return snowflakeTracer.Start(ctx, name, trace.WithAttributes(defaultAttrs...))
}

func statementForSpan(statement string) string {
	statement = strings.Join(strings.Fields(strings.TrimSpace(statement)), " ")
	if len(statement) <= 256 {
		return statement
	}
	return statement[:256] + "..."
}
