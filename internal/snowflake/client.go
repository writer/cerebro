package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	sf "github.com/snowflakedb/gosnowflake"

	"github.com/writerinternal/cerebro/internal/cerrors"
)

const (
	opNewClient  = cerrors.Op("snowflake.NewClient")
	opPing       = cerrors.Op("snowflake.Ping")
	opQuery      = cerrors.Op("snowflake.Query")
	opListTables = cerrors.Op("snowflake.ListTables")
)

// ClientConfig holds configuration for creating a Snowflake client.
// Supports both connection string (password auth) and key-pair authentication.
type ClientConfig struct {
	// ConnectionString is the traditional DSN (user:password@account/db/schema)
	ConnectionString string
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
	// Schema is the default schema for CloudQuery assets (default: RAW)
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
}

// QueryResult holds query results in a structured format.
type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
	Count   int                      `json:"count"`
}

// NewClient creates a new Snowflake client.
// Supports both connection string (password auth) and key-pair authentication.
// Key-pair auth is used when Account, User, and PrivateKey are all provided.
func NewClient(config ClientConfig) (*Client, error) {
	var cfg *sf.Config
	var err error

	// Key-pair authentication takes precedence
	if config.PrivateKey != "" && config.Account != "" && config.User != "" {
		privateKey, err := parsePrivateKey(config.PrivateKey)
		if err != nil {
			return nil, cerrors.Wrapf(opNewClient, err, "failed to parse private key")
		}

		cfg = &sf.Config{
			Account:       config.Account,
			User:          config.User,
			Authenticator: sf.AuthTypeJwt,
			PrivateKey:    privateKey,
			Database:      config.Database,
			Schema:        config.Schema,
			Warehouse:     config.Warehouse,
			Role:          config.Role,
		}
	} else if config.ConnectionString != "" {
		// Fall back to connection string (password auth)
		cfg, err = sf.ParseDSN(config.ConnectionString)
		if err != nil {
			return nil, cerrors.Wrapf(opNewClient, err, "invalid connection string")
		}
		if config.Database != "" {
			cfg.Database = config.Database
		}
		if config.Schema != "" {
			cfg.Schema = config.Schema
		}
		if config.Warehouse != "" {
			cfg.Warehouse = config.Warehouse
		}
	} else {
		return nil, cerrors.E(opNewClient, cerrors.ErrMissingRequired, "either connection string or key-pair config (account, user, private_key) is required")
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
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 first (most common for Snowflake)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
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

// Schema returns the configured schema name (for CloudQuery assets).
func (c *Client) Schema() string {
	return c.schema
}

// AppSchema returns the configured app schema name (for Cerebro tables).
func (c *Client) AppSchema() string {
	return c.appSchema
}

// Ping verifies the database connection is alive.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.db.PingContext(ctx); err != nil {
		if ctx.Err() != nil {
			return cerrors.E(opPing, cerrors.ErrContextTimeout, ctx.Err())
		}
		return cerrors.E(opPing, cerrors.ErrDBConnection, err)
	}
	return nil
}

// Query executes a query and returns structured results.
func (c *Client) Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
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
		return nil, cerrors.Wrapf(opQuery, err, "failed to get columns")
	}

	result := &QueryResult{
		Columns: columns,
		Rows:    make([]map[string]interface{}, 0),
	}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, cerrors.Wrapf(opQuery, err, "failed to scan row")
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		result.Rows = append(result.Rows, row)
	}

	if err := rows.Err(); err != nil {
		return nil, cerrors.Wrapf(opQuery, err, "row iteration error")
	}

	result.Count = len(result.Rows)
	return result, nil
}

// QueryRow executes a query that returns at most one row.
func (c *Client) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return c.db.QueryRowContext(ctx, query, args...)
}

// Exec executes a query that doesn't return rows.
func (c *Client) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := c.db.ExecContext(ctx, query, args...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, cerrors.E(opQuery, cerrors.ErrDBTimeout, ctx.Err())
		}
		return nil, cerrors.E(opQuery, cerrors.ErrDBQuery, err)
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

// WithTimeout returns a context with the specified timeout, suitable for database operations.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}
