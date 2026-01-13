package snowflake

import (
	"context"
	"database/sql"
	"fmt"

	sf "github.com/snowflakedb/gosnowflake"
)

type Client struct {
	db       *sql.DB
	database string
	schema   string
}

type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
	Count   int                      `json:"count"`
}

func NewClient(connectionString, database, schema string) (*Client, error) {
	cfg, err := sf.ParseDSN(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}

	if database != "" {
		cfg.Database = database
	}
	if schema != "" {
		cfg.Schema = schema
	}

	dsn, err := sf.DSN(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dsn: %w", err)
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}

	return &Client{
		db:       db,
		database: cfg.Database,
		schema:   cfg.Schema,
	}, nil
}

func (c *Client) Close() error {
	return c.db.Close()
}

// DB returns the underlying database connection
func (c *Client) DB() *sql.DB {
	return c.db
}

func (c *Client) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func (c *Client) Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("get columns: %w", err)
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
			return nil, fmt.Errorf("scan row: %w", err)
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		result.Rows = append(result.Rows, row)
	}

	result.Count = len(result.Rows)
	return result, rows.Err()
}

func (c *Client) ListTables(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf("SHOW TABLES IN SCHEMA %s.%s", c.database, c.schema)
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var createdOn, name, databaseName, schemaName, kind, comment, clusterBy, rowsCount, bytes, owner, retentionTime, automaticClustering, changeTracking, searchOptimization, searchOptimizationProgress, searchOptimizationBytes, isExternal, enableSchemaEvolution, ownerRoleType, isEvent, budget interface{}
		if err := rows.Scan(&createdOn, &name, &databaseName, &schemaName, &kind, &comment, &clusterBy, &rowsCount, &bytes, &owner, &retentionTime, &automaticClustering, &changeTracking, &searchOptimization, &searchOptimizationProgress, &searchOptimizationBytes, &isExternal, &enableSchemaEvolution, &ownerRoleType, &isEvent, &budget); err != nil {
			if nameStr, ok := name.(string); ok {
				tables = append(tables, nameStr)
			}
			continue
		}
		if nameStr, ok := name.(string); ok {
			tables = append(tables, nameStr)
		}
	}
	return tables, rows.Err()
}
