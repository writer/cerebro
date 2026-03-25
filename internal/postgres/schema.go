package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Schema definitions for Cerebro tables in Postgres.
const (
	// AssetSchemaName is the default Postgres schema for raw warehouse tables.
	AssetSchemaName = "public"

	// SchemaName is the default Postgres schema for Cerebro app tables.
	SchemaName = "cerebro"
)

// TableDDLs contains Postgres-compatible CREATE TABLE statements.
// All Snowflake types have been converted:
//   - VARIANT → JSONB
//   - ARRAY → JSONB
//   - TIMESTAMP_NTZ → TIMESTAMP
//   - TIMESTAMP_TZ → TIMESTAMPTZ
//   - STRING → TEXT
//   - CURRENT_TIMESTAMP() → CURRENT_TIMESTAMP
var TableDDLs = map[string]string{
	"findings": `
		CREATE TABLE IF NOT EXISTS %s.findings (
			id VARCHAR(64) PRIMARY KEY,
			policy_id VARCHAR(128) NOT NULL,
			policy_name VARCHAR(256),
			severity VARCHAR(32),
			status VARCHAR(32) DEFAULT 'OPEN',
			resource_id VARCHAR(256),
			resource_type VARCHAR(128),
			resource_data JSONB,
			description TEXT,
			remediation TEXT,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resolved_at TIMESTAMP,
			suppressed_at TIMESTAMP,
			suppressed_by VARCHAR(128),
			suppression_reason TEXT,
			metadata JSONB,
			_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"tickets": `
		CREATE TABLE IF NOT EXISTS %s.tickets (
			id VARCHAR(64) PRIMARY KEY,
			external_id VARCHAR(128),
			provider VARCHAR(64),
			title VARCHAR(512) NOT NULL,
			description TEXT,
			priority VARCHAR(32),
			status VARCHAR(32),
			type VARCHAR(64),
			assignee VARCHAR(256),
			reporter VARCHAR(256),
			labels JSONB,
			finding_ids JSONB,
			asset_ids JSONB,
			external_url VARCHAR(1024),
			metadata JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resolved_at TIMESTAMP
		)`,

	"access_reviews": `
		CREATE TABLE IF NOT EXISTS %s.access_reviews (
			id VARCHAR(64) PRIMARY KEY,
			name VARCHAR(256) NOT NULL,
			description TEXT,
			type VARCHAR(64),
			status VARCHAR(32) DEFAULT 'draft',
			scope JSONB,
			schedule JSONB,
			reviewers JSONB,
			stats JSONB,
			created_by VARCHAR(128),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			started_at TIMESTAMP,
			due_at TIMESTAMP,
			completed_at TIMESTAMP
		)`,

	"review_items": `
		CREATE TABLE IF NOT EXISTS %s.review_items (
			id VARCHAR(64) PRIMARY KEY,
			review_id VARCHAR(64) NOT NULL REFERENCES %s.access_reviews(id),
			type VARCHAR(64),
			principal_id VARCHAR(256),
			principal_type VARCHAR(64),
			principal_name VARCHAR(256),
			principal_email VARCHAR(256),
			provider VARCHAR(64),
			account VARCHAR(128),
			access_grants JSONB,
			risk_score INTEGER,
			risk_factors JSONB,
			decision_action VARCHAR(32),
			decision_reviewer VARCHAR(128),
			decision_comment TEXT,
			decided_at TIMESTAMP,
			metadata JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"attack_path_nodes": `
		CREATE TABLE IF NOT EXISTS %s.attack_path_nodes (
			id VARCHAR(64) PRIMARY KEY,
			type VARCHAR(64),
			name VARCHAR(256),
			provider VARCHAR(64),
			account VARCHAR(128),
			region VARCHAR(64),
			risk VARCHAR(32),
			properties JSONB,
			findings JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"attack_path_edges": `
		CREATE TABLE IF NOT EXISTS %s.attack_path_edges (
			id VARCHAR(64) PRIMARY KEY,
			source_id VARCHAR(64) NOT NULL,
			target_id VARCHAR(64) NOT NULL,
			type VARCHAR(64),
			risk VARCHAR(32),
			properties JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"attack_paths": `
		CREATE TABLE IF NOT EXISTS %s.attack_paths (
			id VARCHAR(64) PRIMARY KEY,
			title VARCHAR(512),
			description TEXT,
			severity VARCHAR(32),
			score INTEGER,
			node_ids JSONB,
			edge_ids JSONB,
			steps JSONB,
			remediation JSONB,
			analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"agent_sessions": `
		CREATE TABLE IF NOT EXISTS %s.agent_sessions (
			id VARCHAR(64) PRIMARY KEY,
			agent_id VARCHAR(64) NOT NULL,
			user_id VARCHAR(128),
			status VARCHAR(32) DEFAULT 'active',
			context JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"agent_messages": `
		CREATE TABLE IF NOT EXISTS %s.agent_messages (
			id VARCHAR(64) PRIMARY KEY,
			session_id VARCHAR(64) NOT NULL REFERENCES %s.agent_sessions(id),
			role VARCHAR(32) NOT NULL,
			content TEXT,
			tool_calls JSONB,
			metadata JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"provider_syncs": `
		CREATE TABLE IF NOT EXISTS %s.provider_syncs (
			id VARCHAR(64) PRIMARY KEY,
			provider VARCHAR(64) NOT NULL,
			status VARCHAR(32),
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			duration_ms INTEGER,
			tables_synced JSONB,
			total_rows BIGINT,
			errors JSONB
		)`,

	"risk_engine_state": `
		CREATE TABLE IF NOT EXISTS %s.risk_engine_state (
			graph_id VARCHAR(128) PRIMARY KEY,
			snapshot JSONB,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"policy_history": `
		CREATE TABLE IF NOT EXISTS %s.policy_history (
			policy_id VARCHAR(128) NOT NULL,
			version INTEGER NOT NULL,
			content JSONB NOT NULL,
			change_type VARCHAR(32),
			pinned_version INTEGER,
			effective_from TIMESTAMP NOT NULL,
			effective_to TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (policy_id, version)
		)`,

	"audit_log": `
		CREATE TABLE IF NOT EXISTS %s.audit_log (
			id VARCHAR(64) PRIMARY KEY,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			action VARCHAR(128) NOT NULL,
			actor_id VARCHAR(128),
			actor_type VARCHAR(64),
			resource_type VARCHAR(64),
			resource_id VARCHAR(256),
			details JSONB,
			ip_address VARCHAR(64),
			user_agent VARCHAR(512)
		)`,

	"webhooks": `
		CREATE TABLE IF NOT EXISTS %s.webhooks (
			id VARCHAR(64) PRIMARY KEY,
			url VARCHAR(2048) NOT NULL,
			events JSONB,
			secret VARCHAR(256),
			enabled BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

	"webhook_deliveries": `
		CREATE TABLE IF NOT EXISTS %s.webhook_deliveries (
			id VARCHAR(64) PRIMARY KEY,
			webhook_id VARCHAR(64) NOT NULL REFERENCES %s.webhooks(id),
			event_type VARCHAR(128),
			payload JSONB,
			response_status INTEGER,
			response_body TEXT,
			delivered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			duration_ms INTEGER
		)`,

	"cdc_events": `
		CREATE TABLE IF NOT EXISTS %s.cdc_events (
			event_id VARCHAR PRIMARY KEY,
			table_name VARCHAR,
			resource_id VARCHAR,
			change_type VARCHAR,
			provider VARCHAR,
			region VARCHAR,
			account_id VARCHAR,
			payload JSONB,
			payload_hash VARCHAR,
			event_time TIMESTAMPTZ,
			ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)`,
}

// EnsureSchema creates the Postgres schema if it doesn't exist.
func (c *PostgresClient) EnsureSchema(ctx context.Context) error {
	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", c.appSchema)
	_, err := c.db.ExecContext(ctx, query)
	return err
}

// CreateTables creates all Cerebro tables in the app schema.
func (c *PostgresClient) CreateTables(ctx context.Context) error {
	for name, ddl := range TableDDLs {
		var formattedDDL string
		if strings.Count(ddl, "%s") == 1 {
			formattedDDL = fmt.Sprintf(ddl, c.appSchema)
		} else {
			// For tables with foreign key references
			formattedDDL = fmt.Sprintf(ddl, c.appSchema, c.appSchema)
		}

		if _, err := c.db.ExecContext(ctx, formattedDDL); err != nil {
			return fmt.Errorf("create table %s: %w", name, err)
		}
	}
	return nil
}

// Bootstrap creates schema and all tables.
func (c *PostgresClient) Bootstrap(ctx context.Context) error {
	if err := c.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if err := c.CreateTables(ctx); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	return nil
}

// DropSchema drops the Cerebro schema (use with caution).
func (c *PostgresClient) DropSchema(ctx context.Context) error {
	query := fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", c.appSchema)
	_, err := c.db.ExecContext(ctx, query)
	return err
}

// EnsureCDCEventsTable creates the CDC events table in the app schema.
func (c *PostgresClient) EnsureCDCEventsTable(ctx context.Context) error {
	c.cdcSchemaMu.Lock()
	defer c.cdcSchemaMu.Unlock()
	if c.cdcSchemaReady {
		return nil
	}

	ddl := TableDDLs["cdc_events"]
	formattedDDL := fmt.Sprintf(ddl, c.appSchema)
	if _, err := c.db.ExecContext(ctx, formattedDDL); err != nil {
		return err
	}
	c.cdcSchemaReady = true
	return nil
}

// NewPostgresDB opens a Postgres database connection using the provided DSN.
// This is a convenience wrapper around sql.Open.
func NewPostgresDB(driverName, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return db, nil
}
