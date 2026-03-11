package snowflake

import (
	"context"
	"fmt"
	"strings"
)

// Schema definitions for Cerebro tables in Snowflake
const (
	// Asset tables live in the RAW schema; Cerebro tables go in CEREBRO.
	SchemaName = "CEREBRO"
)

// Table DDL statements
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
			resource_data VARIANT,
			description TEXT,
			remediation TEXT,
			first_seen TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			last_seen TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			resolved_at TIMESTAMP_NTZ,
			suppressed_at TIMESTAMP_NTZ,
			suppressed_by VARCHAR(128),
			suppression_reason TEXT,
			metadata VARIANT,
			_created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			_updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
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
			labels ARRAY,
			finding_ids ARRAY,
			asset_ids ARRAY,
			external_url VARCHAR(1024),
			metadata VARIANT,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			resolved_at TIMESTAMP_NTZ
		)`,

	"access_reviews": `
		CREATE TABLE IF NOT EXISTS %s.access_reviews (
			id VARCHAR(64) PRIMARY KEY,
			name VARCHAR(256) NOT NULL,
			description TEXT,
			type VARCHAR(64),
			status VARCHAR(32) DEFAULT 'draft',
			scope VARIANT,
			schedule VARIANT,
			reviewers ARRAY,
			stats VARIANT,
			created_by VARCHAR(128),
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			started_at TIMESTAMP_NTZ,
			due_at TIMESTAMP_NTZ,
			completed_at TIMESTAMP_NTZ
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
			access_grants VARIANT,
			risk_score INTEGER,
			risk_factors ARRAY,
			decision_action VARCHAR(32),
			decision_reviewer VARCHAR(128),
			decision_comment TEXT,
			decided_at TIMESTAMP_NTZ,
			metadata VARIANT,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
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
			properties VARIANT,
			findings ARRAY,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"attack_path_edges": `
		CREATE TABLE IF NOT EXISTS %s.attack_path_edges (
			id VARCHAR(64) PRIMARY KEY,
			source_id VARCHAR(64) NOT NULL,
			target_id VARCHAR(64) NOT NULL,
			type VARCHAR(64),
			risk VARCHAR(32),
			properties VARIANT,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"attack_paths": `
		CREATE TABLE IF NOT EXISTS %s.attack_paths (
			id VARCHAR(64) PRIMARY KEY,
			title VARCHAR(512),
			description TEXT,
			severity VARCHAR(32),
			score INTEGER,
			node_ids ARRAY,
			edge_ids ARRAY,
			steps VARIANT,
			remediation ARRAY,
			analyzed_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"agent_sessions": `
		CREATE TABLE IF NOT EXISTS %s.agent_sessions (
			id VARCHAR(64) PRIMARY KEY,
			agent_id VARCHAR(64) NOT NULL,
			user_id VARCHAR(128),
			status VARCHAR(32) DEFAULT 'active',
			context VARIANT,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"agent_messages": `
		CREATE TABLE IF NOT EXISTS %s.agent_messages (
			id VARCHAR(64) PRIMARY KEY,
			session_id VARCHAR(64) NOT NULL REFERENCES %s.agent_sessions(id),
			role VARCHAR(32) NOT NULL,
			content TEXT,
			tool_calls VARIANT,
			metadata VARIANT,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"provider_syncs": `
		CREATE TABLE IF NOT EXISTS %s.provider_syncs (
			id VARCHAR(64) PRIMARY KEY,
			provider VARCHAR(64) NOT NULL,
			status VARCHAR(32),
			started_at TIMESTAMP_NTZ,
			completed_at TIMESTAMP_NTZ,
			duration_ms INTEGER,
			tables_synced VARIANT,
			total_rows BIGINT,
			errors ARRAY
		)`,

	"risk_engine_state": `
		CREATE TABLE IF NOT EXISTS %s.risk_engine_state (
			graph_id VARCHAR(128) PRIMARY KEY,
			snapshot VARIANT,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"policy_history": `
		CREATE TABLE IF NOT EXISTS %s.policy_history (
			policy_id VARCHAR(128) NOT NULL,
			version INTEGER NOT NULL,
			content VARIANT NOT NULL,
			change_type VARCHAR(32),
			pinned_version INTEGER,
			effective_from TIMESTAMP_NTZ NOT NULL,
			effective_to TIMESTAMP_NTZ,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			PRIMARY KEY (policy_id, version)
		)`,

	"audit_log": `
		CREATE TABLE IF NOT EXISTS %s.audit_log (
			id VARCHAR(64) PRIMARY KEY,
			timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			action VARCHAR(128) NOT NULL,
			actor_id VARCHAR(128),
			actor_type VARCHAR(64),
			resource_type VARCHAR(64),
			resource_id VARCHAR(256),
			details VARIANT,
			ip_address VARCHAR(64),
			user_agent VARCHAR(512)
		)`,

	"webhooks": `
		CREATE TABLE IF NOT EXISTS %s.webhooks (
			id VARCHAR(64) PRIMARY KEY,
			url VARCHAR(2048) NOT NULL,
			events ARRAY,
			secret VARCHAR(256),
			enabled BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)`,

	"webhook_deliveries": `
		CREATE TABLE IF NOT EXISTS %s.webhook_deliveries (
			id VARCHAR(64) PRIMARY KEY,
			webhook_id VARCHAR(64) NOT NULL REFERENCES %s.webhooks(id),
			event_type VARCHAR(128),
			payload VARIANT,
			response_status INTEGER,
			response_body TEXT,
			delivered_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			duration_ms INTEGER
		)`,
}

// CreateSchema creates the Cerebro schema if it doesn't exist
func (c *Client) CreateSchema(ctx context.Context) error {
	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s.%s", c.database, SchemaName)
	_, err := c.db.ExecContext(ctx, query)
	return err
}

// CreateTables creates all Cerebro tables
func (c *Client) CreateTables(ctx context.Context) error {
	schema := fmt.Sprintf("%s.%s", c.database, SchemaName)

	for name, ddl := range TableDDLs {
		// Handle tables with multiple schema references
		var formattedDDL string
		if strings.Count(ddl, "%s") == 1 {
			formattedDDL = fmt.Sprintf(ddl, schema)
		} else {
			// For tables with foreign keys
			formattedDDL = fmt.Sprintf(ddl, schema, schema)
		}

		if _, err := c.db.ExecContext(ctx, formattedDDL); err != nil {
			return fmt.Errorf("create table %s: %w", name, err)
		}
	}
	return nil
}

// Bootstrap creates schema and all tables
func (c *Client) Bootstrap(ctx context.Context) error {
	if err := c.CreateSchema(ctx); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if err := c.CreateTables(ctx); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	return nil
}

// DropSchema drops the Cerebro schema (use with caution)
func (c *Client) DropSchema(ctx context.Context) error {
	query := fmt.Sprintf("DROP SCHEMA IF EXISTS %s.%s CASCADE", c.database, SchemaName)
	_, err := c.db.ExecContext(ctx, query)
	return err
}
