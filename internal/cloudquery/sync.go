// Package cloudquery provides utilities for working with CloudQuery-synced data.
//
// CloudQuery is an external ELT tool that syncs cloud provider data to Snowflake.
// This package provides:
//   - Table schema definitions for CloudQuery tables (tables.go)
//   - DDL generation for creating tables in Snowflake
//   - Inventory and statistics queries for CloudQuery data
//
// Data sync is handled by the CloudQuery CLI via the `cerebro sync` command.
// Policy evaluation is handled by the Cedar engine in internal/policy/.
package cloudquery

import (
	"context"
	"fmt"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// TableManager provides utilities for managing CloudQuery tables in Snowflake
type TableManager struct {
	snowflake *snowflake.Client
	schema    string
}

// NewTableManager creates a new table manager
func NewTableManager(sf *snowflake.Client, schema string) *TableManager {
	return &TableManager{
		snowflake: sf,
		schema:    schema,
	}
}

// EnsureTables creates all CloudQuery tables in Snowflake if they don't exist
func (m *TableManager) EnsureTables(ctx context.Context) error {
	tables := GetAllTableDefinitions()

	for _, table := range tables {
		sql := GenerateCreateTableSQL(table)
		if _, err := m.snowflake.DB().ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("create table %s: %w", table.Name, err)
		}
	}

	return nil
}

// EnsureAWSTables creates only AWS CloudQuery tables
func (m *TableManager) EnsureAWSTables(ctx context.Context) error {
	tables := GetAllTableDefinitions()

	for _, table := range tables {
		sql := GenerateCreateTableSQL(table)
		if _, err := m.snowflake.DB().ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("create table %s: %w", table.Name, err)
		}
	}

	return nil
}

// EnsureGCPTables creates only GCP CloudQuery tables
func (m *TableManager) EnsureGCPTables(ctx context.Context) error {
	tables := GetAllGCPTableDefinitions()

	for _, table := range tables {
		sql := GenerateCreateTableSQL(table)
		if _, err := m.snowflake.DB().ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("create table %s: %w", table.Name, err)
		}
	}

	return nil
}

// EnsureAzureTables creates only Azure CloudQuery tables
func (m *TableManager) EnsureAzureTables(ctx context.Context) error {
	tables := GetAllAzureTableDefinitions()

	for _, table := range tables {
		sql := GenerateCreateTableSQL(table)
		if _, err := m.snowflake.DB().ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("create table %s: %w", table.Name, err)
		}
	}

	return nil
}

// TableStats holds statistics for a CloudQuery table
type TableStats struct {
	Table          string     `json:"table"`
	RowCount       int64      `json:"row_count"`
	LastSync       *time.Time `json:"last_sync"`
	UniqueAccounts int64      `json:"unique_accounts"`
}

// GetTableStats returns statistics for a CloudQuery table
func (m *TableManager) GetTableStats(ctx context.Context, table string) (*TableStats, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	stats := &TableStats{
		Table: table,
	}

	// Get row count
	var count int64
	row := m.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
	if err := row.Scan(&count); err != nil {
		return nil, err
	}
	stats.RowCount = count

	// Get last sync time (CloudQuery adds _cq_sync_time column)
	var lastSync *time.Time
	row = m.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT MAX(_cq_sync_time) FROM %s", table))
	_ = row.Scan(&lastSync) // Ignore error - column may not exist
	stats.LastSync = lastSync

	// Get unique accounts
	var accounts int64
	row = m.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(DISTINCT account_id) FROM %s", table))
	_ = row.Scan(&accounts) // Ignore error - column may not exist
	stats.UniqueAccounts = accounts

	return stats, nil
}

// ListAvailableTables returns CloudQuery tables that exist in Snowflake
func (m *TableManager) ListAvailableTables(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = '%s' 
		AND (table_name LIKE 'aws_%%' OR table_name LIKE 'gcp_%%' OR table_name LIKE 'azure_%%')
		ORDER BY table_name
	`, m.schema)

	rows, err := m.snowflake.DB().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tables = append(tables, name)
	}

	return tables, rows.Err()
}

// AssetInventory holds counts of assets by table
type AssetInventory struct {
	Tables      map[string]int64 `json:"tables"`
	TotalAssets int64            `json:"total_assets"`
	LastUpdated time.Time        `json:"last_updated"`
}

// GetAssetInventory returns asset counts by CloudQuery table
func (m *TableManager) GetAssetInventory(ctx context.Context) (*AssetInventory, error) {
	// Core tables to check for inventory
	tables := []string{
		"aws_ec2_instances",
		"aws_s3_buckets",
		"aws_rds_instances",
		"aws_lambda_functions",
		"aws_iam_users",
		"aws_iam_roles",
		"aws_ec2_security_groups",
		"aws_ec2_vpcs",
		"aws_kms_keys",
		"aws_cloudtrail_trails",
	}

	inventory := &AssetInventory{
		Tables:      make(map[string]int64),
		LastUpdated: time.Now(),
	}

	for _, table := range tables {
		var count int64
		row := m.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
		if err := row.Scan(&count); err != nil {
			continue // Table may not exist
		}
		inventory.Tables[table] = count
		inventory.TotalAssets += count
	}

	return inventory, nil
}

// DataFreshness holds information about data freshness
type DataFreshness struct {
	Table          string     `json:"table"`
	LastSyncTime   *time.Time `json:"last_sync_time"`
	HoursSinceSync float64    `json:"hours_since_sync"`
	IsStale        bool       `json:"is_stale"` // True if > 24 hours old
}

// CheckDataFreshness checks how fresh the CloudQuery data is
func (m *TableManager) CheckDataFreshness(ctx context.Context, table string) (*DataFreshness, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	freshness := &DataFreshness{
		Table: table,
	}

	var lastSync *time.Time
	row := m.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT MAX(_cq_sync_time) FROM %s", table))
	if err := row.Scan(&lastSync); err != nil {
		return freshness, nil // Return with nil timestamp if column doesn't exist
	}

	freshness.LastSyncTime = lastSync
	if lastSync != nil {
		freshness.HoursSinceSync = time.Since(*lastSync).Hours()
		freshness.IsStale = freshness.HoursSinceSync > 24
	}

	return freshness, nil
}
