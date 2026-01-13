package cloudquery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// SyncClient handles synchronization with CloudQuery data
type SyncClient struct {
	snowflake  *snowflake.Client
	httpClient *http.Client
	config     SyncConfig
}

// SyncConfig holds configuration for CloudQuery sync
type SyncConfig struct {
	CloudQueryURL     string // URL to CloudQuery API if using hosted
	SnowflakeDatabase string
	SnowflakeSchema   string
	SyncInterval      time.Duration
	Tables            []string // Specific tables to sync, empty means all
}

// SyncResult represents the result of a sync operation
type SyncResult struct {
	Table      string    `json:"table"`
	RowsSynced int64     `json:"rows_synced"`
	Duration   float64   `json:"duration_seconds"`
	Error      string    `json:"error,omitempty"`
	SyncedAt   time.Time `json:"synced_at"`
}

// NewSyncClient creates a new CloudQuery sync client
func NewSyncClient(sf *snowflake.Client, config SyncConfig) *SyncClient {
	return &SyncClient{
		snowflake: sf,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		config: config,
	}
}

// EnsureTables creates all CloudQuery tables in Snowflake
func (c *SyncClient) EnsureTables(ctx context.Context) error {
	tables := GetAllTableDefinitions()

	for _, table := range tables {
		sql := GenerateCreateTableSQL(table)
		if _, err := c.snowflake.DB().ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("create table %s: %w", table.Name, err)
		}
	}

	return nil
}

// SyncFromCloudQuery pulls data from CloudQuery API (if using hosted CloudQuery)
func (c *SyncClient) SyncFromCloudQuery(ctx context.Context) ([]SyncResult, error) {
	if c.config.CloudQueryURL == "" {
		return nil, fmt.Errorf("CloudQuery URL not configured")
	}

	tables := c.config.Tables
	if len(tables) == 0 {
		// Get all table names
		for name := range GetAllTableDefinitions() {
			tables = append(tables, name)
		}
	}

	var results []SyncResult
	for _, table := range tables {
		start := time.Now()
		result := SyncResult{
			Table:    table,
			SyncedAt: start,
		}

		count, err := c.syncTable(ctx, table)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.RowsSynced = count
		}

		result.Duration = time.Since(start).Seconds()
		results = append(results, result)
	}

	return results, nil
}

func (c *SyncClient) syncTable(ctx context.Context, table string) (int64, error) {
	url := fmt.Sprintf("%s/tables/%s/data", c.config.CloudQueryURL, table)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var rows []map[string]interface{}
	if err := json.Unmarshal(body, &rows); err != nil {
		return 0, err
	}

	return c.insertRows(ctx, table, rows)
}

func (c *SyncClient) insertRows(ctx context.Context, table string, rows []map[string]interface{}) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	tx, err := c.snowflake.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var count int64
	for _, row := range rows {
		cols, vals := buildInsertParams(row)
		placeholders := make([]string, len(vals))
		for i := range placeholders {
			placeholders[i] = "?"
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", //nolint:gosec // G201 - table name is from internal definitions
			table, joinStrings(cols, ", "), joinStrings(placeholders, ", "))

		if _, err := tx.ExecContext(ctx, query, vals...); err != nil {
			continue // Skip failed rows
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return count, nil
}

func buildInsertParams(row map[string]interface{}) ([]string, []interface{}) {
	var cols []string
	var vals []interface{}

	for k, v := range row {
		cols = append(cols, k)
		vals = append(vals, v)
	}

	return cols, vals
}

// QueryTable runs a custom query against a CloudQuery table
func (c *SyncClient) QueryTable(ctx context.Context, table, where string, limit int) ([]map[string]interface{}, error) {
	// Validate table name to prevent SQL injection
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	query := fmt.Sprintf("SELECT * FROM %s", table)
	if where != "" {
		query += " WHERE " + where
	}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := c.snowflake.DB().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}

	return results, rows.Err()
}

// GetTableStats returns statistics for a CloudQuery table
func (c *SyncClient) GetTableStats(ctx context.Context, table string) (*TableStats, error) {
	// Validate table name to prevent SQL injection
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name: %w", err)
	}

	stats := &TableStats{
		Table: table,
	}

	// Get row count
	var count int64
	row := c.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
	if err := row.Scan(&count); err != nil {
		return nil, err
	}
	stats.RowCount = count

	// Get last sync time
	var lastSync *time.Time
	row = c.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT MAX(_cq_sync_time) FROM %s", table))
	_ = row.Scan(&lastSync)
	stats.LastSync = lastSync

	// Get unique accounts
	var accounts int64
	row = c.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(DISTINCT account_id) FROM %s", table))
	_ = row.Scan(&accounts)
	stats.UniqueAccounts = accounts

	return stats, nil
}

// TableStats holds statistics for a CloudQuery table
type TableStats struct {
	Table          string     `json:"table"`
	RowCount       int64      `json:"row_count"`
	LastSync       *time.Time `json:"last_sync"`
	UniqueAccounts int64      `json:"unique_accounts"`
}

// ListAvailableTables returns tables that exist in Snowflake
func (c *SyncClient) ListAvailableTables(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = '%s' 
		AND table_name LIKE 'aws_%%'
		ORDER BY table_name
	`, c.config.SnowflakeSchema)

	rows, err := c.snowflake.DB().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tables = append(tables, name)
	}

	return tables, rows.Err()
}

// GetAssetInventory returns asset counts by type
func (c *SyncClient) GetAssetInventory(ctx context.Context) (map[string]int64, error) {
	tables := []string{
		"aws_ec2_instances",
		"aws_s3_buckets",
		"aws_rds_instances",
		"aws_lambda_functions",
		"aws_iam_users",
		"aws_iam_roles",
		"aws_ec2_security_groups",
		"aws_ec2_vpcs",
	}

	inventory := make(map[string]int64)
	for _, table := range tables {
		var count int64
		row := c.snowflake.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
		if err := row.Scan(&count); err != nil {
			continue
		}
		inventory[table] = count
	}

	return inventory, nil
}

// GetComplianceOverview returns compliance summary across frameworks
func (c *SyncClient) GetComplianceOverview(ctx context.Context) (*ComplianceOverview, error) {
	overview := &ComplianceOverview{
		Frameworks: make(map[string]*FrameworkCompliance),
	}

	query := `
		SELECT 
			framework,
			COUNT(*) as total,
			SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed,
			SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) as failed
		FROM policy_results
		WHERE evaluated_at > DATEADD(day, -1, CURRENT_TIMESTAMP())
		GROUP BY framework
	`

	rows, err := c.snowflake.DB().QueryContext(ctx, query)
	if err != nil {
		return overview, nil // Return empty if table doesn't exist
	}
	defer rows.Close()

	for rows.Next() {
		var framework string
		var total, passed, failed int64
		if err := rows.Scan(&framework, &total, &passed, &failed); err != nil {
			continue
		}
		overview.Frameworks[framework] = &FrameworkCompliance{
			Framework:    framework,
			TotalChecks:  total,
			PassedChecks: passed,
			FailedChecks: failed,
		}
		if total > 0 {
			overview.Frameworks[framework].ComplianceRate = float64(passed) / float64(total) * 100
		}
	}

	return overview, nil
}

// ComplianceOverview holds compliance summary across frameworks
type ComplianceOverview struct {
	Frameworks map[string]*FrameworkCompliance `json:"frameworks"`
}

// FrameworkCompliance holds compliance for a single framework
type FrameworkCompliance struct {
	Framework      string  `json:"framework"`
	TotalChecks    int64   `json:"total_checks"`
	PassedChecks   int64   `json:"passed_checks"`
	FailedChecks   int64   `json:"failed_checks"`
	ComplianceRate float64 `json:"compliance_rate"`
}
