package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// GCPSyncEngine orchestrates GCP resource syncing with change detection
type GCPSyncEngine struct {
	sf          *snowflake.Client
	logger      *slog.Logger
	concurrency int
	projectID   string
}

// GCPEngineOption configures the GCP sync engine
type GCPEngineOption func(*GCPSyncEngine)

func WithGCPProject(projectID string) GCPEngineOption {
	return func(e *GCPSyncEngine) { e.projectID = projectID }
}

func WithGCPConcurrency(n int) GCPEngineOption {
	return func(e *GCPSyncEngine) { e.concurrency = n }
}

func NewGCPSyncEngine(sf *snowflake.Client, logger *slog.Logger, opts ...GCPEngineOption) *GCPSyncEngine {
	e := &GCPSyncEngine{
		sf:          sf,
		logger:      logger,
		concurrency: 10,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// GCPTableSpec defines a GCP table to sync
type GCPTableSpec struct {
	Name    string
	Columns []string
	Fetch   func(ctx context.Context, projectID string) ([]map[string]interface{}, error)
}

// SyncAll syncs all GCP resources with change detection
func (e *GCPSyncEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	if e.projectID == "" {
		return nil, fmt.Errorf("GCP project ID not set")
	}

	tables := e.getGCPTables()
	results := make([]SyncResult, len(tables))
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.concurrency)

	for i, table := range tables {
		wg.Add(1)
		go func(idx int, t GCPTableSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := e.syncTable(ctx, t)
			results[idx] = result
		}(i, table)
	}

	wg.Wait()

	// Persist change history
	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, nil
}

func (e *GCPSyncEngine) syncTable(ctx context.Context, table GCPTableSpec) SyncResult {
	start := time.Now()
	result := SyncResult{
		Table: table.Name,
	}

	e.logger.Info("syncing", "table", table.Name)

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	rows, err := table.Fetch(ctx, e.projectID)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	changes, err := e.upsertWithChanges(ctx, table.Name, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("detected changes", "table", table.Name, "added", len(changes.Added), "modified", len(changes.Modified), "removed", len(changes.Removed))
	}

	e.logger.Info("synced", "table", table.Name, "count", result.Synced)
	return result
}

func (e *GCPSyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s VARIANT", strings.ToUpper(col))
	}

	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		_CQ_HASH VARCHAR,
		%s
	)`, table, strings.Join(colDefs, ", "))

	_, err := e.sf.Query(ctx, createQuery)
	if err != nil {
		return err
	}

	// Schema evolution: add missing columns
	existingCols, err := e.getTableColumns(ctx, table)
	if err != nil {
		return nil // Table might be new
	}

	existingSet := make(map[string]bool)
	for _, col := range existingCols {
		existingSet[strings.ToUpper(col)] = true
	}

	for _, col := range columns {
		upperCol := strings.ToUpper(col)
		if !existingSet[upperCol] {
			alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s VARIANT", table, upperCol)
			if _, err := e.sf.Exec(ctx, alterQuery); err != nil {
				e.logger.Debug("failed to add column", "table", table, "column", upperCol, "error", err)
			}
		}
	}

	return nil
}

func (e *GCPSyncEngine) getTableColumns(ctx context.Context, table string) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT COLUMN_NAME 
		FROM INFORMATION_SCHEMA.COLUMNS 
		WHERE TABLE_NAME = '%s' 
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`, strings.ToUpper(table))

	result, err := e.sf.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	var columns []string
	for _, row := range result.Rows {
		if col, ok := row["COLUMN_NAME"].(string); ok {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func (e *GCPSyncEngine) upsertWithChanges(ctx context.Context, table string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}

	if len(rows) == 0 {
		// Check for deletions even when no new rows
		existing := e.getExistingHashes(ctx, table)
		for id := range existing {
			changes.Removed = append(changes.Removed, id)
		}
		if len(changes.Removed) > 0 {
			if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
				e.logger.Debug("delete failed", "error", err)
			}
		}
		return changes, nil
	}

	// Get existing rows with their hashes
	existing := e.getExistingHashes(ctx, table)

	// Build new row map with hashes
	newRows := make(map[string]string)
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := e.hashRowContent(row)
		newRows[id] = hash
	}

	// Detect changes
	for id, oldHash := range existing {
		if newHash, exists := newRows[id]; !exists {
			changes.Removed = append(changes.Removed, id)
		} else if newHash != oldHash {
			changes.Modified = append(changes.Modified, id)
		}
	}

	for id := range newRows {
		if _, exists := existing[id]; !exists {
			changes.Added = append(changes.Added, id)
		}
	}

	// Delete all and reinsert (simple but effective)
	if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
		e.logger.Debug("delete failed", "error", err)
	}

	// Batch insert
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := e.hashRowContent(row)
		delete(row, "_cq_id")

		cols := []string{"_CQ_ID", "_CQ_HASH"}
		selects := []string{
			fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''")),
			fmt.Sprintf("'%s'", hash),
		}

		for k, v := range row {
			cols = append(cols, strings.ToUpper(k))
			jsonVal, _ := json.Marshal(v)
			// Escape single quotes and backslashes for Snowflake SQL
			escaped := string(jsonVal)
			escaped = strings.ReplaceAll(escaped, "\\", "\\\\")
			escaped = strings.ReplaceAll(escaped, "'", "''")
			selects = append(selects, fmt.Sprintf("PARSE_JSON('%s')", escaped))
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s",
			table, strings.Join(cols, ", "), strings.Join(selects, ", "))

		if _, err := e.sf.Exec(ctx, query); err != nil {
			return changes, fmt.Errorf("insert row: %w", err)
		}
	}

	return changes, nil
}

func (e *GCPSyncEngine) getExistingHashes(ctx context.Context, table string) map[string]string {
	result := make(map[string]string)

	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s", table)
	rows, err := e.sf.Query(ctx, query)
	if err != nil {
		return result
	}

	for _, row := range rows.Rows {
		id, _ := row["_CQ_ID"].(string)
		hash, _ := row["_CQ_HASH"].(string)
		if id != "" {
			result[id] = hash
		}
	}

	return result
}

func (e *GCPSyncEngine) hashRowContent(row map[string]interface{}) string {
	// Create deterministic JSON by sorting keys
	keys := make([]string, 0, len(row))
	for k := range row {
		if k != "_cq_id" && k != "_cq_hash" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		jsonVal, _ := json.Marshal(row[k])
		h.Write(jsonVal)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (e *GCPSyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
		id VARCHAR PRIMARY KEY,
		table_name VARCHAR,
		change_type VARCHAR,
		resource_id VARCHAR,
		sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		provider VARCHAR
	)`

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return err
	}

	// Ensure all columns exist (for tables created by older versions)
	alterQueries := []string{
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS change_type VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS provider VARCHAR",
	}
	for _, q := range alterQueries {
		if _, err := e.sf.Exec(ctx, q); err != nil {
			e.logger.Debug("failed to ensure change history column", "query", q, "error", err)
		}
	}

	for _, r := range results {
		if r.Changes == nil {
			continue
		}

		for _, id := range r.Changes.Added {
			e.insertChangeRecord(ctx, r.Table, "added", id, "gcp")
		}
		for _, id := range r.Changes.Modified {
			e.insertChangeRecord(ctx, r.Table, "modified", id, "gcp")
		}
		for _, id := range r.Changes.Removed {
			e.insertChangeRecord(ctx, r.Table, "removed", id, "gcp")
		}
	}

	return nil
}

func (e *GCPSyncEngine) insertChangeRecord(ctx context.Context, table, changeType, resourceID, provider string) {
	id := fmt.Sprintf("%s-%s-%s-%d", table, changeType, resourceID, time.Now().UnixNano())
	query := fmt.Sprintf(`INSERT INTO _sync_change_history (id, table_name, change_type, resource_id, provider) 
		VALUES ('%s', '%s', '%s', '%s', '%s')`,
		strings.ReplaceAll(id, "'", "''"),
		table,
		changeType,
		strings.ReplaceAll(resourceID, "'", "''"),
		provider)

	if _, err := e.sf.Exec(ctx, query); err != nil {
		e.logger.Debug("failed to insert change record", "error", err)
	}
}

// getGCPTables returns all GCP table definitions
func (e *GCPSyncEngine) getGCPTables() []GCPTableSpec {
	return []GCPTableSpec{
		// Compute
		e.gcpComputeInstanceTable(),
		e.gcpComputeFirewallTable(),
		// Networking
		e.gcpComputeNetworkTable(),
		e.gcpComputeSubnetworkTable(),
		// Storage
		e.gcpStorageBucketTable(),
		// IAM
		e.gcpIAMServiceAccountTable(),
		// Database
		e.gcpSQLInstanceTable(),
		// Serverless
		e.gcpCloudFunctionTable(),
		// Messaging
		e.gcpPubSubTopicTable(),
		// Container
		e.gcpGKEClusterTable(),
	}
}
