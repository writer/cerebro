package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/metrics"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// GCPSyncEngine orchestrates GCP resource syncing with change detection
type GCPSyncEngine struct {
	sf           *snowflake.Client
	logger       *slog.Logger
	concurrency  int
	projectID    string
	tableFilter  map[string]struct{}
	rateLimiter  *rate.Limiter
	retryOptions retryOptions
}

// GCPEngineOption configures the GCP sync engine
type GCPEngineOption func(*GCPSyncEngine)

func WithGCPProject(projectID string) GCPEngineOption {
	return func(e *GCPSyncEngine) { e.projectID = projectID }
}

func WithGCPConcurrency(n int) GCPEngineOption {
	return func(e *GCPSyncEngine) { e.concurrency = n }
}

func WithGCPTableFilter(tables []string) GCPEngineOption {
	return func(e *GCPSyncEngine) { e.tableFilter = normalizeTableFilter(tables) }
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
	if e.rateLimiter == nil {
		e.rateLimiter = rate.NewLimiter(defaultGCPRateLimit, defaultGCPRateBurst)
	}
	if e.retryOptions.Attempts == 0 {
		e.retryOptions = defaultGCPRetryOptions()
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

	tables := filterGCPTables(e.getGCPTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no GCP tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}
	results := make([]SyncResult, len(tables))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for i, table := range tables {
		idx := i
		tableSpec := table
		group.Go(func() error {
			result, err := e.syncTable(ctx, tableSpec)
			results[idx] = result
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()

	// Persist change history
	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, errors.Join(errs...)
}

// ValidateTables ensures required Snowflake tables exist without fetching GCP resources.
func (e *GCPSyncEngine) ValidateTables(ctx context.Context) ([]SyncResult, error) {
	if e.projectID == "" {
		return nil, fmt.Errorf("GCP project ID not set")
	}

	tables := filterGCPTables(e.getGCPTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no GCP tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}

	results := make([]SyncResult, len(tables))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for i, table := range tables {
		idx := i
		tableSpec := table
		group.Go(func() error {
			result, err := e.validateTable(ctx, tableSpec)
			results[idx] = result
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

func (e *GCPSyncEngine) syncTable(ctx context.Context, table GCPTableSpec) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table: table.Name,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("gcp", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): invalid table name: %w", table.Name, e.projectID, err)
	}

	e.logger.Info("syncing", "table", table.Name)

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): ensure table: %w", table.Name, e.projectID, err)
	}

	rows, err := e.fetchWithRetry(ctx, table)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): fetch: %w", table.Name, e.projectID, err)
	}

	rows = normalizeRows(table.Name, table.Columns, rows, e.logger)

	changes, err := e.upsertWithChanges(ctx, table.Name, table.Columns, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): upsert: %w", table.Name, e.projectID, err)
	}

	syncTime := time.Now().UTC()
	if err := e.emitCDCEvents(ctx, table.Name, changes, rows, syncTime); err != nil {
		e.logger.Warn("failed to emit CDC events", "table", table.Name, "error", err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.SyncTime = syncTime
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("detected changes", "table", table.Name, "added", len(changes.Added), "modified", len(changes.Modified), "removed", len(changes.Removed))
	}

	e.logger.Info("synced", "table", table.Name, "count", result.Synced)
	return result, nil
}

func (e *GCPSyncEngine) validateTable(ctx context.Context, table GCPTableSpec) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table: table.Name,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("gcp", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): invalid table name: %w", table.Name, e.projectID, err)
	}

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp %s (project %s): ensure table: %w", table.Name, e.projectID, err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *GCPSyncEngine) emitCDCEvents(ctx context.Context, table string, changes *ChangeSet, rows []map[string]interface{}, syncTime time.Time) error {
	if changes == nil || !changes.HasChanges() {
		return nil
	}

	lookup := buildRowLookup(rows)
	events := buildCDCEventsFromChanges(table, "gcp", "", e.projectID, changes, lookup, syncTime, e.hashRowContent)
	if len(events) == 0 {
		return nil
	}

	return e.sf.InsertCDCEvents(ctx, events)
}

func (e *GCPSyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	for _, col := range columns {
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}

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

	_, err := e.sf.Exec(ctx, createQuery)
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
			alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s VARIANT", table, upperCol)
			if _, err := e.sf.Exec(ctx, alterQuery); err != nil {
				e.logger.Debug("failed to add column", "table", table, "column", upperCol, "error", err)
			}
		}
	}

	return nil
}

func (e *GCPSyncEngine) getTableColumns(ctx context.Context, table string) ([]string, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, err
	}

	query := `
		SELECT COLUMN_NAME 
		FROM INFORMATION_SCHEMA.COLUMNS 
		WHERE TABLE_NAME = ?
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`

	result, err := e.sf.Query(ctx, query, strings.ToUpper(table))
	if err != nil {
		return nil, err
	}

	var columns []string
	for _, row := range result.Rows {
		if col := queryRowString(row, "column_name"); col != "" {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func (e *GCPSyncEngine) upsertWithChanges(ctx context.Context, table string, columns []string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}
	scopeColumn, scopeValues := gcpScopeFilter(columns, rows, e.projectID)

	if len(rows) == 0 {
		// Check for deletions even when no new rows
		existing := e.getExistingHashes(ctx, table, scopeColumn, scopeValues)
		for id := range existing {
			changes.Removed = append(changes.Removed, id)
		}
		if len(changes.Removed) > 0 {
			if err := e.deleteScopedRows(ctx, table, scopeColumn, scopeValues); err != nil {
				e.logger.Debug("delete failed", "error", err)
			}
		}
		return changes, nil
	}

	// Get existing rows with their hashes
	existing := e.getExistingHashes(ctx, table, scopeColumn, scopeValues)

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

	// Delete scoped rows and reinsert
	if err := e.deleteScopedRows(ctx, table, scopeColumn, scopeValues); err != nil {
		e.logger.Debug("delete failed", "error", err)
	}

	insertRows := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := e.hashRowContent(row)
		newRow := make(map[string]interface{}, len(row)+1)
		newRow["_cq_id"] = id
		newRow["_cq_hash"] = hash
		for k, v := range row {
			if k == "_cq_id" || k == "_cq_hash" {
				continue
			}
			newRow[k] = v
		}
		insertRows = append(insertRows, newRow)
	}

	if err := insertRowsBatch(ctx, e.sf, table, insertRows); err != nil {
		return changes, fmt.Errorf("insert rows: %w", err)
	}

	return changes, nil
}

func (e *GCPSyncEngine) getExistingHashes(ctx context.Context, table, scopeColumn string, scopeValues []string) map[string]string {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result
	}

	whereClause, args := gcpScopeWhereClause(scopeColumn, scopeValues)
	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s%s", table, whereClause)
	rows, err := e.sf.Query(ctx, query, args...)
	if err != nil {
		return result
	}

	return decodeExistingHashes(rows.Rows)
}

func (e *GCPSyncEngine) deleteScopedRows(ctx context.Context, table, scopeColumn string, scopeValues []string) error {
	whereClause, args := gcpScopeWhereClause(scopeColumn, scopeValues)
	if whereClause == "" {
		if _, err := e.sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
			if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
				return err
			}
		}
		return nil
	}

	query := fmt.Sprintf("DELETE FROM %s%s", table, whereClause)
	_, err := e.sf.Exec(ctx, query, args...)
	return err
}

func gcpScopeFilter(columns []string, rows []map[string]interface{}, projectID string) (string, []string) {
	column := ""
	switch {
	case hasColumn(columns, "project_id"):
		column = "PROJECT_ID"
	case hasColumn(columns, "project"):
		column = "PROJECT"
	default:
		return "", nil
	}

	values := make(map[string]struct{})
	lookupKey := strings.ToLower(column)
	for _, row := range rows {
		if row == nil {
			continue
		}
		raw, ok := row[lookupKey]
		if !ok || raw == nil {
			continue
		}
		if val := strings.TrimSpace(stringValue(raw)); val != "" {
			values[val] = struct{}{}
		}
	}
	if len(values) == 0 && strings.TrimSpace(projectID) != "" {
		values[strings.TrimSpace(projectID)] = struct{}{}
	}

	out := make([]string, 0, len(values))
	for val := range values {
		out = append(out, val)
	}
	sort.Strings(out)
	return column, out
}

func gcpScopeWhereClause(column string, values []string) (string, []interface{}) {
	if column == "" || len(values) == 0 {
		return "", nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
	args := make([]interface{}, len(values))
	for i, value := range values {
		args[i] = value
	}

	return fmt.Sprintf(" WHERE %s IN (%s)", column, placeholders), args
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
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()",
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

		syncTime := r.SyncTime
		if syncTime.IsZero() {
			syncTime = time.Now().UTC()
		}

		for _, id := range r.Changes.Added {
			e.insertChangeRecord(ctx, r.Table, "added", id, "gcp", syncTime)
		}
		for _, id := range r.Changes.Modified {
			e.insertChangeRecord(ctx, r.Table, "modified", id, "gcp", syncTime)
		}
		for _, id := range r.Changes.Removed {
			e.insertChangeRecord(ctx, r.Table, "removed", id, "gcp", syncTime)
		}
	}

	return nil
}

func (e *GCPSyncEngine) insertChangeRecord(ctx context.Context, table, changeType, resourceID, provider string, syncTime time.Time) {
	id := fmt.Sprintf("%s-%s-%s-%d", table, changeType, resourceID, syncTime.UnixNano())
	query := `INSERT INTO _sync_change_history (id, table_name, change_type, resource_id, sync_time, provider)
		SELECT ?, ?, ?, ?, ?, ?`

	if _, err := e.sf.Exec(ctx, query, id, table, changeType, resourceID, syncTime, provider); err != nil {
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
		e.gcpStorageObjectTable(),
		// KMS
		e.gcpKMSKeyTable(),
		// IAM
		e.gcpIAMServiceAccountTable(),
		e.gcpIAMServiceAccountKeyTable(),
		e.gcpIAMPolicyTable(),
		e.gcpIAMMemberTable(),
		// Database
		e.gcpSQLInstanceTable(),
		// Serverless
		e.gcpCloudFunctionTable(),
		e.gcpCloudRunServiceTable(),
		e.gcpCloudRunRevisionTable(),
		// Messaging
		e.gcpPubSubTopicTable(),
		// Container
		e.gcpGKEClusterTable(),
		e.gcpGKENodePoolTable(),
		// Artifact Registry
		e.gcpArtifactRegistryRepositoryTable(),
		e.gcpArtifactRegistryPackageTable(),
		e.gcpArtifactRegistryVersionTable(),
		// Logging
		e.gcpLoggingSinkTable(),
		e.gcpLoggingProjectSinkTable(),
		// Governance
		e.gcpOrgPolicyTable(),
		// Security
		e.gcpIdsEndpointTable(),
	}
}
