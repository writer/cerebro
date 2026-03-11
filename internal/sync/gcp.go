package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/snowflake/tableops"
	"github.com/writer/cerebro/internal/warehouse"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// GCPSyncEngine orchestrates GCP resource syncing with change detection
type GCPSyncEngine struct {
	sf           warehouse.SyncWarehouse
	logger       *slog.Logger
	concurrency  int
	projectID    string
	tableFilter  map[string]struct{}
	rateLimiter  *rate.Limiter
	retryOptions retryOptions

	permissionUsageLookbackDays int
	gcpIAMTargetGroups          map[string]struct{}
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

func WithGCPPermissionUsageLookbackDays(days int) GCPEngineOption {
	return func(e *GCPSyncEngine) {
		e.permissionUsageLookbackDays = clampPermissionUsageLookbackDays(days)
	}
}

func WithGCPIAMTargetGroups(groups []string) GCPEngineOption {
	return func(e *GCPSyncEngine) {
		e.gcpIAMTargetGroups = normalizeIdentityFilterSet(groups)
	}
}

func NewGCPSyncEngine(sf warehouse.SyncWarehouse, logger *slog.Logger, opts ...GCPEngineOption) *GCPSyncEngine {
	e := &GCPSyncEngine{
		sf:                          sf,
		logger:                      logger,
		concurrency:                 10,
		permissionUsageLookbackDays: defaultPermissionUsageLookbackDays,
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
	return tableops.EnsureVariantTable(ctx, e.sf, table, columns, tableops.EnsureVariantTableOptions{
		AddMissingColumns:     true,
		IgnoreLookupError:     true,
		IgnoreAddColumnErrors: true,
	})
}

func (e *GCPSyncEngine) upsertWithChanges(ctx context.Context, table string, columns []string, rows []map[string]interface{}) (*ChangeSet, error) {
	scopeColumn, scopeValues := gcpScopeFilter(columns, rows, e.projectID)
	return upsertScopedRowsWithChanges(ctx, e.sf, e.logger, table, rows, scopeColumn, scopeValues, e.hashRowContent)
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

func (e *GCPSyncEngine) hashRowContent(row map[string]interface{}) string {
	return hashRowContentWithMode(row, false)
}

func (e *GCPSyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	return persistProviderChangeHistory(ctx, e.sf, e.logger, "gcp", results)
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
		e.gcpIAMGroupPermissionUsageTable(),
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
