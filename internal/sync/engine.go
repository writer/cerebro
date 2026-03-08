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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/snowflake/tableops"
)

// SyncEngine orchestrates cloud resource syncing
type SyncEngine struct {
	sf                 *snowflake.Client
	logger             *slog.Logger
	concurrency        int
	regions            []string
	accountID          string
	tableInit          sync.Map
	tableFilter        map[string]struct{}
	rateLimiter        *rate.Limiter
	retryOptions       retryOptions
	stalenessThreshold time.Duration
}

type tableInitState struct {
	mu    sync.Mutex
	ready bool
}

// EngineOption configures the sync engine
type EngineOption func(*SyncEngine)

func WithConcurrency(n int) EngineOption {
	return func(e *SyncEngine) { e.concurrency = n }
}

func WithRegions(regions []string) EngineOption {
	return func(e *SyncEngine) { e.regions = regions }
}

func WithTableFilter(tables []string) EngineOption {
	return func(e *SyncEngine) { e.tableFilter = normalizeTableFilter(tables) }
}

func WithRateLimiter(limiter *rate.Limiter) EngineOption {
	return func(e *SyncEngine) { e.rateLimiter = limiter }
}

func WithStalenessThreshold(threshold time.Duration) EngineOption {
	return func(e *SyncEngine) { e.stalenessThreshold = threshold }
}

// DefaultAWSRegions returns commonly used AWS regions for multi-region scanning
var DefaultAWSRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"eu-west-1",
	"eu-west-2",
	"eu-central-1",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
}

func NewSyncEngine(sf *snowflake.Client, logger *slog.Logger, opts ...EngineOption) *SyncEngine {
	e := &SyncEngine{
		sf:          sf,
		logger:      logger,
		concurrency: 20,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.rateLimiter == nil {
		e.rateLimiter = rate.NewLimiter(defaultAWSRateLimit, defaultAWSRateBurst)
	}
	if e.retryOptions.Attempts == 0 {
		e.retryOptions = defaultAWSRetryOptions()
	}
	if e.stalenessThreshold == 0 {
		e.stalenessThreshold = defaultSyncStalenessThreshold
	}
	return e
}

// SyncAll syncs all AWS resources with parallel execution
func (e *SyncEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return e.SyncAllWithConfig(ctx, cfg)
}

// SyncAllWithConfig syncs all AWS resources with a preloaded AWS config
func (e *SyncEngine) SyncAllWithConfig(ctx context.Context, cfg aws.Config) ([]SyncResult, error) {
	// Get account ID
	e.accountID = e.getAccountID(ctx, cfg)

	if len(e.regions) == 0 {
		region := cfg.Region
		if region == "" {
			region = "us-east-1"
		}
		e.regions = []string{region}
	}

	// Define all tables to sync
	tables := filterTableSpecs(e.getAWSTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no AWS tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}

	backfillRequests := e.loadBackfillRequests(ctx)
	generationID := newSyncGenerationID("aws", e.accountID, time.Now().UTC())

	// Create work queue
	type workItem struct {
		table  TableSpec
		region string
	}

	var work []workItem
	for _, table := range tables {
		regions := e.regionsForTable(table)
		if len(regions) == 0 {
			e.logger.Info("skipping table with no eligible regions", "table", table.Name)
			continue
		}
		for _, region := range regions {
			work = append(work, workItem{table: table, region: region})
		}
	}
	if len(work) == 0 {
		e.logger.Warn("no AWS tables to sync after region scoping")
		return []SyncResult{}, nil
	}

	sort.SliceStable(work, func(i, j int) bool {
		leftOrder := syncDependencyOrder(work[i].table.Name)
		rightOrder := syncDependencyOrder(work[j].table.Name)
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}

		leftBackfill := hasBackfillRequest(backfillRequests, work[i].table.Name, work[i].region)
		rightBackfill := hasBackfillRequest(backfillRequests, work[j].table.Name, work[j].region)
		if leftBackfill != rightBackfill {
			return leftBackfill && !rightBackfill
		}

		if work[i].table.Name != work[j].table.Name {
			return work[i].table.Name < work[j].table.Name
		}
		return work[i].region < work[j].region
	})
	if len(backfillRequests) > 0 {
		e.logger.Info("ordered sync queue by dependency and queued backfill priority", "backfill_count", len(backfillRequests))
	} else {
		e.logger.Info("ordered sync queue by dependency priority")
	}

	results := make([]SyncResult, len(work))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	serviceLimiters := buildServiceLimiters(limit)
	for i, w := range work {
		idx := i
		item := w
		group.Go(func() error {
			backfillReason, forceBackfill := backfillRequests[backfillRequestKey(item.table.Name, item.region)]
			var serviceLimiter chan struct{}
			if key, _ := serviceLimitForTable(item.table.Name); key != "" {
				serviceLimiter = serviceLimiters[key]
			}
			if serviceLimiter != nil {
				serviceLimiter <- struct{}{}
				defer func() { <-serviceLimiter }()
			}
			result, err := e.syncTable(ctx, cfg, item.table, item.region, forceBackfill, backfillReason, generationID)
			result.GenerationID = generationID
			results[idx] = result
			if recErr := e.recordGenerationResult(ctx, generationID, result, err); recErr != nil {
				e.logger.Warn("failed to record sync generation status", "generation_id", generationID, "table", result.Table, "region", result.Region, "error", recErr)
			}
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()

	if alert, ok := detectSyncStaleness(results, e.stalenessThreshold); ok {
		e.logger.Warn("detected sync staleness divergence",
			"generation_id", generationID,
			"threshold", alert.Threshold.String(),
			"drift", alert.Drift.String(),
			"oldest_table", alert.Min.Table,
			"oldest_region", alert.Min.Region,
			"oldest_sync_time", alert.Min.SyncTime,
			"newest_table", alert.Max.Table,
			"newest_region", alert.Max.Region,
			"newest_sync_time", alert.Max.SyncTime,
		)
		if err := e.recordGenerationAlert(ctx, generationID, alert); err != nil {
			e.logger.Warn("failed to persist sync staleness alert", "generation_id", generationID, "error", err)
		}
	}

	// Persist change history
	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, errors.Join(errs...)
}

// ValidateTablesWithConfig ensures required Snowflake tables exist without fetching cloud resources.
func (e *SyncEngine) ValidateTablesWithConfig(ctx context.Context, cfg aws.Config) ([]SyncResult, error) {
	// Get account ID to validate credentials
	e.accountID = e.getAccountID(ctx, cfg)

	if len(e.regions) == 0 {
		region := cfg.Region
		if region == "" {
			region = "us-east-1"
		}
		e.regions = []string{region}
	}

	tables := filterTableSpecs(e.getAWSTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no AWS tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}

	type workItem struct {
		table  TableSpec
		region string
	}

	var work []workItem
	for _, table := range tables {
		regions := e.regionsForTable(table)
		if len(regions) == 0 {
			e.logger.Info("skipping table with no eligible regions", "table", table.Name)
			continue
		}
		for _, region := range regions {
			work = append(work, workItem{table: table, region: region})
		}
	}
	if len(work) == 0 {
		e.logger.Warn("no AWS tables to validate after region scoping")
		return []SyncResult{}, nil
	}

	results := make([]SyncResult, len(work))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	serviceLimiters := buildServiceLimiters(limit)
	for i, w := range work {
		idx := i
		item := w
		group.Go(func() error {
			var serviceLimiter chan struct{}
			if key, _ := serviceLimitForTable(item.table.Name); key != "" {
				serviceLimiter = serviceLimiters[key]
			}
			if serviceLimiter != nil {
				serviceLimiter <- struct{}{}
				defer func() { <-serviceLimiter }()
			}
			result, err := e.validateTable(ctx, item.table, item.region)
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

func (e *SyncEngine) syncTable(ctx context.Context, cfg aws.Config, table TableSpec, region string, forceBackfill bool, backfillReason string, generationID string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:        table.Name,
		Region:       region,
		GenerationID: generationID,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("aws", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("aws %s (%s): invalid table name: %w", table.Name, region, err)
	}

	// Create regional config
	regionalCfg := cfg.Copy()
	regionalCfg.Region = region

	if forceBackfill {
		if backfillReason == "" {
			backfillReason = "queued backfill request"
		}
		e.logger.Info("processing queued backfill request", "table", table.Name, "region", region, "reason", backfillReason)
		ctx = withForceFullBackfill(ctx)
	}

	// Ensure table exists with correct schema
	if err := e.ensureTableOnce(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("aws %s (%s): ensure table: %w", table.Name, region, err)
	}

	// Fetch resources
	rows, err := e.fetchWithRetry(ctx, table, regionalCfg, region)
	partialFetch := false
	if err != nil {
		if isPartialFetchError(err) && len(rows) > 0 {
			partialFetch = true
			result.BackfillPending = true
			e.logger.Warn("fetch returned partial results; enabling backfill-safe upsert", "table", table.Name, "region", region, "rows", len(rows), "error", err)
			if recErr := e.recordBackfillRequest(ctx, table.Name, region, err.Error()); recErr != nil {
				e.logger.Warn("failed to record backfill request", "table", table.Name, "region", region, "error", recErr)
			}
		} else {
			e.logger.Error("fetch failed", "table", table.Name, "region", region, "error", err)
			result.Errors = 1
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, fmt.Errorf("aws %s (%s): fetch: %w", table.Name, region, err)
		}
	}

	rows = e.normalizeAWSRows(table, region, rows)

	// Upsert with change detection
	incremental := table.Mode == TableSyncModeIncremental || partialFetch
	changes, err := e.upsertWithChanges(ctx, table.Name, table.Columns, region, rows, incremental, table.Scope)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("aws %s (%s): upsert: %w", table.Name, region, err)
	}

	syncTime := time.Now().UTC()
	if err := e.emitCDCEvents(ctx, table.Name, region, changes, rows, syncTime); err != nil {
		e.logger.Warn("failed to emit CDC events", "table", table.Name, "error", err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.SyncTime = syncTime
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("sync complete with changes",
			"table", table.Name,
			"region", region,
			"synced", result.Synced,
			"changes", changes.Summary())
	}

	if !partialFetch {
		if clearErr := e.clearBackfillRequest(ctx, table.Name, region); clearErr != nil {
			e.logger.Debug("failed to clear backfill request", "table", table.Name, "region", region, "error", clearErr)
		}
	}

	return result, nil
}

func (e *SyncEngine) validateTable(ctx context.Context, table TableSpec, region string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: region,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("aws", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("aws %s (%s): invalid table name: %w", table.Name, region, err)
	}

	if err := e.ensureTableOnce(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("aws %s (%s): ensure table: %w", table.Name, region, err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func hasColumn(columns []string, name string) bool {
	upper := strings.ToUpper(name)
	for _, column := range columns {
		if strings.ToUpper(column) == upper {
			return true
		}
	}
	return false
}

func (e *SyncEngine) emitCDCEvents(ctx context.Context, table, region string, changes *ChangeSet, rows []map[string]interface{}, syncTime time.Time) error {
	if changes == nil || !changes.HasChanges() {
		return nil
	}

	lookup := buildRowLookup(rows)
	events := buildCDCEventsFromChanges(table, "aws", region, e.accountID, changes, lookup, syncTime, hashRowContent)
	if len(events) == 0 {
		return nil
	}

	return e.sf.InsertCDCEvents(ctx, events)
}

func (e *SyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	return tableops.EnsureVariantTable(ctx, e.sf, table, columns, tableops.EnsureVariantTableOptions{
		AddMissingColumns:     true,
		IgnoreLookupError:     true,
		IgnoreAddColumnErrors: true,
	})
}

func (e *SyncEngine) ensureTableOnce(ctx context.Context, table string, columns []string) error {
	stateValue, _ := e.tableInit.LoadOrStore(table, &tableInitState{})
	state := stateValue.(*tableInitState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.ready {
		return nil
	}

	if err := e.ensureTable(ctx, table, columns); err != nil {
		return err
	}

	state.ready = true
	return nil
}

func (e *SyncEngine) upsertWithChanges(ctx context.Context, table string, columns []string, region string, rows []map[string]interface{}, incremental bool, scope TableRegionScope) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	hasRegion := hasColumn(columns, "region")
	hasAccount := hasColumn(columns, "account_id")
	globalScope := scope == TableRegionScopeGlobal

	if len(rows) == 0 {
		if incremental {
			return changes, nil
		}
		existing, err := e.getExistingHashes(ctx, table, region, hasRegion, hasAccount, globalScope)
		if err != nil {
			return changes, fmt.Errorf("get existing hashes: %w", err)
		}
		changes = detectRowChanges(existing, map[string]string{}, false)
		if len(changes.Removed) > 0 {
			if err := e.deleteScopedRows(ctx, table, region, hasRegion, hasAccount, globalScope); err != nil {
				return changes, fmt.Errorf("delete scoped rows: %w", err)
			}
		}
		return changes, nil
	}

	rows = dedupeRowsByID(rows)

	// Get existing rows with their hashes
	existing, err := e.getExistingHashes(ctx, table, region, hasRegion, hasAccount, globalScope)
	if err != nil {
		return changes, fmt.Errorf("get existing hashes: %w", err)
	}

	// Build new row map with hashes
	newRows := buildRowHashes(rows, hashRowContent)
	changes = detectRowChanges(existing, newRows, incremental)

	// Build row set for atomic upsert.
	mergeRows := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := hashRowContent(row)
		newRow := make(map[string]interface{}, len(row)+1)
		newRow["_cq_id"] = id
		newRow["_cq_hash"] = hash
		for k, v := range row {
			if k == "_cq_id" || k == "_cq_hash" {
				continue
			}
			newRow[k] = v
		}
		mergeRows = append(mergeRows, newRow)
	}

	// Atomic upsert via MERGE - no delete-before-insert window.
	if err := mergeRowsBatch(ctx, e.sf, table, mergeRows); err != nil {
		return changes, fmt.Errorf("merge rows: %w", err)
	}

	// For full snapshots, remove rows that disappeared from source.
	if !incremental && len(changes.Removed) > 0 {
		removedIDs := make(map[string]string, len(changes.Removed))
		for _, id := range changes.Removed {
			removedIDs[id] = ""
		}
		if err := e.deleteRowsByID(ctx, table, removedIDs, region, hasRegion, hasAccount, globalScope); err != nil {
			return changes, fmt.Errorf("delete removed rows: %w", err)
		}
	}

	return changes, nil
}

func (e *SyncEngine) deleteRowsByID(ctx context.Context, table string, ids map[string]string, region string, hasRegion bool, hasAccount bool, globalScope bool) error {
	if len(ids) == 0 {
		return nil
	}
	scopeWhere, scopeArgs := e.scopeWhereClause(region, hasRegion, hasAccount, globalScope)
	scopeCondition := strings.TrimPrefix(scopeWhere, " WHERE ")
	if scopeCondition == "" && requiresScopedDelete(hasRegion, hasAccount, globalScope) {
		return fmt.Errorf("refusing unscoped delete-by-id for table %s", table)
	}

	keys := make([]string, 0, len(ids))
	for id := range ids {
		if id == "" {
			continue
		}
		keys = append(keys, id)
	}
	if len(keys) == 0 {
		return nil
	}

	for start := 0; start < len(keys); start += insertBatchSize {
		end := start + insertBatchSize
		if end > len(keys) {
			end = len(keys)
		}
		batch := keys[start:end]
		placeholders := strings.TrimRight(strings.Repeat("?,", len(batch)), ",")
		args := make([]interface{}, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		query := fmt.Sprintf("DELETE FROM %s WHERE _CQ_ID IN (%s)", table, placeholders)
		if scopeCondition != "" {
			query = fmt.Sprintf("%s AND %s", query, scopeCondition)
			args = append(args, scopeArgs...)
		}
		if _, err := e.sf.Exec(ctx, query, args...); err != nil {
			return err
		}
	}

	return nil
}

func (e *SyncEngine) getExistingHashes(ctx context.Context, table string, region string, hasRegion bool, hasAccount bool, globalScope bool) (map[string]string, error) {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result, err
	}

	where, args := e.scopeWhereClause(region, hasRegion, hasAccount, globalScope)
	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s%s", table, where)
	rows, err := e.sf.Query(ctx, query, args...)
	if err != nil {
		return result, err
	}

	return decodeExistingHashes(rows.Rows), nil
}

func (e *SyncEngine) deleteScopedRows(ctx context.Context, table string, region string, hasRegion bool, hasAccount bool, globalScope bool) error {
	where, args := e.scopeWhereClause(region, hasRegion, hasAccount, globalScope)
	if where == "" {
		if requiresScopedDelete(hasRegion, hasAccount, globalScope) {
			return fmt.Errorf("refusing unscoped delete for table %s", table)
		}
		if _, err := e.sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
			if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
				return err
			}
		}
		return nil
	}
	query := fmt.Sprintf("DELETE FROM %s%s", table, where)
	_, err := e.sf.Exec(ctx, query, args...)
	return err
}

func (e *SyncEngine) scopeWhereClause(region string, hasRegion bool, hasAccount bool, globalScope bool) (string, []interface{}) {
	clauses := make([]string, 0, 2)
	args := make([]interface{}, 0, 2)

	if hasAccount && e.accountID != "" {
		clauses = append(clauses, "ACCOUNT_ID = ?")
		args = append(args, e.accountID)
	}

	if hasRegion && !globalScope {
		clauses = append(clauses, "REGION = ?")
		args = append(args, region)
	}

	if len(clauses) == 0 {
		return "", nil
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}

func requiresScopedDelete(hasRegion bool, hasAccount bool, globalScope bool) bool {
	return hasAccount || hasRegion || globalScope
}

func (e *SyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	// Create change history table if not exists
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
		id VARCHAR PRIMARY KEY,
		table_name VARCHAR,
		resource_id VARCHAR,
		operation VARCHAR,
		region VARCHAR,
		account_id VARCHAR,
		provider VARCHAR,
		timestamp TIMESTAMP_TZ,
		_cq_sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create change history table: %w", err)
	}
	for _, query := range []string{
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS operation VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS region VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS account_id VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS provider VARCHAR",
		"ALTER TABLE _sync_change_history ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP_TZ",
	} {
		if _, err := e.sf.Exec(ctx, query); err != nil {
			e.logger.Debug("failed to ensure change history column", "query", query, "error", err)
		}
	}

	// Insert changes
	for _, r := range results {
		if r.Changes == nil {
			continue
		}

		syncTime := r.SyncTime
		if syncTime.IsZero() {
			syncTime = time.Now().UTC()
		}

		for _, id := range r.Changes.Added {
			e.insertChangeRecord(ctx, r.Table, id, "add", r.Region, syncTime)
		}
		for _, id := range r.Changes.Modified {
			e.insertChangeRecord(ctx, r.Table, id, "modify", r.Region, syncTime)
		}
		for _, id := range r.Changes.Removed {
			e.insertChangeRecord(ctx, r.Table, id, "remove", r.Region, syncTime)
		}
	}

	return nil
}

func (e *SyncEngine) insertChangeRecord(ctx context.Context, table, resourceID, op, region string, ts time.Time) {
	id := fmt.Sprintf("%s-%s-%s-%d", table, resourceID, op, ts.UnixNano())
	query := `INSERT INTO _sync_change_history (id, table_name, resource_id, operation, region, account_id, provider, timestamp)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?`

	if _, err := e.sf.Exec(ctx, query, id, table, resourceID, op, region, e.accountID, "aws", ts); err != nil {
		e.logger.Debug("failed to insert change record", "error", err)
	}
}

func (e *SyncEngine) ensureBackfillQueueTable(ctx context.Context) error {
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_backfill_queue (
		id VARCHAR PRIMARY KEY,
		provider VARCHAR,
		table_name VARCHAR,
		region VARCHAR,
		account_id VARCHAR,
		reason VARCHAR,
		requested_at TIMESTAMP_TZ,
		_cq_sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`
	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create backfill queue: %w", err)
	}
	return nil
}

func backfillRequestKey(table, region string) string {
	return normalizeBackfillScopeValue(table) + "|" + normalizeBackfillScopeValue(region)
}

func normalizeBackfillScopeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func backfillQueueID(accountID, table, region string) string {
	return fmt.Sprintf("aws:%s:%s:%s", strings.TrimSpace(accountID), normalizeBackfillScopeValue(table), normalizeBackfillScopeValue(region))
}

func backfillRequestsFromRows(rows []map[string]interface{}) map[string]string {
	requests := make(map[string]string, len(rows))
	for _, row := range rows {
		tableName := normalizeBackfillScopeValue(queryRowString(row, "table_name"))
		region := normalizeBackfillScopeValue(queryRowString(row, "region"))
		if tableName == "" || region == "" {
			continue
		}
		requests[backfillRequestKey(tableName, region)] = strings.TrimSpace(queryRowString(row, "reason"))
	}
	return requests
}

func hasBackfillRequest(backfills map[string]string, table, region string) bool {
	if len(backfills) == 0 {
		return false
	}
	_, ok := backfills[backfillRequestKey(table, region)]
	return ok
}

func (e *SyncEngine) loadBackfillRequests(ctx context.Context) map[string]string {
	if err := e.ensureBackfillQueueTable(ctx); err != nil {
		e.logger.Warn("failed to initialize backfill queue", "error", err)
		return nil
	}

	result, err := e.sf.Query(ctx,
		"SELECT table_name, region, reason FROM _sync_backfill_queue WHERE provider = ? AND account_id = ?",
		"aws",
		e.accountID,
	)
	if err != nil {
		e.logger.Warn("failed to load backfill requests", "error", err)
		return nil
	}

	return backfillRequestsFromRows(result.Rows)
}

func (e *SyncEngine) recordBackfillRequest(ctx context.Context, table, region, reason string) error {
	table = normalizeBackfillScopeValue(table)
	region = normalizeBackfillScopeValue(region)
	reason = strings.TrimSpace(reason)
	if table == "" || region == "" {
		return fmt.Errorf("invalid backfill scope: table=%q region=%q", table, region)
	}

	if err := e.ensureBackfillQueueTable(ctx); err != nil {
		return err
	}

	id := backfillQueueID(e.accountID, table, region)
	mergeQuery := `MERGE INTO _sync_backfill_queue t
		USING (SELECT ? AS id, ? AS provider, ? AS table_name, ? AS region, ? AS account_id, ? AS reason, CURRENT_TIMESTAMP() AS requested_at) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			reason = s.reason,
			requested_at = s.requested_at,
			_cq_sync_time = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (id, provider, table_name, region, account_id, reason, requested_at)
		VALUES (s.id, s.provider, s.table_name, s.region, s.account_id, s.reason, s.requested_at)`

	if _, err := e.sf.Exec(ctx, mergeQuery, id, "aws", table, region, e.accountID, reason); err != nil {
		return fmt.Errorf("upsert backfill request: %w", err)
	}

	return nil
}

func (e *SyncEngine) clearBackfillRequest(ctx context.Context, table, region string) error {
	table = normalizeBackfillScopeValue(table)
	region = normalizeBackfillScopeValue(region)
	if table == "" || region == "" {
		return fmt.Errorf("invalid backfill scope: table=%q region=%q", table, region)
	}

	if err := e.ensureBackfillQueueTable(ctx); err != nil {
		return err
	}

	id := backfillQueueID(e.accountID, table, region)
	_, err := e.sf.Exec(ctx, "DELETE FROM _sync_backfill_queue WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete backfill request: %w", err)
	}
	return nil
}

func (e *SyncEngine) getAccountID(ctx context.Context, cfg aws.Config) string {
	if e.accountID != "" {
		return e.accountID
	}
	stsClient := sts.NewFromConfig(cfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil && out.Account != nil {
		e.accountID = *out.Account
	}
	return e.accountID
}

// hashRowContent creates a consistent hash of row content
func hashRowContent(row map[string]interface{}) string {
	return hashRowContentWithMode(row, true)
}
