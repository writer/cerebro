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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// SyncEngine orchestrates cloud resource syncing
type SyncEngine struct {
	sf          *snowflake.Client
	logger      *slog.Logger
	concurrency int
	regions     []string
	accountID   string
}

// EngineOption configures the sync engine
type EngineOption func(*SyncEngine)

func WithConcurrency(n int) EngineOption {
	return func(e *SyncEngine) { e.concurrency = n }
}

func WithRegions(regions []string) EngineOption {
	return func(e *SyncEngine) { e.regions = regions }
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
		concurrency: 10,
		regions:     []string{"us-east-1"}, // default to single region, use WithRegions(DefaultAWSRegions) for multi-region
	}
	for _, opt := range opts {
		opt(e)
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

	// Get account ID
	e.accountID = e.getAccountID(ctx, cfg)

	// Define all tables to sync
	tables := e.getAWSTables()

	// Create work queue
	type workItem struct {
		table  TableSpec
		region string
	}

	var work []workItem
	for _, table := range tables {
		for _, region := range e.regions {
			work = append(work, workItem{table: table, region: region})
		}
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

	for i, w := range work {
		idx := i
		item := w
		group.Go(func() error {
			result, err := e.syncTable(ctx, cfg, item.table, item.region)
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

func (e *SyncEngine) syncTable(ctx context.Context, cfg aws.Config, table TableSpec, region string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: region,
	}

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Duration = time.Since(start)
		return result, fmt.Errorf("invalid table name %s: %w", table.Name, err)
	}

	// Create regional config
	regionalCfg := cfg.Copy()
	regionalCfg.Region = region

	// Ensure table exists with correct schema
	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result, fmt.Errorf("ensure table %s: %w", table.Name, err)
	}

	// Fetch resources
	rows, err := table.Fetch(ctx, regionalCfg, region)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "region", region, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result, fmt.Errorf("fetch %s: %w", table.Name, err)
	}

	// Upsert with change detection
	changes, err := e.upsertWithChanges(ctx, table.Name, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result, fmt.Errorf("upsert %s: %w", table.Name, err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("sync complete with changes",
			"table", table.Name,
			"region", region,
			"synced", result.Synced,
			"changes", changes.Summary())
	}

	return result, nil
}

func (e *SyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	for _, col := range columns {
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}

	// Create table if not exists
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

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	// Add missing columns
	existingCols, err := e.getTableColumns(ctx, table)
	if err != nil {
		return nil // table might not exist yet
	}

	existingSet := make(map[string]bool)
	for _, col := range existingCols {
		existingSet[strings.ToUpper(col)] = true
	}

	// Add _CQ_HASH if missing
	if !existingSet["_CQ_HASH"] {
		if _, err := e.sf.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN _CQ_HASH VARCHAR", table)); err != nil {
			e.logger.Debug("failed to add _CQ_HASH column", "error", err)
		}
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

func (e *SyncEngine) getTableColumns(ctx context.Context, table string) ([]string, error) {
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
		if col, ok := row["COLUMN_NAME"].(string); ok {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func (e *SyncEngine) upsertWithChanges(ctx context.Context, table string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	if len(rows) == 0 {
		return changes, nil
	}

	// Get existing rows with their hashes
	existing := e.getExistingHashes(ctx, table)

	// Build new row map with hashes
	newRows := make(map[string]string) // id -> hash
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := hashRowContent(row)
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

	// Delete and insert (simple strategy, could use MERGE for large tables)
	if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
		e.logger.Debug("delete failed", "error", err)
	}

	// Batch insert
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := hashRowContent(row)
		delete(row, "_cq_id")

		cols := []string{"_CQ_ID", "_CQ_HASH"}
		selects := []string{"?", "?"}
		args := []interface{}{id, hash}

		for k, v := range row {
			cols = append(cols, strings.ToUpper(k))
			jsonVal, _ := json.Marshal(v)
			selects = append(selects, "PARSE_JSON(?)")
			args = append(args, string(jsonVal))
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s",
			table, strings.Join(cols, ", "), strings.Join(selects, ", "))

		if _, err := e.sf.Exec(ctx, query, args...); err != nil {
			return changes, fmt.Errorf("insert row: %w", err)
		}
	}

	return changes, nil
}

func (e *SyncEngine) getExistingHashes(ctx context.Context, table string) map[string]string {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result
	}

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

func (e *SyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	// Create change history table if not exists
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
		id VARCHAR PRIMARY KEY,
		table_name VARCHAR,
		resource_id VARCHAR,
		operation VARCHAR,
		region VARCHAR,
		account_id VARCHAR,
		timestamp TIMESTAMP_TZ,
		_cq_sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create change history table: %w", err)
	}

	// Insert changes
	now := time.Now().UTC()
	for _, r := range results {
		if r.Changes == nil {
			continue
		}

		for _, id := range r.Changes.Added {
			e.insertChangeRecord(ctx, r.Table, id, "add", r.Region, now)
		}
		for _, id := range r.Changes.Modified {
			e.insertChangeRecord(ctx, r.Table, id, "modify", r.Region, now)
		}
		for _, id := range r.Changes.Removed {
			e.insertChangeRecord(ctx, r.Table, id, "remove", r.Region, now)
		}
	}

	return nil
}

func (e *SyncEngine) insertChangeRecord(ctx context.Context, table, resourceID, op, region string, ts time.Time) {
	id := fmt.Sprintf("%s-%s-%s-%d", table, resourceID, op, ts.UnixNano())
	query := `INSERT INTO _sync_change_history (id, table_name, resource_id, operation, region, account_id, timestamp)
		SELECT ?, ?, ?, ?, ?, ?, ?`

	if _, err := e.sf.Exec(ctx, query, id, table, resourceID, op, region, e.accountID, ts); err != nil {
		e.logger.Debug("failed to insert change record", "error", err)
	}
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
	// Sort keys for consistent ordering
	keys := make([]string, 0, len(row))
	for k := range row {
		if k != "_cq_id" && k != "_cq_hash" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// Build deterministic JSON
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := json.Marshal(row[k])
		parts = append(parts, fmt.Sprintf("%q:%s", k, string(v)))
	}

	data := "{" + strings.Join(parts, ",") + "}"
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // first 8 bytes = 16 hex chars
}
