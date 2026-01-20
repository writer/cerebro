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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

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

	// Process in parallel with semaphore
	results := make([]SyncResult, len(work))
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.concurrency)

	for i, w := range work {
		wg.Add(1)
		go func(idx int, item workItem) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			result := e.syncTable(ctx, cfg, item.table, item.region)
			results[idx] = result
		}(i, w)
	}

	wg.Wait()

	// Persist change history
	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, nil
}

func (e *SyncEngine) syncTable(ctx context.Context, cfg aws.Config, table TableSpec, region string) SyncResult {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: region,
	}

	// Create regional config
	regionalCfg := cfg.Copy()
	regionalCfg.Region = region

	// Ensure table exists with correct schema
	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	// Fetch resources
	rows, err := table.Fetch(ctx, regionalCfg, region)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "region", region, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	// Upsert with change detection
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
		e.logger.Info("sync complete with changes",
			"table", table.Name,
			"region", region,
			"synced", result.Synced,
			"changes", changes.Summary())
	}

	return result
}

func (e *SyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
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

func (e *SyncEngine) upsertWithChanges(ctx context.Context, table string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}

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
		selects := []string{
			fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''")),
			fmt.Sprintf("'%s'", hash),
		}

		for k, v := range row {
			cols = append(cols, strings.ToUpper(k))
			jsonVal, _ := json.Marshal(v)
			escaped := strings.ReplaceAll(string(jsonVal), "'", "''")
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

func (e *SyncEngine) getExistingHashes(ctx context.Context, table string) map[string]string {
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
	query := fmt.Sprintf(`INSERT INTO _sync_change_history (id, table_name, resource_id, operation, region, account_id, timestamp)
		SELECT '%s', '%s', '%s', '%s', '%s', '%s', '%s'`,
		strings.ReplaceAll(id, "'", "''"),
		table,
		strings.ReplaceAll(resourceID, "'", "''"),
		op,
		region,
		e.accountID,
		ts.Format(time.RFC3339))

	if _, err := e.sf.Exec(ctx, query); err != nil {
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
