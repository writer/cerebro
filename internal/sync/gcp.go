package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// GCPSyncEngine orchestrates GCP resource syncing
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

// SyncAll syncs all GCP resources
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
	return results, nil
}

func (e *GCPSyncEngine) syncTable(ctx context.Context, table GCPTableSpec) SyncResult {
	start := time.Now()
	result := SyncResult{
		Table: table.Name,
	}

	if err := e.ensureGCPTable(ctx, table.Name, table.Columns); err != nil {
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

	if err := e.upsertGCPRows(ctx, table.Name, rows); err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	result.Synced = len(rows)
	result.Duration = time.Since(start)
	
	e.logger.Info("synced", "table", table.Name, "count", result.Synced)
	return result
}

func (e *GCPSyncEngine) ensureGCPTable(ctx context.Context, table string, columns []string) error {
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s VARIANT", col)
	}

	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		_CQ_HASH VARCHAR,
		%s
	)`, table, joinStrings(colDefs, ", "))

	_, err := e.sf.Query(ctx, createQuery)
	return err
}

func (e *GCPSyncEngine) upsertGCPRows(ctx context.Context, table string, rows []map[string]interface{}) error {
	for _, row := range rows {
		if err := e.upsertGCPRow(ctx, table, row); err != nil {
			return err
		}
	}
	return nil
}

func (e *GCPSyncEngine) upsertGCPRow(ctx context.Context, table string, row map[string]interface{}) error {
	id, ok := row["_cq_id"].(string)
	if !ok || id == "" {
		return fmt.Errorf("row missing _cq_id")
	}

	delete(row, "_cq_id")

	// Build column list and values
	cols := []string{"_CQ_ID"}
	selects := []string{fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''"))}
	
	for col, val := range row {
		cols = append(cols, strings.ToUpper(col))
		jsonVal, _ := json.Marshal(val)
		escaped := strings.ReplaceAll(string(jsonVal), "'", "''")
		selects = append(selects, fmt.Sprintf("PARSE_JSON('%s')", escaped))
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s",
		table, joinStrings(cols, ", "), joinStrings(selects, ", "))

	_, err := e.sf.Query(ctx, query)
	return err
}

func buildSelectList(cols, vals []string) string {
	var parts []string
	for i, col := range cols {
		parts = append(parts, fmt.Sprintf("%s AS %s", vals[i], col))
	}
	return joinStrings(parts, ", ")
}

func buildUpdateList(cols []string) string {
	var parts []string
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("t.%s = s.%s", col, col))
	}
	return joinStrings(parts, ", ")
}

func buildInsertValues(cols []string) string {
	var parts []string
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("s.%s", col))
	}
	return joinStrings(parts, ", ")
}

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += sep + s[i]
	}
	return result
}

// getGCPTables returns all GCP table definitions
func (e *GCPSyncEngine) getGCPTables() []GCPTableSpec {
	return []GCPTableSpec{
		// Compute
		e.gcpComputeInstanceTable(),
		// Storage
		e.gcpStorageBucketTable(),
		// IAM
		e.gcpIAMServiceAccountTable(),
	}
}
