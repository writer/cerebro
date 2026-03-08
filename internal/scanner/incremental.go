package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
)

// ScanWatermark tracks the last scan time for each table
type ScanWatermark struct {
	Table        string    `json:"table"`
	LastScanTime time.Time `json:"last_scan_time"`
	LastScanID   string    `json:"last_scan_id"`
	RowsScanned  int64     `json:"rows_scanned"`
}

// WatermarkStore manages scan watermarks for incremental scanning
type WatermarkStore struct {
	watermarks  map[string]*ScanWatermark
	mu          sync.RWMutex
	db          *sql.DB // Optional Snowflake persistence
	schemaMu    sync.Mutex
	schemaReady bool
}

// NewWatermarkStore creates a new watermark store
func NewWatermarkStore(db *sql.DB) *WatermarkStore {
	return &WatermarkStore{
		watermarks: make(map[string]*ScanWatermark),
		db:         db,
	}
}

// SetDB updates the backing database handle used for watermark persistence.
func (s *WatermarkStore) SetDB(db *sql.DB) {
	s.schemaMu.Lock()
	s.db = db
	s.schemaReady = false
	s.schemaMu.Unlock()
}

// GetWatermark returns the last scan watermark for a table
func (s *WatermarkStore) GetWatermark(table string) *ScanWatermark {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.watermarks[table]
}

// SetWatermark updates the scan watermark for a table
func (s *WatermarkStore) SetWatermark(table string, scanTime time.Time, lastScanID string, rowsScanned int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.watermarks[table] = &ScanWatermark{
		Table:        table,
		LastScanTime: scanTime,
		LastScanID:   lastScanID,
		RowsScanned:  rowsScanned,
	}
}

// GetIncrementalQuery returns a SQL query for incremental scanning
// Uses CloudQuery's _cq_sync_time column to filter new/updated rows
// Returns an error if the table name is invalid (SQL injection protection)
func GetIncrementalQuery(table string, lastScanTime *time.Time, lastScanID string, limit int) (string, error) {
	// Validate table name to prevent SQL injection
	if err := snowflake.ValidateTableName(table); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}
	if limit == 0 {
		limit = 1000
	}
	if lastScanTime == nil {
		// Full scan
		return fmt.Sprintf("SELECT * FROM %s LIMIT %d", table, limit), nil
	}

	// Incremental scan - only rows synced after last scan
	scanTime := formatScanTime(*lastScanTime)
	if lastScanID != "" {
		safeScanID := escapeSQLString(lastScanID)
		return fmt.Sprintf(
			"SELECT * FROM %s WHERE (_cq_sync_time > '%s' OR (_cq_sync_time = '%s' AND _cq_id > '%s')) ORDER BY _cq_sync_time ASC, _cq_id ASC LIMIT %d",
			table,
			scanTime,
			scanTime,
			safeScanID,
			limit,
		), nil
	}

	return fmt.Sprintf(
		"SELECT * FROM %s WHERE _cq_sync_time > '%s' ORDER BY _cq_sync_time ASC, _cq_id ASC LIMIT %d",
		table,
		scanTime,
		limit,
	), nil
}

// IncrementalScanConfig configures incremental scanning behavior
type IncrementalScanConfig struct {
	ForceFullScan  bool          // Ignore watermarks and do full scan
	MaxAge         time.Duration // Max watermark age before forcing full scan (default 7 days)
	BatchSize      int           // Rows per batch (default 1000)
	SkipStaleCheck bool          // Skip checking if data is stale
}

// WatermarkPersistOptions configures watermark persistence retries.
type WatermarkPersistOptions struct {
	Timeout  time.Duration // Timeout for a single persistence attempt
	Attempts int           // Number of attempts before giving up
	Backoff  time.Duration // Base backoff between attempts
}

// DefaultIncrementalConfig returns default incremental scan configuration
func DefaultIncrementalConfig() IncrementalScanConfig {
	return IncrementalScanConfig{
		ForceFullScan:  false,
		MaxAge:         7 * 24 * time.Hour, // 7 days
		BatchSize:      1000,
		SkipStaleCheck: false,
	}
}

// DefaultWatermarkPersistOptions returns retry defaults for watermark persistence.
func DefaultWatermarkPersistOptions() WatermarkPersistOptions {
	return WatermarkPersistOptions{
		Timeout:  2 * time.Minute,
		Attempts: 3,
		Backoff:  2 * time.Second,
	}
}

// ShouldFullScan determines if a full scan is needed based on watermark age
func (s *WatermarkStore) ShouldFullScan(table string, maxAge time.Duration) bool {
	wm := s.GetWatermark(table)
	if wm == nil {
		return true // No watermark, need full scan
	}

	// If watermark is older than maxAge, do full scan
	return time.Since(wm.LastScanTime) > maxAge
}

func (s *WatermarkStore) ensureWatermarkTable(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemaReady {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cerebro_scan_watermarks (
			table_name VARCHAR PRIMARY KEY,
			last_scan_time TIMESTAMP_NTZ,
			last_scan_id VARCHAR,
			rows_scanned NUMBER,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)
	`); err != nil {
		return fmt.Errorf("create watermarks table: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE cerebro_scan_watermarks ADD COLUMN IF NOT EXISTS last_scan_id VARCHAR`); err != nil {
		return fmt.Errorf("ensure last_scan_id column: %w", err)
	}

	s.schemaReady = true
	return nil
}

// PersistWatermarks saves watermarks to Snowflake (if configured)
func (s *WatermarkStore) PersistWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	if err := s.ensureWatermarkTable(ctx); err != nil {
		return err
	}

	s.mu.RLock()
	watermarks := make([]*ScanWatermark, 0, len(s.watermarks))
	for _, wm := range s.watermarks {
		watermarks = append(watermarks, wm)
	}
	s.mu.RUnlock()

	if len(watermarks) == 0 {
		return nil
	}

	const batchSize = 200
	for i := 0; i < len(watermarks); i += batchSize {
		end := i + batchSize
		if end > len(watermarks) {
			end = len(watermarks)
		}
		batch := watermarks[i:end]
		values := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*4)
		for _, wm := range batch {
			values = append(values, "(?, ?, ?, ?)")
			args = append(args, wm.Table, wm.LastScanTime, wm.LastScanID, wm.RowsScanned)
		}
		// #nosec G202 -- target table is static and VALUES placeholders are generated internally.
		merge := `
			MERGE INTO cerebro_scan_watermarks t
			USING (SELECT column1 AS table_name,
			              column2 AS last_scan_time,
			              column3 AS last_scan_id,
			              column4 AS rows_scanned
			       FROM VALUES ` + strings.Join(values, ",") + `) s
			ON t.table_name = s.table_name
			WHEN MATCHED THEN UPDATE SET
				last_scan_time = s.last_scan_time,
				last_scan_id = s.last_scan_id,
				rows_scanned = s.rows_scanned,
				updated_at = CURRENT_TIMESTAMP()
			WHEN NOT MATCHED THEN INSERT (table_name, last_scan_time, last_scan_id, rows_scanned)
			VALUES (s.table_name, s.last_scan_time, s.last_scan_id, s.rows_scanned)
		`
		if _, err := s.db.ExecContext(ctx, merge, args...); err != nil {
			return fmt.Errorf("upsert watermarks: %w", err)
		}
	}

	return nil
}

// PersistWatermarksWithRetry persists watermarks with retry/backoff and a detached timeout.
func (s *WatermarkStore) PersistWatermarksWithRetry(ctx context.Context, opts WatermarkPersistOptions) error {
	if s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout == 0 || opts.Attempts == 0 || opts.Backoff == 0 {
		defaults := DefaultWatermarkPersistOptions()
		if opts.Timeout == 0 {
			opts.Timeout = defaults.Timeout
		}
		if opts.Attempts == 0 {
			opts.Attempts = defaults.Attempts
		}
		if opts.Backoff == 0 {
			opts.Backoff = defaults.Backoff
		}
	}
	if opts.Attempts < 1 {
		opts.Attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < opts.Attempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attemptCtx, cancel := withDetachedTimeout(ctx, opts.Timeout)
		err := s.PersistWatermarks(attemptCtx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < opts.Attempts-1 {
			if !sleepWithContext(ctx, opts.Backoff*time.Duration(attempt+1)) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return lastErr
			}
		}
	}
	return lastErr
}

// LoadWatermarks loads watermarks from Snowflake (if configured)
func (s *WatermarkStore) LoadWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cerebro_scan_watermarks (
			table_name VARCHAR PRIMARY KEY,
			last_scan_time TIMESTAMP_NTZ,
			last_scan_id VARCHAR,
			rows_scanned NUMBER,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)
	`); err != nil {
		return fmt.Errorf("create watermarks table: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE cerebro_scan_watermarks ADD COLUMN IF NOT EXISTS last_scan_id VARCHAR`); err != nil {
		return fmt.Errorf("ensure last_scan_id column: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT table_name, last_scan_time, last_scan_id, rows_scanned
		FROM cerebro_scan_watermarks
	`)
	if err != nil {
		return fmt.Errorf("query watermarks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var wm ScanWatermark
		if err := rows.Scan(&wm.Table, &wm.LastScanTime, &wm.LastScanID, &wm.RowsScanned); err != nil {
			continue
		}
		s.watermarks[wm.Table] = &wm
	}

	return rows.Err()
}

// IncrementalStats returns statistics about incremental scanning
type IncrementalStats struct {
	TablesWithWatermarks int              `json:"tables_with_watermarks"`
	TotalRowsScanned     int64            `json:"total_rows_scanned"`
	OldestWatermark      *time.Time       `json:"oldest_watermark,omitempty"`
	NewestWatermark      *time.Time       `json:"newest_watermark,omitempty"`
	TableStats           map[string]int64 `json:"table_stats"`
}

// Stats returns incremental scanning statistics
func (s *WatermarkStore) Stats() IncrementalStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := IncrementalStats{
		TablesWithWatermarks: len(s.watermarks),
		TableStats:           make(map[string]int64),
	}

	for _, wm := range s.watermarks {
		stats.TotalRowsScanned += wm.RowsScanned
		stats.TableStats[wm.Table] = wm.RowsScanned

		if stats.OldestWatermark == nil || wm.LastScanTime.Before(*stats.OldestWatermark) {
			stats.OldestWatermark = &wm.LastScanTime
		}
		if stats.NewestWatermark == nil || wm.LastScanTime.After(*stats.NewestWatermark) {
			stats.NewestWatermark = &wm.LastScanTime
		}
	}

	return stats
}

func withDetachedTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		return context.WithCancel(parent) // #nosec G118 -- cancel function is returned to caller for lifecycle management
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout) // #nosec G118 -- cancel function is returned and explicitly called by caller
	go func() {
		select {
		case <-parent.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// ExtractScanCursor returns the latest sync time and ID from a batch of assets.
func ExtractScanCursor(assets []map[string]interface{}) (time.Time, string) {
	var maxTime time.Time
	var maxID string
	for _, asset := range assets {
		syncTime, ok := parseScanTime(asset["_cq_sync_time"])
		if !ok {
			continue
		}
		id := toScanString(asset["_cq_id"])
		if isCursorAfter(syncTime, id, maxTime, maxID) {
			maxTime = syncTime
			maxID = id
		}
	}

	return maxTime, maxID
}

// IsCursorAfter returns true if the new cursor is after the current cursor.
func IsCursorAfter(newTime time.Time, newID string, currentTime time.Time, currentID string) bool {
	return isCursorAfter(newTime, newID, currentTime, currentID)
}

func isCursorAfter(newTime time.Time, newID string, currentTime time.Time, currentID string) bool {
	if currentTime.IsZero() {
		return !newTime.IsZero()
	}
	if newTime.After(currentTime) {
		return true
	}
	if newTime.Equal(currentTime) && newID > currentID {
		return true
	}
	return false
}

func parseScanTime(value interface{}) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err == nil {
			return parsed, true
		}
		parsed, err = time.Parse(time.RFC3339, typed)
		if err == nil {
			return parsed, true
		}
	case []byte:
		return parseScanTime(string(typed))
	}
	return time.Time{}, false
}

func formatScanTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func escapeSQLString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func toScanString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}
