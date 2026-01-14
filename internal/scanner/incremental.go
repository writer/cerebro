package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// ScanWatermark tracks the last scan time for each table
type ScanWatermark struct {
	Table        string    `json:"table"`
	LastScanTime time.Time `json:"last_scan_time"`
	RowsScanned  int64     `json:"rows_scanned"`
}

// WatermarkStore manages scan watermarks for incremental scanning
type WatermarkStore struct {
	watermarks map[string]*ScanWatermark
	mu         sync.RWMutex
	db         *sql.DB // Optional Snowflake persistence
}

// NewWatermarkStore creates a new watermark store
func NewWatermarkStore(db *sql.DB) *WatermarkStore {
	return &WatermarkStore{
		watermarks: make(map[string]*ScanWatermark),
		db:         db,
	}
}

// GetWatermark returns the last scan watermark for a table
func (s *WatermarkStore) GetWatermark(table string) *ScanWatermark {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.watermarks[table]
}

// SetWatermark updates the scan watermark for a table
func (s *WatermarkStore) SetWatermark(table string, scanTime time.Time, rowsScanned int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.watermarks[table] = &ScanWatermark{
		Table:        table,
		LastScanTime: scanTime,
		RowsScanned:  rowsScanned,
	}
}

// GetIncrementalQuery returns a SQL query for incremental scanning
// Uses CloudQuery's _cq_sync_time column to filter new/updated rows
func GetIncrementalQuery(table string, lastScanTime *time.Time, limit int) string {
	if lastScanTime == nil {
		// Full scan
		return fmt.Sprintf("SELECT * FROM %s LIMIT %d", table, limit)
	}

	// Incremental scan - only rows synced after last scan
	return fmt.Sprintf(
		"SELECT * FROM %s WHERE _cq_sync_time > '%s' LIMIT %d",
		table,
		lastScanTime.Format(time.RFC3339),
		limit,
	)
}

// IncrementalScanConfig configures incremental scanning behavior
type IncrementalScanConfig struct {
	ForceFullScan  bool          // Ignore watermarks and do full scan
	MaxAge         time.Duration // Max watermark age before forcing full scan (default 7 days)
	BatchSize      int           // Rows per batch (default 1000)
	SkipStaleCheck bool          // Skip checking if data is stale
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

// ShouldFullScan determines if a full scan is needed based on watermark age
func (s *WatermarkStore) ShouldFullScan(table string, maxAge time.Duration) bool {
	wm := s.GetWatermark(table)
	if wm == nil {
		return true // No watermark, need full scan
	}

	// If watermark is older than maxAge, do full scan
	return time.Since(wm.LastScanTime) > maxAge
}

// PersistWatermarks saves watermarks to Snowflake (if configured)
func (s *WatermarkStore) PersistWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create watermarks table if needed
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cerebro_scan_watermarks (
			table_name VARCHAR PRIMARY KEY,
			last_scan_time TIMESTAMP_NTZ,
			rows_scanned NUMBER,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)
	`)
	if err != nil {
		return fmt.Errorf("create watermarks table: %w", err)
	}

	// Upsert each watermark
	for _, wm := range s.watermarks {
		_, err := s.db.ExecContext(ctx, `
			MERGE INTO cerebro_scan_watermarks t
			USING (SELECT ? AS table_name, ? AS last_scan_time, ? AS rows_scanned) s
			ON t.table_name = s.table_name
			WHEN MATCHED THEN UPDATE SET 
				last_scan_time = s.last_scan_time,
				rows_scanned = s.rows_scanned,
				updated_at = CURRENT_TIMESTAMP()
			WHEN NOT MATCHED THEN INSERT (table_name, last_scan_time, rows_scanned)
				VALUES (s.table_name, s.last_scan_time, s.rows_scanned)
		`, wm.Table, wm.LastScanTime, wm.RowsScanned)
		if err != nil {
			return fmt.Errorf("upsert watermark %s: %w", wm.Table, err)
		}
	}

	return nil
}

// LoadWatermarks loads watermarks from Snowflake (if configured)
func (s *WatermarkStore) LoadWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT table_name, last_scan_time, rows_scanned 
		FROM cerebro_scan_watermarks
	`)
	if err != nil {
		return fmt.Errorf("query watermarks: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var wm ScanWatermark
		if err := rows.Scan(&wm.Table, &wm.LastScanTime, &wm.RowsScanned); err != nil {
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
