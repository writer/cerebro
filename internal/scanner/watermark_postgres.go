package scanner

import (
	"context"
	"database/sql"
	"fmt"
)

// PostgresWatermarkStore manages scan watermarks persisted to PostgreSQL.
type PostgresWatermarkStore struct {
	WatermarkStore
}

// NewPostgresWatermarkStore creates a watermark store backed by Postgres.
func NewPostgresWatermarkStore(db *sql.DB) *PostgresWatermarkStore {
	return &PostgresWatermarkStore{
		WatermarkStore: WatermarkStore{
			watermarks: make(map[string]*ScanWatermark),
			db:         db,
		},
	}
}

// ensurePostgresWatermarkTable creates the watermarks table if needed.
func (s *PostgresWatermarkStore) ensurePostgresWatermarkTable(ctx context.Context) error {
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
			table_name TEXT PRIMARY KEY,
			last_scan_time TIMESTAMP,
			last_scan_id TEXT,
			rows_scanned BIGINT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("create watermarks table: %w", err)
	}

	s.schemaReady = true
	return nil
}

// PersistWatermarks saves watermarks to Postgres.
func (s *PostgresWatermarkStore) PersistWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	if err := s.ensurePostgresWatermarkTable(ctx); err != nil {
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin watermarks transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const upsert = `
		INSERT INTO cerebro_scan_watermarks (table_name, last_scan_time, last_scan_id, rows_scanned)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (table_name) DO UPDATE SET
			last_scan_time = EXCLUDED.last_scan_time,
			last_scan_id = EXCLUDED.last_scan_id,
			rows_scanned = EXCLUDED.rows_scanned,
			updated_at = CURRENT_TIMESTAMP
	`
	stmt, err := tx.PrepareContext(ctx, upsert)
	if err != nil {
		return fmt.Errorf("prepare watermarks upsert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, wm := range watermarks {
		if _, err := stmt.ExecContext(ctx, wm.Table, wm.LastScanTime, wm.LastScanID, wm.RowsScanned); err != nil {
			return fmt.Errorf("upsert watermarks: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit watermarks transaction: %w", err)
	}

	return nil
}

// LoadWatermarks loads watermarks from Postgres.
func (s *PostgresWatermarkStore) LoadWatermarks(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	if err := s.ensurePostgresWatermarkTable(ctx); err != nil {
		return err
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
