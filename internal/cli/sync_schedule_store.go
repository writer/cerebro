package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type scheduleStore interface {
	EnsureSchema(ctx context.Context) error
	List(ctx context.Context) ([]SyncSchedule, error)
	Get(ctx context.Context, name string) (*SyncSchedule, error)
	Save(ctx context.Context, schedule *SyncSchedule) error
	Delete(ctx context.Context, name string) error
	Close() error
}

type scheduleSQLStore struct {
	db         *sql.DB
	rewriteSQL func(string) string
}

func openScheduleStore() (scheduleStore, error) {
	databaseURL := strings.TrimSpace(os.Getenv("JOB_DATABASE_URL"))
	if databaseURL == "" {
		return nil, fmt.Errorf("JOB_DATABASE_URL is required")
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open schedule database: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping schedule database: %w", err)
	}

	return &scheduleSQLStore{db: db}, nil
}

func (s *scheduleSQLStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *scheduleSQLStore) q(query string) string {
	if s != nil && s.rewriteSQL != nil {
		return s.rewriteSQL(query)
	}
	return query
}

func (s *scheduleSQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("schedule database is not available")
	}
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS sync_schedules (
	name TEXT PRIMARY KEY,
	cron TEXT NOT NULL,
	provider TEXT NOT NULL,
	table_filter TEXT NOT NULL DEFAULT '',
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	scan_after BOOLEAN NOT NULL DEFAULT FALSE,
	retry INTEGER NOT NULL DEFAULT 3,
	created_at BIGINT NOT NULL DEFAULT 0,
	updated_at BIGINT NOT NULL DEFAULT 0,
	last_run BIGINT NOT NULL DEFAULT 0,
	last_status TEXT NOT NULL DEFAULT '',
	next_run BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sync_schedules_enabled_next_run ON sync_schedules (enabled, next_run, name);
`)
	return err
}

func (s *scheduleSQLStore) List(ctx context.Context) ([]SyncSchedule, error) {
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT name, cron, provider, table_filter, enabled, scan_after, retry, created_at, updated_at, last_run, last_status, next_run
FROM sync_schedules
ORDER BY name
`))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	schedules := make([]SyncSchedule, 0)
	for rows.Next() {
		schedule, err := scanStoredSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, *schedule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return schedules, nil
}

func (s *scheduleSQLStore) Get(ctx context.Context, name string) (*SyncSchedule, error) {
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, s.q(`
SELECT name, cron, provider, table_filter, enabled, scan_after, retry, created_at, updated_at, last_run, last_status, next_run
FROM sync_schedules
WHERE name = $1
`), name)
	schedule, err := scanStoredSchedule(row)
	if err == nil {
		return schedule, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return nil, err
}

func (s *scheduleSQLStore) Save(ctx context.Context, schedule *SyncSchedule) error {
	if schedule == nil {
		return fmt.Errorf("schedule is required")
	}
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	normalized := *schedule
	now := time.Now().UTC()
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = now
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	}

	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO sync_schedules (
	name, cron, provider, table_filter, enabled, scan_after, retry, created_at, updated_at, last_run, last_status, next_run
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (name) DO UPDATE SET
	cron = EXCLUDED.cron,
	provider = EXCLUDED.provider,
	table_filter = EXCLUDED.table_filter,
	enabled = EXCLUDED.enabled,
	scan_after = EXCLUDED.scan_after,
	retry = EXCLUDED.retry,
	updated_at = EXCLUDED.updated_at,
	last_run = EXCLUDED.last_run,
	last_status = EXCLUDED.last_status,
	next_run = EXCLUDED.next_run
`),
		normalized.Name,
		normalized.Cron,
		normalized.Provider,
		normalized.Table,
		normalized.Enabled,
		normalized.ScanAfter,
		normalized.Retry,
		scheduleTimeToUnix(normalized.CreatedAt),
		scheduleTimeToUnix(normalized.UpdatedAt),
		scheduleTimeToUnix(normalized.LastRun),
		normalized.LastStatus,
		scheduleTimeToUnix(normalized.NextRun),
	)
	return err
}

func (s *scheduleSQLStore) Delete(ctx context.Context, name string) error {
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM sync_schedules WHERE name = $1`), name)
	return err
}

func scanStoredSchedule(sc interface{ Scan(dest ...any) error }) (*SyncSchedule, error) {
	var (
		schedule      SyncSchedule
		createdAtUnix int64
		updatedAtUnix int64
		lastRunUnix   int64
		nextRunUnix   int64
		lastStatus    string
		tableFilter   string
	)
	if err := sc.Scan(
		&schedule.Name,
		&schedule.Cron,
		&schedule.Provider,
		&tableFilter,
		&schedule.Enabled,
		&schedule.ScanAfter,
		&schedule.Retry,
		&createdAtUnix,
		&updatedAtUnix,
		&lastRunUnix,
		&lastStatus,
		&nextRunUnix,
	); err != nil {
		return nil, err
	}
	schedule.Table = tableFilter
	schedule.CreatedAt = scheduleTimeFromUnix(createdAtUnix)
	schedule.UpdatedAt = scheduleTimeFromUnix(updatedAtUnix)
	schedule.LastRun = scheduleTimeFromUnix(lastRunUnix)
	schedule.LastStatus = lastStatus
	schedule.NextRun = scheduleTimeFromUnix(nextRunUnix)
	return &schedule, nil
}

func scheduleTimeToUnix(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}

func scheduleTimeFromUnix(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}
