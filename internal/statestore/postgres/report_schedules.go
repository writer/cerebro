package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureReportScheduleStatements = []string{
	`CREATE TABLE IF NOT EXISTS report_schedules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  report_id TEXT NOT NULL,
  parameters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  interval_seconds BIGINT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_run_at TIMESTAMPTZ NOT NULL,
  last_run_at TIMESTAMPTZ,
  claim_owner TEXT NOT NULL DEFAULT '',
  claim_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS claim_owner TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS report_schedules_tenant_idx ON report_schedules (tenant_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS report_schedules_due_idx ON report_schedules (next_run_at) WHERE enabled`,
}

const reportScheduleColumns = `id, tenant_id, report_id, parameters_json::text, interval_seconds, enabled, next_run_at, last_run_at, claim_owner, claim_expires_at, created_at, updated_at`

func (s *Store) ensureReportScheduleTable(ctx context.Context) error {
	return s.ensureReportTables(ctx)
}

// PutReportSchedule upserts one saved report schedule.
func (s *Store) PutReportSchedule(ctx context.Context, schedule *ports.ReportSchedule) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if schedule == nil {
		return errors.New("report schedule is required")
	}
	id := strings.TrimSpace(schedule.ID)
	tenantID := strings.TrimSpace(schedule.TenantID)
	reportID := strings.TrimSpace(schedule.ReportID)
	if id == "" || tenantID == "" || reportID == "" {
		return errors.New("report schedule id, tenant_id, and report_id are required")
	}
	if schedule.IntervalSeconds <= 0 {
		return errors.New("report schedule interval must be positive")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return err
	}
	parameters, err := json.Marshal(sanitizedStringMap(schedule.Parameters))
	if err != nil {
		return fmt.Errorf("marshal report schedule parameters: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO report_schedules (id, tenant_id, report_id, parameters_json, interval_seconds, enabled, next_run_at, last_run_at)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  report_id = EXCLUDED.report_id,
  parameters_json = EXCLUDED.parameters_json,
  interval_seconds = EXCLUDED.interval_seconds,
  enabled = EXCLUDED.enabled,
  next_run_at = EXCLUDED.next_run_at,
  last_run_at = EXCLUDED.last_run_at,
  claim_owner = '',
  claim_expires_at = NULL,
  updated_at = NOW()`,
		id, tenantID, reportID, string(parameters), schedule.IntervalSeconds, schedule.Enabled,
		schedule.NextRunAt.UTC(), nullableTime(schedule.LastRunAt)); err != nil {
		return fmt.Errorf("upsert report schedule %q: %w", id, err)
	}
	return nil
}

// GetReportSchedule loads one saved report schedule.
func (s *Store) GetReportSchedule(ctx context.Context, scheduleID string) (*ports.ReportSchedule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(scheduleID)
	if id == "" {
		return nil, errors.New("report schedule id is required")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is a fixed constant and the id remains parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM report_schedules WHERE id = $1", reportScheduleColumns), id)
	schedule, err := scanReportSchedule(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrReportScheduleNotFound, id)
		}
		return nil, fmt.Errorf("query report schedule %q: %w", id, err)
	}
	return schedule, nil
}

// ListReportSchedules returns saved schedules for one tenant, newest-first.
func (s *Store) ListReportSchedules(ctx context.Context, filter ports.ReportScheduleFilter) ([]*ports.ReportSchedule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{}
	args := []any{}
	if tenantID := strings.TrimSpace(filter.TenantID); tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("tenant_id = $%d", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, reportScheduleListLimit(filter.Limit))
	// #nosec G201 -- column list and clauses are fixed predicates; all values remain parameterized.
	query := fmt.Sprintf("SELECT %s FROM report_schedules %s ORDER BY created_at DESC LIMIT $%d", reportScheduleColumns, where, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list report schedules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	schedules := []*ports.ReportSchedule{}
	for rows.Next() {
		schedule, err := scanReportSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

// DeleteReportSchedule removes one saved schedule.
func (s *Store) DeleteReportSchedule(ctx context.Context, scheduleID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(scheduleID)
	if id == "" {
		return errors.New("report schedule id is required")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM report_schedules WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete report schedule %q: %w", id, err)
	}
	return nil
}

// ClaimDueReportSchedules atomically claims enabled schedules whose next run is
// due, advancing each one full interval ahead so a single pass enqueues each due
// schedule exactly once even across concurrent server replicas.
func (s *Store) ClaimDueReportSchedules(ctx context.Context, now time.Time, owner string, ttl time.Duration, limit uint32) ([]*ports.ReportSchedule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = reportScheduleClaimLimit
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, errors.New("report schedule claim owner is required")
	}
	if ttl <= 0 {
		return nil, errors.New("report schedule claim ttl must be positive")
	}
	now = now.UTC()
	// #nosec G201 -- column list is a fixed constant and all values remain parameterized.
	query := fmt.Sprintf(`
UPDATE report_schedules
SET claim_owner = $3,
    claim_expires_at = $1::timestamptz + $4::bigint * INTERVAL '1 millisecond',
    updated_at = NOW()
WHERE id IN (
  SELECT id FROM report_schedules
  WHERE enabled
    AND next_run_at <= $1::timestamptz
    AND (claim_expires_at IS NULL OR claim_expires_at <= $1::timestamptz)
  ORDER BY next_run_at
  LIMIT $2
  FOR UPDATE SKIP LOCKED
)
RETURNING %s`, reportScheduleColumns)
	rows, err := s.db.QueryContext(ctx, query, now, limit, owner, ttl.Milliseconds())
	if err != nil {
		return nil, fmt.Errorf("claim due report schedules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	schedules := []*ports.ReportSchedule{}
	for rows.Next() {
		schedule, err := scanReportSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

// CompleteReportScheduleClaim advances a schedule only after its occurrence job
// has been durably created. The owner and occurrence prevent a stale worker from
// acknowledging a newer claim.
func (s *Store) CompleteReportScheduleClaim(ctx context.Context, scheduleID string, owner string, occurrenceAt time.Time, completedAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	scheduleID = strings.TrimSpace(scheduleID)
	owner = strings.TrimSpace(owner)
	if scheduleID == "" || owner == "" || occurrenceAt.IsZero() || completedAt.IsZero() {
		return errors.New("report schedule id, claim owner, occurrence, and completion time are required")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE report_schedules
SET next_run_at = $4::timestamptz + make_interval(secs => interval_seconds),
    last_run_at = $3::timestamptz,
    claim_owner = '',
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE id = $1
  AND claim_owner = $2
  AND next_run_at = $3::timestamptz`, scheduleID, owner, occurrenceAt.UTC(), completedAt.UTC())
	if err != nil {
		return fmt.Errorf("complete report schedule claim %q: %w", scheduleID, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("report schedule claim conflict: %s", scheduleID)
	}
	return nil
}

// ReleaseReportScheduleClaim makes a failed enqueue eligible for the next poll.
func (s *Store) ReleaseReportScheduleClaim(ctx context.Context, scheduleID string, owner string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	scheduleID = strings.TrimSpace(scheduleID)
	owner = strings.TrimSpace(owner)
	if scheduleID == "" || owner == "" {
		return errors.New("report schedule id and claim owner are required")
	}
	if err := s.ensureReportScheduleTable(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE report_schedules
SET claim_owner = '', claim_expires_at = NULL, updated_at = NOW()
WHERE id = $1 AND claim_owner = $2`, scheduleID, owner)
	if err != nil {
		return fmt.Errorf("release report schedule claim %q: %w", scheduleID, err)
	}
	return nil
}

const reportScheduleClaimLimit uint32 = 50

func reportScheduleListLimit(limit uint32) uint32 {
	const (
		defaultLimit uint32 = 100
		maxLimit     uint32 = 500
	)
	switch {
	case limit == 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	default:
		return limit
	}
}

func scanReportSchedule(row scanner) (*ports.ReportSchedule, error) {
	var (
		schedule       ports.ReportSchedule
		parametersText string
		lastRunAt      sql.NullTime
		claimExpiresAt sql.NullTime
	)
	if err := row.Scan(
		&schedule.ID,
		&schedule.TenantID,
		&schedule.ReportID,
		&parametersText,
		&schedule.IntervalSeconds,
		&schedule.Enabled,
		&schedule.NextRunAt,
		&lastRunAt,
		&schedule.ClaimOwner,
		&claimExpiresAt,
		&schedule.CreatedAt,
		&schedule.UpdatedAt,
	); err != nil {
		return nil, err
	}
	parameters := map[string]string{}
	if strings.TrimSpace(parametersText) != "" {
		if err := json.Unmarshal([]byte(parametersText), &parameters); err != nil {
			return nil, fmt.Errorf("decode report schedule parameters: %w", err)
		}
	}
	schedule.Parameters = parameters
	if lastRunAt.Valid {
		schedule.LastRunAt = lastRunAt.Time
	}
	if claimExpiresAt.Valid {
		schedule.ClaimExpiresAt = claimExpiresAt.Time
	}
	return &schedule, nil
}
