package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureComplianceMonitorStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_monitors (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  plan_revision_id TEXT NOT NULL,
  trigger_kind TEXT NOT NULL,
  interval_seconds BIGINT NOT NULL,
  expected_coverage TEXT NOT NULL DEFAULT '',
  maximum_evidence_age_seconds BIGINT NOT NULL DEFAULT 0,
  grace_period_seconds BIGINT NOT NULL DEFAULT 0,
  escalation_owner TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  aggregate_version BIGINT NOT NULL DEFAULT 1,
  next_run_at TIMESTAMPTZ NOT NULL,
  last_success_at TIMESTAMPTZ,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  claim_owner TEXT NOT NULL DEFAULT '',
  claim_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_monitors_due_idx ON compliance_monitors (next_run_at) WHERE enabled`,
	`CREATE INDEX IF NOT EXISTS compliance_monitors_plan_idx ON compliance_monitors (tenant_id, plan_revision_id)`,
	`CREATE TABLE IF NOT EXISTS compliance_plan_run_leases (
  tenant_id TEXT NOT NULL,
  plan_revision_id TEXT NOT NULL,
  lease_owner TEXT NOT NULL,
  occurrence_key TEXT NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, plan_revision_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_plan_run_leases_expiry_idx ON compliance_plan_run_leases (lease_expires_at)`,
}

const complianceMonitorColumns = `tenant_id, id, program_id, plan_revision_id, trigger_kind, interval_seconds, expected_coverage, maximum_evidence_age_seconds, grace_period_seconds, escalation_owner, enabled, aggregate_version, next_run_at, last_success_at, consecutive_failures, claim_owner, claim_expires_at, created_at, updated_at`

func (s *Store) ensureComplianceMonitorTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceMonitor, "compliance_monitors", ensureComplianceMonitorStatements)
}

func (s *Store) PutComplianceMonitor(ctx context.Context, monitor *ports.ComplianceMonitor, expectedVersion uint64) (*ports.ComplianceMonitor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := validateComplianceMonitor(monitor); err != nil {
		return nil, err
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return nil, err
	}
	version := monitor.Version
	if version == 0 {
		version = 1
	}
	// #nosec G201 -- the column list is fixed and values remain parameterized.
	query := fmt.Sprintf(`
INSERT INTO compliance_monitors (
  tenant_id, id, program_id, plan_revision_id, trigger_kind, interval_seconds,
  expected_coverage, maximum_evidence_age_seconds, grace_period_seconds,
  escalation_owner, enabled, aggregate_version, next_run_at
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  program_id = EXCLUDED.program_id,
  plan_revision_id = EXCLUDED.plan_revision_id,
  trigger_kind = EXCLUDED.trigger_kind,
  interval_seconds = EXCLUDED.interval_seconds,
  expected_coverage = EXCLUDED.expected_coverage,
  maximum_evidence_age_seconds = EXCLUDED.maximum_evidence_age_seconds,
  grace_period_seconds = EXCLUDED.grace_period_seconds,
  escalation_owner = EXCLUDED.escalation_owner,
  enabled = EXCLUDED.enabled,
  aggregate_version = compliance_monitors.aggregate_version + 1,
  next_run_at = EXCLUDED.next_run_at,
  claim_owner = '',
  claim_expires_at = NULL,
  updated_at = NOW()
WHERE compliance_monitors.aggregate_version = $14
RETURNING %s`, complianceMonitorColumns)
	row := s.db.QueryRowContext(ctx, query,
		strings.TrimSpace(monitor.TenantID), strings.TrimSpace(monitor.ID), strings.TrimSpace(monitor.ProgramID),
		strings.TrimSpace(monitor.PlanRevisionID), strings.TrimSpace(monitor.TriggerKind), monitor.IntervalSeconds,
		strings.TrimSpace(monitor.ExpectedCoverage), int64(monitor.MaximumEvidenceAge/time.Second),
		int64(monitor.GracePeriod/time.Second), strings.TrimSpace(monitor.EscalationOwner), monitor.Enabled,
		version, monitor.NextRunAt.UTC(), expectedVersion)
	stored, err := scanComplianceMonitor(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrComplianceMonitorConflict, monitor.ID)
		}
		return nil, fmt.Errorf("put compliance monitor %q: %w", monitor.ID, err)
	}
	return stored, nil
}

func (s *Store) GetComplianceMonitor(ctx context.Context, tenantID, monitorID string) (*ports.ComplianceMonitor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- the column list is fixed and values remain parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s FROM compliance_monitors WHERE tenant_id = $1 AND id = $2`, complianceMonitorColumns), strings.TrimSpace(tenantID), strings.TrimSpace(monitorID))
	monitor, err := scanComplianceMonitor(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrComplianceMonitorNotFound
		}
		return nil, fmt.Errorf("get compliance monitor: %w", err)
	}
	return monitor, nil
}

func (s *Store) ListComplianceMonitors(ctx context.Context, filter ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	// #nosec G201 -- the column list is fixed and values remain parameterized.
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT %s FROM compliance_monitors WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, complianceMonitorColumns), strings.TrimSpace(filter.TenantID), strings.TrimSpace(filter.AfterID), limit)
	if err != nil {
		return nil, fmt.Errorf("list compliance monitors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	monitors := []*ports.ComplianceMonitor{}
	for rows.Next() {
		monitor, scanErr := scanComplianceMonitor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		monitors = append(monitors, monitor)
	}
	return monitors, rows.Err()
}

func (s *Store) ClaimDueComplianceMonitors(ctx context.Context, now time.Time, owner string, ttl time.Duration, limit uint32) ([]*ports.ComplianceMonitor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return nil, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || ttl <= 0 {
		return nil, errors.New("compliance monitor owner and positive ttl are required")
	}
	if limit == 0 || limit > 100 {
		limit = 50
	}
	// #nosec G201 -- the column list is fixed and values remain parameterized.
	query := fmt.Sprintf(`
UPDATE compliance_monitors
SET claim_owner = $3,
    claim_expires_at = $1::timestamptz + $4::bigint * INTERVAL '1 millisecond',
    updated_at = NOW()
WHERE (tenant_id, id) IN (
  SELECT tenant_id, id FROM compliance_monitors
  WHERE enabled AND trigger_kind = 'time' AND next_run_at <= $1
    AND (claim_expires_at IS NULL OR claim_expires_at <= $1)
  ORDER BY next_run_at, tenant_id, id
  LIMIT $2 FOR UPDATE SKIP LOCKED
)
RETURNING %s`, complianceMonitorColumns)
	rows, err := s.db.QueryContext(ctx, query, now.UTC(), limit, owner, ttl.Milliseconds())
	if err != nil {
		return nil, fmt.Errorf("claim due compliance monitors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	monitors := []*ports.ComplianceMonitor{}
	for rows.Next() {
		monitor, scanErr := scanComplianceMonitor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		monitors = append(monitors, monitor)
	}
	return monitors, rows.Err()
}

func (s *Store) CompleteComplianceMonitorClaim(ctx context.Context, tenantID, monitorID, owner string, occurrenceAt, completedAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE compliance_monitors
SET next_run_at = $5::timestamptz + make_interval(secs => interval_seconds),
    claim_owner = '', claim_expires_at = NULL, updated_at = NOW()
WHERE tenant_id = $1 AND id = $2 AND claim_owner = $3 AND next_run_at = $4`,
		strings.TrimSpace(tenantID), strings.TrimSpace(monitorID), strings.TrimSpace(owner), occurrenceAt.UTC(), completedAt.UTC())
	if err != nil {
		return fmt.Errorf("complete compliance monitor claim: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ports.ErrComplianceMonitorConflict
	}
	return nil
}

func (s *Store) ReleaseComplianceMonitorClaim(ctx context.Context, tenantID, monitorID, owner string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE compliance_monitors SET claim_owner = '', claim_expires_at = NULL, updated_at = NOW() WHERE tenant_id = $1 AND id = $2 AND claim_owner = $3`, strings.TrimSpace(tenantID), strings.TrimSpace(monitorID), strings.TrimSpace(owner))
	return err
}

func (s *Store) AcquireCompliancePlanLease(ctx context.Context, tenantID, planRevisionID, owner, occurrence string, now time.Time, ttl time.Duration) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(planRevisionID) == "" || strings.TrimSpace(owner) == "" || strings.TrimSpace(occurrence) == "" || ttl <= 0 {
		return errors.New("tenant, plan revision, lease owner, occurrence, and positive ttl are required")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO compliance_plan_run_leases (tenant_id, plan_revision_id, lease_owner, occurrence_key, lease_expires_at)
VALUES ($1,$2,$3,$4,$5::timestamptz + $6::bigint * INTERVAL '1 millisecond')
ON CONFLICT (tenant_id, plan_revision_id) DO UPDATE SET
  lease_owner = EXCLUDED.lease_owner,
  occurrence_key = EXCLUDED.occurrence_key,
  lease_expires_at = EXCLUDED.lease_expires_at,
  updated_at = NOW()
WHERE compliance_plan_run_leases.lease_expires_at <= $5 OR compliance_plan_run_leases.occurrence_key = EXCLUDED.occurrence_key`,
		strings.TrimSpace(tenantID), strings.TrimSpace(planRevisionID), strings.TrimSpace(owner), strings.TrimSpace(occurrence), now.UTC(), ttl.Milliseconds())
	if err != nil {
		return fmt.Errorf("acquire compliance plan lease: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ports.ErrComplianceMonitorOverlap
	}
	return nil
}

func (s *Store) ReleaseCompliancePlanLease(ctx context.Context, tenantID, planRevisionID, owner string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM compliance_plan_run_leases WHERE tenant_id = $1 AND plan_revision_id = $2 AND lease_owner = $3`, strings.TrimSpace(tenantID), strings.TrimSpace(planRevisionID), strings.TrimSpace(owner))
	return err
}

func (s *Store) RecordComplianceMonitorOutcome(ctx context.Context, tenantID, monitorID string, succeeded bool, at time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceMonitorTables(ctx); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE compliance_monitors
SET last_success_at = CASE WHEN $3 THEN $4::timestamptz ELSE last_success_at END,
    consecutive_failures = CASE WHEN $3 THEN 0 ELSE consecutive_failures + 1 END,
    updated_at = NOW()
WHERE tenant_id = $1 AND id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(monitorID), succeeded, at.UTC())
	if err != nil {
		return fmt.Errorf("record compliance monitor outcome: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ports.ErrComplianceMonitorNotFound
	}
	return nil
}

func validateComplianceMonitor(monitor *ports.ComplianceMonitor) error {
	if monitor == nil {
		return errors.New("compliance monitor is required")
	}
	if strings.TrimSpace(monitor.ID) == "" || strings.TrimSpace(monitor.TenantID) == "" || strings.TrimSpace(monitor.ProgramID) == "" || strings.TrimSpace(monitor.PlanRevisionID) == "" {
		return errors.New("compliance monitor id, tenant, program, and plan revision are required")
	}
	if monitor.TriggerKind != ports.ComplianceTriggerTime && monitor.TriggerKind != ports.ComplianceTriggerChange {
		return errors.New("compliance monitor trigger kind is invalid")
	}
	if monitor.TriggerKind == ports.ComplianceTriggerTime && monitor.IntervalSeconds <= 0 {
		return errors.New("time-triggered compliance monitor interval must be positive")
	}
	if monitor.NextRunAt.IsZero() {
		return errors.New("compliance monitor next run time is required")
	}
	return nil
}

func scanComplianceMonitor(row scanner) (*ports.ComplianceMonitor, error) {
	var monitor ports.ComplianceMonitor
	var maximumAgeSeconds, graceSeconds int64
	var lastSuccessAt, claimExpiresAt sql.NullTime
	if err := row.Scan(
		&monitor.TenantID, &monitor.ID, &monitor.ProgramID, &monitor.PlanRevisionID,
		&monitor.TriggerKind, &monitor.IntervalSeconds, &monitor.ExpectedCoverage,
		&maximumAgeSeconds, &graceSeconds, &monitor.EscalationOwner, &monitor.Enabled,
		&monitor.Version, &monitor.NextRunAt, &lastSuccessAt, &monitor.ConsecutiveFailures,
		&monitor.ClaimOwner, &claimExpiresAt, &monitor.CreatedAt, &monitor.UpdatedAt,
	); err != nil {
		return nil, err
	}
	monitor.MaximumEvidenceAge = time.Duration(maximumAgeSeconds) * time.Second
	monitor.GracePeriod = time.Duration(graceSeconds) * time.Second
	if lastSuccessAt.Valid {
		monitor.LastSuccessAt = lastSuccessAt.Time.UTC()
	}
	if claimExpiresAt.Valid {
		monitor.ClaimExpiresAt = claimExpiresAt.Time.UTC()
	}
	monitor.NextRunAt = monitor.NextRunAt.UTC()
	monitor.CreatedAt = monitor.CreatedAt.UTC()
	monitor.UpdatedAt = monitor.UpdatedAt.UTC()
	return &monitor, nil
}
