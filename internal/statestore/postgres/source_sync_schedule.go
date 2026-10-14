package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.SourceRuntimeSyncScheduleStore = (*Store)(nil)

var ensureSourceRuntimeSyncScheduleStatements = []string{`CREATE TABLE IF NOT EXISTS source_runtime_sync_schedules (
  runtime_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT '',
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_failure_class TEXT NOT NULL DEFAULT '',
  next_attempt_at TIMESTAMPTZ NOT NULL,
  circuit_open BOOLEAN NOT NULL DEFAULT FALSE,
  config_digest TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL
)`,
	`ALTER TABLE source_runtime_sync_schedules ADD COLUMN IF NOT EXISTS config_digest TEXT NOT NULL DEFAULT ''`,
}

const sourceRuntimeSyncScheduleColumns = `runtime_id, tenant_id, consecutive_failures, last_failure_class, next_attempt_at, circuit_open, config_digest, updated_at`

const getSourceRuntimeSyncScheduleSQL = `SELECT ` + sourceRuntimeSyncScheduleColumns + `
FROM source_runtime_sync_schedules
WHERE runtime_id = $1`

// recordSourceRuntimeSyncFailureSQL increments the failure count in the same
// statement that stores the schedule so concurrent writers cannot lose a
// failure. $5 is the circuit threshold; zero never opens the circuit.
const recordSourceRuntimeSyncFailureSQL = `INSERT INTO source_runtime_sync_schedules (` + sourceRuntimeSyncScheduleColumns + `)
VALUES ($1, $2, 1, $3, $4, $5::INTEGER > 0 AND 1 >= $5::INTEGER, $7, $6)
ON CONFLICT (runtime_id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  consecutive_failures = LEAST(source_runtime_sync_schedules.consecutive_failures, 2147483646) + 1,
  last_failure_class = EXCLUDED.last_failure_class,
  next_attempt_at = EXCLUDED.next_attempt_at,
  circuit_open = $5::INTEGER > 0 AND LEAST(source_runtime_sync_schedules.consecutive_failures, 2147483646) + 1 >= $5::INTEGER,
  config_digest = EXCLUDED.config_digest,
  updated_at = EXCLUDED.updated_at
RETURNING ` + sourceRuntimeSyncScheduleColumns

const recordSourceRuntimeSyncSuccessSQL = `DELETE FROM source_runtime_sync_schedules WHERE runtime_id = $1`

// GetSourceRuntimeSyncSchedule returns the stored retry schedule for runtimeID.
func (s *Store) GetSourceRuntimeSyncSchedule(ctx context.Context, runtimeID string) (ports.SourceRuntimeSyncSchedule, bool, error) {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return ports.SourceRuntimeSyncSchedule{}, false, errors.New("source runtime sync schedule runtime id is required")
	}
	if err := s.ensureSourceRuntimeSyncScheduleTables(ctx); err != nil {
		return ports.SourceRuntimeSyncSchedule{}, false, err
	}
	schedule, err := scanSourceRuntimeSyncSchedule(s.db.QueryRowContext(ctx, getSourceRuntimeSyncScheduleSQL, runtimeID))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.SourceRuntimeSyncSchedule{}, false, nil
	}
	if err != nil {
		return ports.SourceRuntimeSyncSchedule{}, false, fmt.Errorf("get source runtime sync schedule %q: %w", runtimeID, err)
	}
	return schedule, true, nil
}

// RecordSourceRuntimeSyncFailure stores one failed sync and returns the
// updated schedule.
func (s *Store) RecordSourceRuntimeSyncFailure(ctx context.Context, failure ports.SourceRuntimeSyncFailure) (ports.SourceRuntimeSyncSchedule, error) {
	runtimeID := strings.TrimSpace(failure.RuntimeID)
	if runtimeID == "" {
		return ports.SourceRuntimeSyncSchedule{}, errors.New("source runtime sync schedule runtime id is required")
	}
	if failure.NextAttemptAt.IsZero() || failure.ObservedAt.IsZero() {
		return ports.SourceRuntimeSyncSchedule{}, errors.New("source runtime sync schedule times are required")
	}
	if err := s.ensureSourceRuntimeSyncScheduleTables(ctx); err != nil {
		return ports.SourceRuntimeSyncSchedule{}, err
	}
	threshold := int64(failure.CircuitOpenAfter)
	if threshold > math.MaxInt32 {
		threshold = math.MaxInt32
	}
	schedule, err := scanSourceRuntimeSyncSchedule(s.db.QueryRowContext(ctx, recordSourceRuntimeSyncFailureSQL,
		runtimeID,
		strings.TrimSpace(failure.TenantID),
		strings.TrimSpace(failure.FailureClass),
		failure.NextAttemptAt.UTC(),
		threshold,
		failure.ObservedAt.UTC(),
		strings.TrimSpace(failure.ConfigDigest),
	))
	if err != nil {
		return ports.SourceRuntimeSyncSchedule{}, fmt.Errorf("record source runtime sync failure %q: %w", runtimeID, err)
	}
	return schedule, nil
}

// RecordSourceRuntimeSyncSuccess clears the retry schedule for runtimeID.
func (s *Store) RecordSourceRuntimeSyncSuccess(ctx context.Context, runtimeID string) error {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return errors.New("source runtime sync schedule runtime id is required")
	}
	if err := s.ensureSourceRuntimeSyncScheduleTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, recordSourceRuntimeSyncSuccessSQL, runtimeID); err != nil {
		return fmt.Errorf("record source runtime sync success %q: %w", runtimeID, err)
	}
	return nil
}

func (s *Store) ensureSourceRuntimeSyncScheduleTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureStatements(ctx, &s.platform.sourceSyncSchedule, "source runtime sync schedule", ensureSourceRuntimeSyncScheduleStatements)
}

type sourceRuntimeSyncScheduleScanner interface {
	Scan(dest ...any) error
}

func scanSourceRuntimeSyncSchedule(scanner sourceRuntimeSyncScheduleScanner) (ports.SourceRuntimeSyncSchedule, error) {
	var (
		schedule    ports.SourceRuntimeSyncSchedule
		consecutive int64
	)
	if err := scanner.Scan(
		&schedule.RuntimeID,
		&schedule.TenantID,
		&consecutive,
		&schedule.LastFailureClass,
		&schedule.NextAttemptAt,
		&schedule.CircuitOpen,
		&schedule.ConfigDigest,
		&schedule.UpdatedAt,
	); err != nil {
		return ports.SourceRuntimeSyncSchedule{}, err
	}
	if consecutive > 0 && consecutive <= math.MaxUint32 {
		schedule.ConsecutiveFailures = uint32(consecutive)
	}
	schedule.NextAttemptAt = schedule.NextAttemptAt.UTC()
	schedule.UpdatedAt = schedule.UpdatedAt.UTC()
	return schedule, nil
}
