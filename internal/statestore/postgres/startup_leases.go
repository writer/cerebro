package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ensureStartupLeaseStatements = []string{
	`CREATE TABLE IF NOT EXISTS startup_job_leases (
  id TEXT PRIMARY KEY,
  lease_owner TEXT NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS startup_job_leases_expires_idx ON startup_job_leases (lease_expires_at)`,
}

// AcquireStartupJobLease acquires a short durable lease for one-off startup work.
func (s *Store) AcquireStartupJobLease(ctx context.Context, id string, owner string, ttl time.Duration) (bool, error) {
	if err := s.ensureStartupLeaseTable(ctx); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("startup job lease id is required")
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return false, errors.New("startup job lease owner is required")
	}
	if ttl <= 0 {
		return false, errors.New("startup job lease ttl must be positive")
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO startup_job_leases (id, lease_owner, lease_expires_at)
VALUES ($1, $2, NOW() + $3::interval)
ON CONFLICT (id) DO UPDATE SET
  lease_owner = EXCLUDED.lease_owner,
  lease_expires_at = EXCLUDED.lease_expires_at,
  updated_at = NOW()
WHERE startup_job_leases.lease_expires_at <= NOW()`,
		id, owner, postgresInterval(ttl))
	if err != nil {
		return false, fmt.Errorf("acquire startup job lease %q: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("acquire startup job lease %q rows affected: %w", id, err)
	}
	return rows > 0, nil
}

// ReleaseStartupJobLease releases a startup-job lease held by owner.
func (s *Store) ReleaseStartupJobLease(ctx context.Context, id string, owner string) error {
	if err := s.ensureStartupLeaseTable(ctx); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("startup job lease id is required")
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return errors.New("startup job lease owner is required")
	}
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM startup_job_leases
WHERE id = $1 AND lease_owner = $2`,
		id, owner); err != nil {
		return fmt.Errorf("release startup job lease %q: %w", id, err)
	}
	return nil
}

func (s *Store) ensureStartupLeaseTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.startupLeaseTableReady, "startup_job_leases", ensureStartupLeaseStatements)
}
