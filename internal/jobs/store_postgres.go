package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Compile-time interface check.
var _ Store = (*PostgresStore)(nil)

// PostgresStore implements Store using PostgreSQL via database/sql.
type PostgresStore struct {
	db *sql.DB
	// rewriteSQL is an optional SQL rewriter used for testing with alternate
	// drivers (e.g. SQLite). When nil the query is used as-is with Postgres
	// $1,$2 placeholders.
	rewriteSQL func(string) string
}

// NewPostgresStore creates a new PostgresStore backed by the given sql.DB.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// q applies any configured SQL rewriter (used for testing with SQLite).
func (s *PostgresStore) q(query string) string {
	if s.rewriteSQL != nil {
		return s.rewriteSQL(query)
	}
	return query
}

const jobColumns = `job_id, type, status, payload, result, error, attempt, max_attempts, group_id, worker_id, lease_expires_at, created_at, updated_at, correlation_id, parent_id`

// scanJob scans a single row into a Job struct. The caller must ensure the
// column order matches jobColumns.
func scanJob(sc interface{ Scan(dest ...any) error }) (*Job, error) {
	var j Job
	err := sc.Scan(
		&j.ID, &j.Type, &j.Status, &j.Payload, &j.Result, &j.Error,
		&j.Attempt, &j.MaxAttempts, &j.GroupID, &j.WorkerID,
		&j.LeaseExpiresAt, &j.CreatedAt, &j.UpdatedAt,
		&j.CorrelationID, &j.ParentID,
	)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// EnsureSchema creates the jobs table and required indexes if they do not
// already exist.
func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS jobs (
	job_id TEXT PRIMARY KEY,
	type TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	payload TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	attempt INTEGER NOT NULL DEFAULT 0,
	max_attempts INTEGER NOT NULL DEFAULT 0,
	group_id TEXT NOT NULL DEFAULT '',
	worker_id TEXT NOT NULL DEFAULT '',
	lease_expires_at BIGINT NOT NULL DEFAULT 0,
	created_at BIGINT NOT NULL DEFAULT 0,
	updated_at BIGINT NOT NULL DEFAULT 0,
	correlation_id TEXT NOT NULL DEFAULT '',
	parent_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_lease ON jobs (status, lease_expires_at);
`)
	return err
}

// CreateJob inserts a new job. Returns an error if a job with the same ID
// already exists.
func (s *PostgresStore) CreateJob(ctx context.Context, job *Job) error {
	if job == nil {
		return fmt.Errorf("job required")
	}
	res, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO jobs (`+jobColumns+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (job_id) DO NOTHING
`),
		job.ID, string(job.Type), string(job.Status), job.Payload, job.Result, job.Error,
		job.Attempt, job.MaxAttempts, job.GroupID, job.WorkerID,
		job.LeaseExpiresAt, job.CreatedAt, job.UpdatedAt,
		job.CorrelationID, job.ParentID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("job %s already exists", job.ID)
	}
	return nil
}

// GetJob retrieves a job by ID. Returns ErrJobNotFound if the job does not
// exist.
func (s *PostgresStore) GetJob(ctx context.Context, jobID string) (*Job, error) {
	if jobID == "" {
		return nil, fmt.Errorf("job id required")
	}
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+jobColumns+` FROM jobs WHERE job_id = $1`), jobID)
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrJobNotFound
	}
	if err != nil {
		return nil, err
	}
	return job, nil
}

// ClaimJob atomically claims a job for the given worker. A job can be claimed
// if it is queued, or if it is running but its lease has expired (lease
// stealing). Returns the updated job and true on success; nil and false if the
// job could not be claimed.
//
// Note: placeholder numbers follow SQL text order so that a simple $N→?
// rewriter produces correct positional parameters for SQLite testing.
func (s *PostgresStore) ClaimJob(ctx context.Context, jobID, workerID string, lease time.Duration) (*Job, bool, error) {
	if jobID == "" {
		return nil, false, fmt.Errorf("job id required")
	}
	if workerID == "" {
		return nil, false, fmt.Errorf("worker id required")
	}

	now := time.Now().UTC().Unix()
	leaseUntil := now + int64(lease.Seconds())

	row := s.db.QueryRowContext(ctx, s.q(`
UPDATE jobs SET
	status = 'running',
	worker_id = $1,
	lease_expires_at = $2,
	attempt = attempt + 1,
	updated_at = $3
WHERE job_id = $4
	AND (status = 'queued' OR (status = 'running' AND lease_expires_at < $5))
RETURNING `+jobColumns),
		workerID, leaseUntil, now, jobID, now,
	)

	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return job, true, nil
}

// ExtendLease extends the lease for a running job owned by the given worker.
// Returns ErrJobLeaseLost if the job is not running or is owned by a different
// worker.
func (s *PostgresStore) ExtendLease(ctx context.Context, jobID, workerID string, lease time.Duration) error {
	if jobID == "" {
		return fmt.Errorf("job id required")
	}
	if workerID == "" {
		return fmt.Errorf("worker id required")
	}

	now := time.Now().UTC().Unix()
	leaseUntil := now + int64(lease.Seconds())

	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET lease_expires_at = $1, updated_at = $2
WHERE job_id = $3 AND status = 'running' AND worker_id = $4
`), leaseUntil, now, jobID, workerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrJobLeaseLost
	}
	return nil
}

// CompleteJob unconditionally marks a job as succeeded.
func (s *PostgresStore) CompleteJob(ctx context.Context, jobID, result string) error {
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'succeeded', result = $1, error = '', lease_expires_at = 0, updated_at = $2
WHERE job_id = $3
`), result, now, jobID)
	return err
}

// FailJob unconditionally marks a job as failed.
func (s *PostgresStore) FailJob(ctx context.Context, jobID, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'failed', error = $1, lease_expires_at = 0, updated_at = $2
WHERE job_id = $3
`), message, now, jobID)
	return err
}

// RetryJob unconditionally requeues a job for retry.
func (s *PostgresStore) RetryJob(ctx context.Context, jobID, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'queued', error = $1, lease_expires_at = 0, worker_id = '', updated_at = $2
WHERE job_id = $3
`), message, now, jobID)
	return err
}

// CompleteJobOwned marks a job as succeeded only if the caller still owns the
// lease (matching worker_id and attempt). Returns ErrJobLeaseLost otherwise.
func (s *PostgresStore) CompleteJobOwned(ctx context.Context, jobID, workerID string, attempt int, result string) error {
	now := time.Now().UTC().Unix()
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'succeeded', result = $1, error = '', lease_expires_at = 0, updated_at = $2
WHERE job_id = $3 AND status = 'running' AND worker_id = $4 AND attempt = $5
`), result, now, jobID, workerID, attempt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrJobLeaseLost
	}
	return nil
}

// FailJobOwned marks a job as failed only if the caller still owns the lease.
// Returns ErrJobLeaseLost otherwise.
func (s *PostgresStore) FailJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	now := time.Now().UTC().Unix()
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'failed', error = $1, lease_expires_at = 0, updated_at = $2
WHERE job_id = $3 AND status = 'running' AND worker_id = $4 AND attempt = $5
`), message, now, jobID, workerID, attempt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrJobLeaseLost
	}
	return nil
}

// RetryJobOwned requeues a job only if the caller still owns the lease.
// Returns ErrJobLeaseLost otherwise.
func (s *PostgresStore) RetryJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	now := time.Now().UTC().Unix()
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE jobs SET status = 'queued', error = $1, lease_expires_at = 0, worker_id = '', updated_at = $2
WHERE job_id = $3 AND status = 'running' AND worker_id = $4 AND attempt = $5
`), message, now, jobID, workerID, attempt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrJobLeaseLost
	}
	return nil
}

// FindOrphanedJobs returns running jobs whose leases have expired, ordered by
// lease expiry time. This is used by the orphan scanner to recover stuck jobs.
func (s *PostgresStore) FindOrphanedJobs(ctx context.Context, limit int) ([]*Job, error) {
	now := time.Now().UTC().Unix()
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT `+jobColumns+` FROM jobs
WHERE status = 'running' AND lease_expires_at > 0 AND lease_expires_at < $1
ORDER BY lease_expires_at ASC
LIMIT $2
`), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}
