package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureJobStatements = []string{
	`CREATE TABLE IF NOT EXISTS platform_jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT '',
  subject_type TEXT NOT NULL DEFAULT '',
  subject_id TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL DEFAULT '',
  request_hash TEXT NOT NULL DEFAULT '',
  progress_percent INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_refs_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
  attempt INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_expires_at TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ,
  failure_class TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS request_hash TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ`,
	`ALTER TABLE platform_jobs ADD COLUMN IF NOT EXISTS failure_class TEXT NOT NULL DEFAULT ''`,
	`CREATE UNIQUE INDEX IF NOT EXISTS platform_jobs_idempotency_idx ON platform_jobs (tenant_id, idempotency_key) WHERE idempotency_key <> ''`,
	`CREATE INDEX IF NOT EXISTS platform_jobs_tenant_status_idx ON platform_jobs (tenant_id, status, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_jobs_kind_updated_idx ON platform_jobs (kind, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_jobs_recovery_idx ON platform_jobs (status, lease_expires_at, created_at) WHERE status IN ('queued', 'running')`,
	`CREATE TABLE IF NOT EXISTS platform_job_events (
  job_id TEXT NOT NULL REFERENCES platform_jobs(id) ON DELETE CASCADE,
  sequence BIGSERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS platform_job_events_job_sequence_idx ON platform_job_events (job_id, sequence ASC)`,
}

const platformJobColumns = `id, kind, status, tenant_id, subject_type, subject_id, idempotency_key, request_hash,
       progress_percent, message, error, payload_json::text, result_json::text,
       result_refs_json::text, cancel_requested, attempt, lease_owner, lease_expires_at,
       heartbeat_at, failure_class, created_at, started_at, finished_at, updated_at`

// CreateJob inserts a platform job or returns the existing idempotent job.
func (s *Store) CreateJob(ctx context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, false, err
	}
	job := &ports.Job{
		ID:             newPlatformJobID(),
		Kind:           strings.TrimSpace(request.Kind),
		Status:         ports.JobStatusQueued,
		TenantID:       strings.TrimSpace(request.TenantID),
		SubjectType:    strings.TrimSpace(request.SubjectType),
		SubjectID:      strings.TrimSpace(request.SubjectID),
		IdempotencyKey: strings.TrimSpace(request.IdempotencyKey),
		RequestHash:    strings.TrimSpace(request.RequestHash),
		Payload:        cloneMap(request.Payload),
	}
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return nil, false, fmt.Errorf("marshal job payload: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO platform_jobs (
  id, kind, status, tenant_id, subject_type, subject_id, idempotency_key, request_hash, payload_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key <> ''
DO UPDATE SET request_hash = CASE
  WHEN platform_jobs.request_hash = '' THEN EXCLUDED.request_hash
  ELSE platform_jobs.request_hash
END,
updated_at = platform_jobs.updated_at
WHERE platform_jobs.request_hash = '' OR platform_jobs.request_hash = EXCLUDED.request_hash
RETURNING id, (xmax = 0) AS inserted`,
		job.ID,
		job.Kind,
		job.Status,
		job.TenantID,
		job.SubjectType,
		job.SubjectID,
		job.IdempotencyKey,
		job.RequestHash,
		string(payload),
	)
	var id string
	var inserted bool
	if err := row.Scan(&id, &inserted); err != nil {
		if errors.Is(err, sql.ErrNoRows) && job.IdempotencyKey != "" {
			return nil, false, fmt.Errorf("%w: tenant %q key %q", ports.ErrJobIdempotencyConflict, job.TenantID, job.IdempotencyKey)
		}
		return nil, false, fmt.Errorf("insert platform job: %w", err)
	}
	stored, err := s.GetJob(ctx, id)
	if err != nil {
		return nil, false, err
	}
	return stored, inserted, nil
}

// GetJob loads one platform job.
func (s *Store) GetJob(ctx context.Context, id string) (*ports.Job, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("job id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- the column list is a fixed constant and the id is parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
SELECT %s
FROM platform_jobs
WHERE id = $1`, platformJobColumns), id)
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrJobNotFound, id)
		}
		return nil, fmt.Errorf("query platform job %q: %w", id, err)
	}
	return job, nil
}

// ListJobs returns platform jobs matching the supplied filter.
func (s *Store) ListJobs(ctx context.Context, filter ports.JobFilter) ([]*ports.Job, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	clauses, args := jobFilterClauses(filter)
	limit := filter.Limit
	if limit == 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and LIMIT placeholder index is derived from args.
	query := fmt.Sprintf(`
SELECT %s
FROM platform_jobs
WHERE %s
ORDER BY updated_at DESC, id ASC
LIMIT $%d`, platformJobColumns, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list platform jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	jobs := []*ports.Job{}
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// CountJobs returns the total platform jobs matching the supplied filter.
func (s *Store) CountJobs(ctx context.Context, filter ports.JobFilter) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return 0, err
	}
	clauses, args := jobFilterClauses(filter)
	// #nosec G201 -- clauses are fixed column predicates built by jobFilterClauses.
	query := fmt.Sprintf(`
	SELECT COUNT(*)
	FROM platform_jobs
	WHERE %s`, strings.Join(clauses, " AND "))
	var count int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count platform jobs: %w", err)
	}
	if count < 0 {
		return 0, nil
	}
	return uint64(count), nil
}

func jobFilterClauses(filter ports.JobFilter) ([]string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "kind", filter.Kind)
	addTextFilter(&clauses, &args, "status", filter.Status)
	return clauses, args
}

// UpdateJob applies a partial job state update.
func (s *Store) UpdateJob(ctx context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("job id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	args := []any{id}
	setClauses := []string{}
	addSet := func(column string, value any) {
		args = append(args, value)
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addJSONSet := func(column string, value string) {
		args = append(args, value)
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d::jsonb", column, len(args)))
	}
	if status := strings.TrimSpace(update.Status); status != "" {
		addSet("status", status)
	}
	if update.Progress != nil {
		addSet("progress_percent", *update.Progress)
	}
	if update.Message != "" {
		addSet("message", update.Message)
	}
	if update.Error != "" {
		addSet("error", update.Error)
	}
	if update.FailureClass != "" {
		addSet("failure_class", strings.TrimSpace(update.FailureClass))
	}
	if update.Result != nil {
		result, err := json.Marshal(cloneMap(update.Result))
		if err != nil {
			return nil, err
		}
		addJSONSet("result_json", string(result))
	}
	if update.ResultRefs != nil {
		refs, err := json.Marshal(cloneStringMap(update.ResultRefs))
		if err != nil {
			return nil, err
		}
		addJSONSet("result_refs_json", string(refs))
	}
	if update.StartedAt != nil {
		addSet("started_at", update.StartedAt.UTC())
	}
	if update.FinishedAt != nil {
		addSet("finished_at", update.FinishedAt.UTC())
	}
	if update.CancelRequested != nil {
		addSet("cancel_requested", *update.CancelRequested)
	}
	if update.ClearLease {
		setClauses = append(setClauses,
			"lease_owner = ''",
			"lease_expires_at = NULL",
			"heartbeat_at = NULL",
		)
	}
	setClauses = append(setClauses, "updated_at = NOW()")
	allowedStatuses := normalizeJobStatuses(update.AllowedStatuses)
	clauses := []string{"id = $1"}
	if expectedOwner := strings.TrimSpace(update.ExpectedLeaseOwner); expectedOwner != "" {
		args = append(args, expectedOwner)
		clauses = append(clauses, fmt.Sprintf("lease_owner = $%d", len(args)))
	}
	if update.RequireNotCancelled {
		clauses = append(clauses, "cancel_requested = FALSE")
	}
	if len(allowedStatuses) > 0 {
		placeholders := make([]string, 0, len(allowedStatuses))
		for _, status := range allowedStatuses {
			args = append(args, status)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		clauses = append(clauses, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	resultExec, err := s.db.ExecContext(ctx, fmt.Sprintf(`
UPDATE platform_jobs
SET %s
WHERE %s`, strings.Join(setClauses, ", "), strings.Join(clauses, " AND ")), args...)
	if err != nil {
		return nil, fmt.Errorf("update platform job %q: %w", id, err)
	}
	if rows, _ := resultExec.RowsAffected(); rows == 0 {
		if len(allowedStatuses) > 0 {
			return nil, fmt.Errorf("%w: %s", ports.ErrJobUpdateConflict, id)
		}
		return nil, fmt.Errorf("%w: %s", ports.ErrJobNotFound, id)
	}
	return s.GetJob(ctx, id)
}

// ClaimJob atomically assigns queued or expired work to one worker.
func (s *Store) ClaimJob(ctx context.Context, request ports.JobClaimRequest) (*ports.Job, error) {
	jobID, owner, now, expiresAt, err := normalizeJobLeaseRequest(request.JobID, request.Owner, request.Now, request.TTL)
	if err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- the column list is fixed and all values are parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
UPDATE platform_jobs
SET status = $2,
    attempt = attempt + 1,
    lease_owner = $3,
    lease_expires_at = $4,
    heartbeat_at = $5,
    started_at = COALESCE(started_at, $5),
    message = 'job running',
    failure_class = '',
    updated_at = NOW()
WHERE id = $1
  AND cancel_requested = FALSE
  AND (
    status = $6
    OR (status = $2 AND (lease_expires_at IS NULL OR lease_expires_at <= $5))
  )
RETURNING %s`, platformJobColumns), jobID, ports.JobStatusRunning, owner, expiresAt, now, ports.JobStatusQueued)
	job, scanErr := scanJob(row)
	if scanErr == nil {
		return job, nil
	}
	if !errors.Is(scanErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("claim platform job %q: %w", jobID, scanErr)
	}
	if _, getErr := s.GetJob(ctx, jobID); getErr != nil {
		return nil, getErr
	}
	return nil, fmt.Errorf("%w: %s", ports.ErrJobLeaseConflict, jobID)
}

// RenewJobLease extends a live owner lease and returns current cancellation state.
func (s *Store) RenewJobLease(ctx context.Context, request ports.JobLeaseRenewRequest) (*ports.Job, error) {
	jobID, owner, now, expiresAt, err := normalizeJobLeaseRequest(request.JobID, request.Owner, request.Now, request.TTL)
	if err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- the column list is fixed and all values are parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
UPDATE platform_jobs
SET lease_expires_at = $3,
    heartbeat_at = $4,
    updated_at = NOW()
WHERE id = $1
  AND status = $5
  AND lease_owner = $2
  AND lease_expires_at > $4
RETURNING %s`, platformJobColumns), jobID, owner, expiresAt, now, ports.JobStatusRunning)
	job, scanErr := scanJob(row)
	if scanErr == nil {
		return job, nil
	}
	if errors.Is(scanErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ports.ErrJobLeaseConflict, jobID)
	}
	return nil, fmt.Errorf("renew platform job lease %q: %w", jobID, scanErr)
}

// RecoverJobs resets expired running jobs and lists queued work for startup.
func (s *Store) RecoverJobs(ctx context.Context, request ports.JobRecoveryRequest) ([]*ports.Job, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	now := request.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	limit := request.Limit
	if limit == 0 || limit > 500 {
		limit = 100
	}
	// #nosec G201 -- the column list is fixed and all values are parameterized.
	query := fmt.Sprintf(`
WITH cancelled AS (
  UPDATE platform_jobs
  SET status = $5,
      message = 'job cancelled',
      failure_class = 'cancelled',
      finished_at = COALESCE(finished_at, $3),
      lease_owner = '',
      lease_expires_at = NULL,
      heartbeat_at = NULL,
      updated_at = NOW()
  WHERE status = $2
    AND cancel_requested = TRUE
    AND (lease_expires_at IS NULL OR lease_expires_at <= $3)
  RETURNING id
), recovered AS (
  UPDATE platform_jobs
  SET status = $1,
      message = 'job recovered after lease expiry',
      lease_owner = '',
      lease_expires_at = NULL,
      heartbeat_at = NULL,
      updated_at = NOW()
  WHERE status = $2
    AND cancel_requested = FALSE
    AND (lease_expires_at IS NULL OR lease_expires_at <= $3)
  RETURNING %s
), queued AS (
  SELECT %s
  FROM platform_jobs
  WHERE status = $1 AND cancel_requested = FALSE
)
SELECT *
FROM (
  SELECT * FROM recovered
  UNION ALL
  SELECT * FROM queued
) runnable
ORDER BY created_at ASC, id ASC
LIMIT $4`, platformJobColumns, platformJobColumns)
	rows, err := s.db.QueryContext(ctx, query, ports.JobStatusQueued, ports.JobStatusRunning, now, limit, ports.JobStatusCancelled)
	if err != nil {
		return nil, fmt.Errorf("recover platform jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	jobs := make([]*ports.Job, 0)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func normalizeJobLeaseRequest(jobID string, owner string, now time.Time, ttl time.Duration) (string, string, time.Time, time.Time, error) {
	jobID = strings.TrimSpace(jobID)
	owner = strings.TrimSpace(owner)
	if jobID == "" {
		return "", "", time.Time{}, time.Time{}, errors.New("job id is required")
	}
	if owner == "" {
		return "", "", time.Time{}, time.Time{}, errors.New("job lease owner is required")
	}
	if ttl <= 0 {
		return "", "", time.Time{}, time.Time{}, errors.New("job lease ttl must be positive")
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return jobID, owner, now, now.Add(ttl), nil
}

// AppendJobEvent appends one timeline event.
func (s *Store) AppendJobEvent(ctx context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	if strings.TrimSpace(event.JobID) == "" {
		return nil, errors.New("job id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return nil, fmt.Errorf("marshal job event payload: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO platform_job_events (job_id, type, status, message, payload_json)
VALUES ($1, $2, $3, $4, $5::jsonb)
RETURNING sequence, created_at`,
		strings.TrimSpace(event.JobID),
		strings.TrimSpace(event.Type),
		strings.TrimSpace(event.Status),
		strings.TrimSpace(event.Message),
		string(payload),
	)
	event.JobID = strings.TrimSpace(event.JobID)
	if err := row.Scan(&event.Sequence, &event.CreatedAt); err != nil {
		return nil, fmt.Errorf("append platform job event: %w", err)
	}
	return &event, nil
}

// ListJobEvents returns the timeline for one job.
func (s *Store) ListJobEvents(ctx context.Context, jobID string, limit uint32) ([]*ports.JobEvent, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, errors.New("job id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureJobTables(ctx); err != nil {
		return nil, err
	}
	if _, err := s.GetJob(ctx, jobID); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT job_id, sequence, type, status, message, payload_json::text, created_at
FROM platform_job_events
WHERE job_id = $1
ORDER BY sequence ASC
LIMIT $2`, jobID, limit)
	if err != nil {
		return nil, fmt.Errorf("list platform job events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := []*ports.JobEvent{}
	for rows.Next() {
		event, err := scanJobEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ensureJobTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.jobTablesReady, "platform job", ensureJobStatements)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (*ports.Job, error) {
	job := &ports.Job{}
	var payload, result, refs string
	var leaseExpires, heartbeat, started, finished sql.NullTime
	if err := row.Scan(
		&job.ID, &job.Kind, &job.Status, &job.TenantID, &job.SubjectType, &job.SubjectID, &job.IdempotencyKey, &job.RequestHash,
		&job.Progress, &job.Message, &job.Error, &payload, &result, &refs, &job.CancelRequested,
		&job.Attempt, &job.LeaseOwner, &leaseExpires, &heartbeat, &job.FailureClass,
		&job.CreatedAt, &started, &finished, &job.UpdatedAt,
	); err != nil {
		return nil, err
	}
	job.Payload = map[string]any{}
	job.Result = map[string]any{}
	job.ResultRefs = map[string]string{}
	_ = json.Unmarshal([]byte(payload), &job.Payload)
	_ = json.Unmarshal([]byte(result), &job.Result)
	_ = json.Unmarshal([]byte(refs), &job.ResultRefs)
	if started.Valid {
		job.StartedAt = started.Time
	}
	if leaseExpires.Valid {
		job.LeaseExpiresAt = leaseExpires.Time
	}
	if heartbeat.Valid {
		job.HeartbeatAt = heartbeat.Time
	}
	if finished.Valid {
		job.FinishedAt = finished.Time
	}
	return job, nil
}

func scanJobEvent(row scanner) (*ports.JobEvent, error) {
	event := &ports.JobEvent{}
	var payload string
	if err := row.Scan(&event.JobID, &event.Sequence, &event.Type, &event.Status, &event.Message, &payload, &event.CreatedAt); err != nil {
		return nil, err
	}
	event.Payload = map[string]any{}
	_ = json.Unmarshal([]byte(payload), &event.Payload)
	return event, nil
}

func normalizeJobStatuses(values []string) []string {
	seen := map[string]struct{}{}
	statuses := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		statuses = append(statuses, value)
	}
	return statuses
}

func addTextFilter(clauses *[]string, args *[]any, column string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*args = append(*args, value)
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func cloneMap(values map[string]any) map[string]any {
	cloned := map[string]any{}
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := map[string]string{}
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func newPlatformJobID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return "job-" + hex.EncodeToString(b[:])
}
