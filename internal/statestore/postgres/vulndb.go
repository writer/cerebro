package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/vulndb"
)

var ensureVulnDBStatements = []string{
	`CREATE TABLE IF NOT EXISTS vulndb_vulnerabilities (
  id TEXT PRIMARY KEY,
  vulnerability_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS vulndb_aliases (
  alias TEXT PRIMARY KEY,
  vulnerability_id TEXT NOT NULL REFERENCES vulndb_vulnerabilities(id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS vulndb_aliases_vulnerability_idx ON vulndb_aliases (vulnerability_id)`,
	`CREATE TABLE IF NOT EXISTS vulndb_affected_packages (
  row_key TEXT PRIMARY KEY,
  vulnerability_id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  package_name_key TEXT NOT NULL,
  affected_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS vulndb_affected_packages_lookup_idx ON vulndb_affected_packages (ecosystem, package_name_key)`,
	`CREATE TABLE IF NOT EXISTS vulndb_sync_states (
  source TEXT PRIMARY KEY,
  cursor_value TEXT NOT NULL DEFAULT '',
  etag TEXT NOT NULL DEFAULT '',
  last_synced_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  sync_state_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS vulndb_sync_jobs (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  feed_url TEXT NOT NULL,
  allow_insecure_http BOOLEAN NOT NULL DEFAULT FALSE,
  interval_ns BIGINT NOT NULL DEFAULT 0,
  next_run_at TIMESTAMPTZ,
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_expires_at TIMESTAMPTZ,
  last_started_at TIMESTAMPTZ,
  last_finished_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  runs BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS vulndb_sync_jobs_due_idx ON vulndb_sync_jobs (next_run_at, lease_expires_at)`,
}

// UpsertVulnerability inserts or replaces a normalized advisory.
func (s *Store) UpsertVulnerability(ctx context.Context, vulnerability vulndb.Vulnerability) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	vulnerability.ID = vulndb.NormalizeIdentifier(vulnerability.ID)
	if vulnerability.ID == "" {
		return errors.New("vulnerability id is required")
	}
	vulnerability.Aliases = normalizedVulnAliases(vulnerability.Aliases)
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(vulnerability)
	if err != nil {
		return fmt.Errorf("marshal vulnerability: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin vulndb vulnerability upsert: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO vulndb_vulnerabilities (id, vulnerability_json)
VALUES ($1, $2::jsonb)
ON CONFLICT (id)
DO UPDATE SET vulnerability_json = EXCLUDED.vulnerability_json, updated_at = NOW()`, vulnerability.ID, string(payload)); err != nil {
		return fmt.Errorf("upsert vulnerability %q: %w", vulnerability.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulndb_aliases WHERE vulnerability_id = $1`, vulnerability.ID); err != nil {
		return fmt.Errorf("replace vulnerability aliases %q: %w", vulnerability.ID, err)
	}
	aliases := append([]string{vulnerability.ID}, vulnerability.Aliases...)
	for _, alias := range normalizedVulnAliases(aliases) {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO vulndb_aliases (alias, vulnerability_id)
VALUES ($1, $2)
ON CONFLICT (alias)
DO UPDATE SET vulnerability_id = EXCLUDED.vulnerability_id`, alias, vulnerability.ID); err != nil {
			return fmt.Errorf("upsert vulnerability alias %q: %w", alias, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit vulnerability %q: %w", vulnerability.ID, err)
	}
	return nil
}

// DeleteVulnerability removes an advisory, aliases, and affected packages.
func (s *Store) DeleteVulnerability(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id = vulndb.NormalizeIdentifier(id)
	if id == "" {
		return nil
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete vulnerability %q: %w", id, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulndb_affected_packages WHERE vulnerability_id = $1`, id); err != nil {
		return fmt.Errorf("delete affected packages for vulnerability %q: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulndb_vulnerabilities WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete vulnerability %q: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete vulnerability %q: %w", id, err)
	}
	return nil
}

// FindVulnerability returns an advisory by canonical ID or alias.
func (s *Store) FindVulnerability(ctx context.Context, idOrAlias string) (vulndb.Vulnerability, bool, error) {
	if s == nil || s.db == nil {
		return vulndb.Vulnerability{}, false, errors.New("postgres is not configured")
	}
	lookup := vulndb.NormalizeIdentifier(idOrAlias)
	if lookup == "" {
		return vulndb.Vulnerability{}, false, nil
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return vulndb.Vulnerability{}, false, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `
SELECT v.vulnerability_json::text
FROM vulndb_aliases a
JOIN vulndb_vulnerabilities v ON v.id = a.vulnerability_id
WHERE a.alias = $1`, lookup).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return vulndb.Vulnerability{}, false, nil
		}
		return vulndb.Vulnerability{}, false, fmt.Errorf("query vulnerability %q: %w", lookup, err)
	}
	var vulnerability vulndb.Vulnerability
	if err := json.Unmarshal([]byte(payload), &vulnerability); err != nil {
		return vulndb.Vulnerability{}, false, fmt.Errorf("decode vulnerability %q: %w", lookup, err)
	}
	return vulnerability, true, nil
}

// UpsertAffectedPackage inserts or replaces an affected package row.
func (s *Store) UpsertAffectedPackage(ctx context.Context, affected vulndb.AffectedPackage) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	affected.VulnerabilityID = vulndb.NormalizeIdentifier(affected.VulnerabilityID)
	affected.Source = strings.TrimSpace(affected.Source)
	affected.Ecosystem = normalizeVulnDBEcosystem(affected.Ecosystem)
	affected.PackageName = strings.TrimSpace(affected.PackageName)
	if affected.VulnerabilityID == "" {
		return errors.New("affected package vulnerability id is required")
	}
	if affected.Ecosystem == "" {
		return errors.New("affected package ecosystem is required")
	}
	if affected.PackageName == "" {
		return errors.New("affected package name is required")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(affected)
	if err != nil {
		return fmt.Errorf("marshal affected package: %w", err)
	}
	rowKey := postgresAffectedPackageKey(affected)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO vulndb_affected_packages (row_key, vulnerability_id, ecosystem, package_name, package_name_key, affected_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (row_key)
DO UPDATE SET
  vulnerability_id = EXCLUDED.vulnerability_id,
  ecosystem = EXCLUDED.ecosystem,
  package_name = EXCLUDED.package_name,
  package_name_key = EXCLUDED.package_name_key,
  affected_json = EXCLUDED.affected_json,
  updated_at = NOW()`, rowKey, affected.VulnerabilityID, affected.Ecosystem, affected.PackageName, normalizeVulnDBPackageName(affected.PackageName), string(payload)); err != nil {
		return fmt.Errorf("upsert affected package %q: %w", rowKey, err)
	}
	return nil
}

// ReplaceAffectedPackages replaces affected package rows for one vulnerability/source.
func (s *Store) ReplaceAffectedPackages(ctx context.Context, vulnerabilityID string, source string, packages []vulndb.AffectedPackage) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	vulnerabilityID = vulndb.NormalizeIdentifier(vulnerabilityID)
	source = strings.TrimSpace(source)
	if vulnerabilityID == "" {
		return errors.New("affected package vulnerability id is required")
	}
	if source == "" {
		return errors.New("affected package source is required")
	}
	normalized := make([]vulndb.AffectedPackage, 0, len(packages))
	for _, affected := range packages {
		affected.VulnerabilityID = vulnerabilityID
		affected.Source = source
		affected.Ecosystem = normalizeVulnDBEcosystem(affected.Ecosystem)
		affected.PackageName = strings.TrimSpace(affected.PackageName)
		if affected.Ecosystem == "" {
			return errors.New("affected package ecosystem is required")
		}
		if affected.PackageName == "" {
			return errors.New("affected package name is required")
		}
		normalized = append(normalized, affected)
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin affected package replacement: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `
DELETE FROM vulndb_affected_packages
WHERE vulnerability_id = $1 AND (COALESCE(affected_json->>'Source', '') = $2 OR COALESCE(affected_json->>'Source', '') = '')`, vulnerabilityID, source); err != nil {
		return fmt.Errorf("delete affected packages %q/%q: %w", vulnerabilityID, source, err)
	}
	for _, affected := range normalized {
		payload, err := json.Marshal(affected)
		if err != nil {
			return fmt.Errorf("marshal affected package: %w", err)
		}
		rowKey := postgresAffectedPackageKey(affected)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO vulndb_affected_packages (row_key, vulnerability_id, ecosystem, package_name, package_name_key, affected_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (row_key)
DO UPDATE SET
  vulnerability_id = EXCLUDED.vulnerability_id,
  ecosystem = EXCLUDED.ecosystem,
  package_name = EXCLUDED.package_name,
  package_name_key = EXCLUDED.package_name_key,
  affected_json = EXCLUDED.affected_json,
  updated_at = NOW()`, rowKey, affected.VulnerabilityID, affected.Ecosystem, affected.PackageName, normalizeVulnDBPackageName(affected.PackageName), string(payload)); err != nil {
			return fmt.Errorf("replace affected package %q: %w", rowKey, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit affected package replacement: %w", err)
	}
	return nil
}

// CandidateAffectedPackages returns all advisory package rows for an ecosystem/name pair.
func (s *Store) CandidateAffectedPackages(ctx context.Context, query vulndb.PackageQuery) ([]vulndb.AffectedPackage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	ecosystem := normalizeVulnDBEcosystem(query.Ecosystem)
	packageName := normalizeVulnDBPackageName(query.Name)
	if ecosystem == "" || packageName == "" {
		return nil, nil
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT affected_json::text
FROM vulndb_affected_packages
WHERE ecosystem = $1 AND package_name_key = $2
ORDER BY row_key`, ecosystem, packageName)
	if err != nil {
		return nil, fmt.Errorf("query affected packages: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var out []vulndb.AffectedPackage
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan affected package: %w", err)
		}
		var affected vulndb.AffectedPackage
		if err := json.Unmarshal([]byte(payload), &affected); err != nil {
			return nil, fmt.Errorf("decode affected package: %w", err)
		}
		out = append(out, affected)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate affected packages: %w", err)
	}
	return out, nil
}

// GetSyncState returns feed synchronization progress by logical source label.
func (s *Store) GetSyncState(ctx context.Context, source string) (vulndb.SyncState, bool, error) {
	if s == nil || s.db == nil {
		return vulndb.SyncState{}, false, errors.New("postgres is not configured")
	}
	source = normalizeVulnDBSource(source)
	if source == "" {
		return vulndb.SyncState{}, false, nil
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return vulndb.SyncState{}, false, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT sync_state_json::text FROM vulndb_sync_states WHERE source = $1`, source).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return vulndb.SyncState{}, false, nil
		}
		return vulndb.SyncState{}, false, fmt.Errorf("query sync state %q: %w", source, err)
	}
	var state vulndb.SyncState
	if err := json.Unmarshal([]byte(payload), &state); err != nil {
		return vulndb.SyncState{}, false, fmt.Errorf("decode sync state %q: %w", source, err)
	}
	return state, true, nil
}

// PutSyncState records feed synchronization progress by logical source label.
func (s *Store) PutSyncState(ctx context.Context, state vulndb.SyncState) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	state.Source = normalizeVulnDBSource(state.Source)
	if state.Source == "" {
		return errors.New("sync state source is required")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal sync state: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO vulndb_sync_states (source, cursor_value, etag, last_synced_at, last_success_at, last_error, sync_state_json)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (source)
DO UPDATE SET
  cursor_value = EXCLUDED.cursor_value,
  etag = EXCLUDED.etag,
  last_synced_at = EXCLUDED.last_synced_at,
  last_success_at = EXCLUDED.last_success_at,
  last_error = EXCLUDED.last_error,
  sync_state_json = EXCLUDED.sync_state_json,
  updated_at = NOW()`, state.Source, strings.TrimSpace(state.Cursor), strings.TrimSpace(state.ETag), nullableTime(state.LastSyncedAt), nullableTime(state.LastSuccessAt), strings.TrimSpace(state.LastError), string(payload)); err != nil {
		return fmt.Errorf("put sync state %q: %w", state.Source, err)
	}
	return nil
}

// Stats returns counts for persisted advisory data.
func (s *Store) Stats(ctx context.Context) (vulndb.Stats, error) {
	if s == nil || s.db == nil {
		return vulndb.Stats{}, errors.New("postgres is not configured")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return vulndb.Stats{}, err
	}
	var stats vulndb.Stats
	if err := s.db.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM vulndb_vulnerabilities),
  (SELECT COUNT(*) FROM vulndb_affected_packages),
  (SELECT COUNT(*) FROM vulndb_sync_states),
  (SELECT COUNT(*) FROM vulndb_sync_jobs)`).Scan(&stats.Vulnerabilities, &stats.AffectedPackages, &stats.SyncSources, &stats.SyncJobs); err != nil {
		return vulndb.Stats{}, fmt.Errorf("query vulndb stats: %w", err)
	}
	return stats, nil
}

// PutSyncJob upserts a durable advisory feed synchronization job.
func (s *Store) PutSyncJob(ctx context.Context, job vulndb.SyncJob) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	job = normalizePostgresSyncJob(job)
	if job.ID == "" {
		return errors.New("sync job id is required")
	}
	if job.Source == "" {
		return errors.New("sync job source is required")
	}
	if !vulndb.IsSupportedFeedSource(job.Source) {
		return fmt.Errorf("unsupported vulndb feed source %q", job.Source)
	}
	if job.FeedURL == "" {
		return errors.New("sync job feed url is required")
	}
	if job.Interval <= 0 {
		return errors.New("sync job interval must be positive")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO vulndb_sync_jobs (
  id, source, feed_url, allow_insecure_http, interval_ns, next_run_at,
  lease_owner, lease_expires_at, last_started_at, last_finished_at,
  last_success_at, last_error, runs
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id)
DO UPDATE SET
  source = EXCLUDED.source,
  feed_url = EXCLUDED.feed_url,
  allow_insecure_http = EXCLUDED.allow_insecure_http,
  interval_ns = EXCLUDED.interval_ns,
  next_run_at = COALESCE(EXCLUDED.next_run_at, vulndb_sync_jobs.next_run_at),
  lease_owner = CASE WHEN EXCLUDED.lease_owner = '' THEN vulndb_sync_jobs.lease_owner ELSE EXCLUDED.lease_owner END,
  lease_expires_at = CASE WHEN EXCLUDED.lease_owner = '' THEN vulndb_sync_jobs.lease_expires_at ELSE EXCLUDED.lease_expires_at END,
  last_started_at = COALESCE(EXCLUDED.last_started_at, vulndb_sync_jobs.last_started_at),
  last_finished_at = COALESCE(EXCLUDED.last_finished_at, vulndb_sync_jobs.last_finished_at),
  last_success_at = COALESCE(EXCLUDED.last_success_at, vulndb_sync_jobs.last_success_at),
  last_error = CASE WHEN EXCLUDED.last_error = '' THEN vulndb_sync_jobs.last_error ELSE EXCLUDED.last_error END,
  runs = CASE WHEN EXCLUDED.runs = 0 THEN vulndb_sync_jobs.runs ELSE EXCLUDED.runs END,
  updated_at = NOW()`,
		job.ID,
		job.Source,
		job.FeedURL,
		job.AllowInsecureHTTP,
		job.Interval.Nanoseconds(),
		nullableTime(job.NextRunAt),
		job.LeaseOwner,
		nullableTime(job.LeaseExpiresAt),
		nullableTime(job.LastStartedAt),
		nullableTime(job.LastFinishedAt),
		nullableTime(job.LastSuccessAt),
		job.LastError,
		job.Runs,
	); err != nil {
		return fmt.Errorf("put sync job %q: %w", job.ID, err)
	}
	return nil
}

// GetSyncJob returns a durable advisory feed synchronization job.
func (s *Store) GetSyncJob(ctx context.Context, id string) (vulndb.SyncJob, bool, error) {
	if s == nil || s.db == nil {
		return vulndb.SyncJob{}, false, errors.New("postgres is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return vulndb.SyncJob{}, false, nil
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return vulndb.SyncJob{}, false, err
	}
	row := s.db.QueryRowContext(ctx, syncJobSelectSQL()+` WHERE id = $1`, id)
	job, err := scanSyncJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return vulndb.SyncJob{}, false, nil
		}
		return vulndb.SyncJob{}, false, fmt.Errorf("get sync job %q: %w", id, err)
	}
	return job, true, nil
}

// ListDueSyncJobs returns sync jobs whose next run is due and whose lease is free or expired.
func (s *Store) ListDueSyncJobs(ctx context.Context, now time.Time, limit int) ([]vulndb.SyncJob, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = vulndb.DefaultSyncJobLimit
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, syncJobSelectSQL()+`
 WHERE (lease_expires_at IS NULL OR lease_expires_at <= $1)
   AND (next_run_at IS NULL OR next_run_at <= $1)
 ORDER BY next_run_at NULLS FIRST, id
 LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list due sync jobs: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var jobs []vulndb.SyncJob
	for rows.Next() {
		job, err := scanSyncJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due sync jobs: %w", err)
	}
	return jobs, nil
}

// AcquireSyncJobLease leases a sync job for a worker.
func (s *Store) AcquireSyncJobLease(ctx context.Context, id string, owner string, ttl time.Duration) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return false, errors.New("sync job id is required")
	}
	if owner == "" {
		return false, errors.New("sync job lease owner is required")
	}
	if ttl <= 0 {
		return false, errors.New("sync job lease ttl must be positive")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE vulndb_sync_jobs
SET lease_owner = $2,
    lease_expires_at = NOW() + $3::interval,
    last_started_at = NOW(),
    updated_at = NOW()
WHERE id = $1
  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW() OR lease_owner = $2)`, id, owner, postgresInterval(ttl))
	if err != nil {
		return false, fmt.Errorf("acquire sync job lease %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("acquire sync job lease %q rows affected: %w", id, err)
	}
	return rows > 0, nil
}

// ReleaseSyncJobLease releases a sync job lease held by owner.
func (s *Store) ReleaseSyncJobLease(ctx context.Context, id string, owner string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return errors.New("sync job id is required")
	}
	if owner == "" {
		return errors.New("sync job lease owner is required")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE vulndb_sync_jobs
SET lease_owner = '',
    lease_expires_at = NULL,
    updated_at = NOW()
WHERE id = $1 AND lease_owner = $2`, id, owner); err != nil {
		return fmt.Errorf("release sync job lease %q: %w", id, err)
	}
	return nil
}

// CompleteSyncJob records a successful sync job run.
func (s *Store) CompleteSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time) error {
	return s.finishSyncJob(ctx, id, owner, nextRunAt, nil)
}

// FailSyncJob records a failed sync job run.
func (s *Store) FailSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time, syncErr error) error {
	if syncErr == nil {
		syncErr = errors.New("sync job failed")
	}
	return s.finishSyncJob(ctx, id, owner, nextRunAt, syncErr)
}

func (s *Store) finishSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time, syncErr error) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return errors.New("sync job id is required")
	}
	if err := s.ensureVulnDBTables(ctx); err != nil {
		return err
	}
	statusErr := ""
	successAt := any(nil)
	if syncErr != nil {
		statusErr = syncErr.Error()
	} else {
		successAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE vulndb_sync_jobs
SET lease_owner = '',
    lease_expires_at = NULL,
    last_finished_at = NOW(),
    last_success_at = COALESCE($4, last_success_at),
    last_error = $5,
    runs = runs + 1,
    next_run_at = $3,
    updated_at = NOW()
WHERE id = $1
  AND (lease_owner = '' OR lease_owner = $2)`, id, owner, nullableTime(nextRunAt), successAt, statusErr)
	if err != nil {
		return fmt.Errorf("finish sync job %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("finish sync job %q rows affected: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("sync job %q is leased by another owner", id)
	}
	return nil
}

func (s *Store) ensureVulnDBTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureStatements(ctx, &s.vulnDBTablesReady, "vulndb", ensureVulnDBStatements)
}

type syncJobScanner interface {
	Scan(dest ...any) error
}

func syncJobSelectSQL() string {
	return `SELECT id, source, feed_url, allow_insecure_http, interval_ns, next_run_at,
       lease_owner, lease_expires_at, last_started_at, last_finished_at,
       last_success_at, last_error, runs
FROM vulndb_sync_jobs`
}

func scanSyncJob(scanner syncJobScanner) (vulndb.SyncJob, error) {
	var (
		job            vulndb.SyncJob
		intervalNS     int64
		nextRunAt      sql.NullTime
		leaseExpiresAt sql.NullTime
		lastStartedAt  sql.NullTime
		lastFinishedAt sql.NullTime
		lastSuccessAt  sql.NullTime
		leaseOwner     string
		lastError      string
	)
	if err := scanner.Scan(
		&job.ID,
		&job.Source,
		&job.FeedURL,
		&job.AllowInsecureHTTP,
		&intervalNS,
		&nextRunAt,
		&leaseOwner,
		&leaseExpiresAt,
		&lastStartedAt,
		&lastFinishedAt,
		&lastSuccessAt,
		&lastError,
		&job.Runs,
	); err != nil {
		return vulndb.SyncJob{}, err
	}
	job.Interval = time.Duration(intervalNS)
	job.NextRunAt = nullTime(nextRunAt)
	job.LeaseOwner = strings.TrimSpace(leaseOwner)
	job.LeaseExpiresAt = nullTime(leaseExpiresAt)
	job.LastStartedAt = nullTime(lastStartedAt)
	job.LastFinishedAt = nullTime(lastFinishedAt)
	job.LastSuccessAt = nullTime(lastSuccessAt)
	job.LastError = strings.TrimSpace(lastError)
	return job, nil
}

func nullTime(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func normalizedVulnAliases(values []string) []string {
	seen := map[string]struct{}{}
	aliases := make([]string, 0, len(values))
	for _, value := range values {
		alias := vulndb.NormalizeIdentifier(value)
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	return aliases
}

func postgresAffectedPackageKey(pkg vulndb.AffectedPackage) string {
	parts := []string{
		vulndb.NormalizeIdentifier(pkg.VulnerabilityID),
		strings.TrimSpace(pkg.Source),
		normalizeVulnDBEcosystem(pkg.Ecosystem),
		normalizeVulnDBPackageName(pkg.PackageName),
		strings.TrimSpace(pkg.RangeType),
		strings.TrimSpace(pkg.Introduced),
		strings.TrimSpace(pkg.IntroducedExclusive),
		strings.TrimSpace(pkg.Fixed),
		strings.TrimSpace(pkg.LastAffected),
		strings.TrimSpace(pkg.VulnerableVersion),
		strings.TrimSpace(pkg.DistroName),
		strings.TrimSpace(pkg.DistroVersion),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizePostgresSyncJob(job vulndb.SyncJob) vulndb.SyncJob {
	job.ID = strings.TrimSpace(job.ID)
	job.Source = normalizeVulnDBSource(job.Source)
	job.FeedURL = strings.TrimSpace(job.FeedURL)
	job.LeaseOwner = strings.TrimSpace(job.LeaseOwner)
	job.LastError = strings.TrimSpace(job.LastError)
	return job
}

func normalizeVulnDBSource(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeVulnDBEcosystem(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeVulnDBPackageName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func postgresInterval(duration time.Duration) string {
	return fmt.Sprintf("%f seconds", duration.Seconds())
}
