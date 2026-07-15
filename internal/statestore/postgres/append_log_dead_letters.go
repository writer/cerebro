package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

const appendLogDeadLetterDefaultLimit = uint32(50)
const appendLogDeadLetterMaxLimit = uint32(500)
const appendLogDeadLetterCleanupDefaultLimit = 100
const appendLogDeadLetterCleanupMaxLimit = 500
const appendLogDeadLetterCapacityLockID = int64(0x6170646c)
const appendLogDeadLetterCapacityLockSQL = `SELECT pg_advisory_xact_lock($1)`
const appendLogDeadLetterAuditInsertSQL = `INSERT INTO append_log_dead_letter_audit (dead_letter_id, action, actor, reason) VALUES ($1, $2, $3, $4)`
const appendLogDeadLetterForcePurgeSelectSQL = `SELECT status,
       replay_token <> '' AND replay_lease_expires_at IS NOT NULL AND replay_lease_expires_at > NOW()
FROM append_log_dead_letters
WHERE id = $1 AND tenant_id = $2
FOR UPDATE`
const appendLogDeadLetterForcePurgeDeleteSQL = `DELETE FROM append_log_dead_letters
WHERE id = $1
  AND tenant_id = $2
  AND status = 'pending'
  AND (replay_token = '' OR replay_lease_expires_at IS NULL OR replay_lease_expires_at <= NOW())`

var ensureAppendLogDeadLetterStatements = []string{`CREATE TABLE IF NOT EXISTS append_log_dead_letters (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  subject TEXT NOT NULL,
  operation TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL DEFAULT '',
  runtime_id TEXT NOT NULL DEFAULT '',
  job_id TEXT NOT NULL DEFAULT '',
  error_category TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 0,
  payload_hash TEXT NOT NULL,
  payload_bytes INTEGER NOT NULL DEFAULT 0,
  event_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  replayed_at TIMESTAMPTZ,
  discarded_at TIMESTAMPTZ,
  discard_reason TEXT NOT NULL DEFAULT '',
  replay_owner TEXT NOT NULL DEFAULT '',
  replay_token TEXT NOT NULL DEFAULT '',
  replay_lease_expires_at TIMESTAMPTZ,
  replay_attempt_count INTEGER NOT NULL DEFAULT 0,
  last_replay_started_at TIMESTAMPTZ,
  last_replay_finished_at TIMESTAMPTZ,
  last_replay_error_category TEXT NOT NULL DEFAULT ''
)`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS replay_owner TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS replay_token TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS replay_lease_expires_at TIMESTAMPTZ`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS replay_attempt_count INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS last_replay_started_at TIMESTAMPTZ`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS last_replay_finished_at TIMESTAMPTZ`,
	`ALTER TABLE append_log_dead_letters ADD COLUMN IF NOT EXISTS last_replay_error_category TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_status_updated_idx ON append_log_dead_letters (status, updated_at ASC, id ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_subject_status_idx ON append_log_dead_letters (subject, status, updated_at ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_runtime_status_idx ON append_log_dead_letters (runtime_id, status, updated_at ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_source_status_idx ON append_log_dead_letters (source_id, status, updated_at ASC)`,
	`CREATE TABLE IF NOT EXISTS append_log_dead_letter_audit (
  id BIGSERIAL PRIMARY KEY,
  dead_letter_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letter_audit_record_created_idx ON append_log_dead_letter_audit (dead_letter_id, created_at DESC)`,
}

const recordAppendLogDeadLetterSQL = `
	INSERT INTO append_log_dead_letters (
	  id, status, subject, operation, event_id, event_kind, tenant_id, source_id,
	  runtime_id, job_id, error_category, error_message, retry_count, max_attempts,
	  payload_hash, payload_bytes, event_json
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb)
	ON CONFLICT (id)
	DO UPDATE SET status = EXCLUDED.status,
	              subject = EXCLUDED.subject,
	              operation = EXCLUDED.operation,
	              event_id = EXCLUDED.event_id,
	              event_kind = EXCLUDED.event_kind,
	              tenant_id = EXCLUDED.tenant_id,
	              source_id = EXCLUDED.source_id,
	              runtime_id = EXCLUDED.runtime_id,
	              job_id = EXCLUDED.job_id,
	              error_category = EXCLUDED.error_category,
	              error_message = EXCLUDED.error_message,
	              retry_count = EXCLUDED.retry_count,
	              max_attempts = EXCLUDED.max_attempts,
	              payload_hash = EXCLUDED.payload_hash,
	              payload_bytes = EXCLUDED.payload_bytes,
	              event_json = EXCLUDED.event_json,
	              updated_at = NOW(),
	              replayed_at = NULL,
	              discarded_at = NULL,
	              discard_reason = ''
	WHERE append_log_dead_letters.status = 'pending'`

func (s *Store) RecordAppendLogDeadLetter(ctx context.Context, record ports.AppendLogDeadLetter) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return err
	}
	record = normalizeAppendLogDeadLetter(record)
	if err := validateAppendLogDeadLetter(record); err != nil {
		return err
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(record.Event)
	if err != nil {
		return fmt.Errorf("marshal append log dead letter event %q: %w", record.EventID, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin append log dead letter record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, appendLogDeadLetterCapacityLockSQL, appendLogDeadLetterCapacityLockID); err != nil {
		return fmt.Errorf("lock append log dead letter capacity: %w", err)
	}
	backlog, existingBytes, existingStatus, err := appendLogDeadLetterCapacity(ctx, tx, record.ID)
	if err != nil {
		return err
	}
	if existingStatus == ports.AppendLogDeadLetterStatusReplayed || existingStatus == ports.AppendLogDeadLetterStatusDiscarded {
		annotateAppendLogDeadLetterBacklog(ctx, backlog, s.appendLog.deadLetterPolicy, "terminal_record_preserved")
		return nil
	}
	projected := projectAppendLogDeadLetterBacklog(backlog, existingStatus, existingBytes, int64(record.PayloadBytes))
	if projected.PendingRecords > 0 && projected.OldestPendingAt.IsZero() {
		projected.OldestPendingAt = time.Now()
	}
	policy := s.appendLog.deadLetterPolicy
	if appendLogDeadLetterHardLimitExceeded(projected, policy) {
		annotateAppendLogDeadLetterBacklog(ctx, projected, policy, "hard_limit_rejected")
		telemetry.IncrementMain(ctx, "append_log.dead_letter.hard_limit_rejection.count", 1)
		return fmt.Errorf("%w: pending_records=%d hard_records=%d pending_bytes=%d hard_bytes=%d", ports.ErrAppendLogDeadLetterBacklogHardLimit, projected.PendingRecords, policy.DeadLetterHardRecords, projected.PendingPayloadBytes, policy.DeadLetterHardBytes)
	}
	result, err := tx.ExecContext(ctx, recordAppendLogDeadLetterSQL,
		record.ID,
		record.Status,
		record.Subject,
		record.Operation,
		record.EventID,
		record.EventKind,
		record.TenantID,
		record.SourceID,
		record.RuntimeID,
		record.JobID,
		record.ErrorCategory,
		record.ErrorMessage,
		record.RetryCount,
		record.MaxAttempts,
		record.PayloadHash,
		record.PayloadBytes,
		string(payload),
	)
	if err != nil {
		return fmt.Errorf("record append log dead letter %q: %w", record.ID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("record append log dead letter %q rows affected: %w", record.ID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: append log dead letter %q changed state while recording", ports.ErrAppendLogDeadLetterNotPending, record.ID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit append log dead letter %q: %w", record.ID, err)
	}
	annotateAppendLogDeadLetterBacklog(ctx, projected, policy, "recorded")
	if projected.PendingRecords >= policy.DeadLetterWarningRecords || projected.PendingPayloadBytes >= policy.DeadLetterWarningBytes {
		telemetry.IncrementMain(ctx, "append_log.dead_letter.backlog_warning.count", 1)
	}
	return nil
}

func projectAppendLogDeadLetterBacklog(backlog ports.AppendLogDeadLetterBacklog, existingStatus string, existingBytes int64, payloadBytes int64) ports.AppendLogDeadLetterBacklog {
	projected := backlog
	switch strings.TrimSpace(existingStatus) {
	case ports.AppendLogDeadLetterStatusPending:
		projected.PendingPayloadBytes = projected.PendingPayloadBytes - existingBytes + payloadBytes
	case "":
		projected.PendingRecords++
		projected.PendingPayloadBytes += payloadBytes
	}
	return projected
}

func appendLogDeadLetterHardLimitExceeded(backlog ports.AppendLogDeadLetterBacklog, policy config.StateStoreConfig) bool {
	return backlog.PendingRecords > policy.DeadLetterHardRecords || backlog.PendingPayloadBytes > policy.DeadLetterHardBytes
}

type appendLogDeadLetterCapacityQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func appendLogDeadLetterCapacity(ctx context.Context, queryer appendLogDeadLetterCapacityQueryer, id string) (ports.AppendLogDeadLetterBacklog, int64, string, error) {
	var backlog ports.AppendLogDeadLetterBacklog
	var oldest sql.NullTime
	var existingBytes sql.NullInt64
	var existingStatus sql.NullString
	err := queryer.QueryRowContext(ctx, `SELECT
  COUNT(*) FILTER (WHERE status = 'pending'),
  COALESCE(SUM(payload_bytes) FILTER (WHERE status = 'pending'), 0),
  MIN(created_at) FILTER (WHERE status = 'pending'),
	  (SELECT payload_bytes FROM append_log_dead_letters WHERE id = $1),
	  (SELECT status FROM append_log_dead_letters WHERE id = $1)
FROM append_log_dead_letters`, id).Scan(&backlog.PendingRecords, &backlog.PendingPayloadBytes, &oldest, &existingBytes, &existingStatus)
	if err != nil {
		return ports.AppendLogDeadLetterBacklog{}, 0, "", fmt.Errorf("get append log dead letter capacity: %w", err)
	}
	if oldest.Valid {
		backlog.OldestPendingAt = oldest.Time
	}
	return backlog, existingBytes.Int64, strings.TrimSpace(existingStatus.String), nil
}

func (s *Store) ListAppendLogDeadLetters(ctx context.Context, filter ports.AppendLogDeadLetterFilter) ([]ports.AppendLogDeadLetter, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return nil, err
	}
	query, args := appendLogDeadLetterListQuery(filter)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list append log dead letters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var records []ports.AppendLogDeadLetter
	for rows.Next() {
		record, err := scanAppendLogDeadLetter(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list append log dead letters rows: %w", err)
	}
	return records, nil
}

func (s *Store) GetAppendLogDeadLetter(ctx context.Context, id string) (ports.AppendLogDeadLetter, error) {
	if s == nil || s.db == nil {
		return ports.AppendLogDeadLetter{}, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	row := s.db.QueryRowContext(ctx, appendLogDeadLetterSelectSQL()+` WHERE id = $1`, strings.TrimSpace(id))
	record, err := scanAppendLogDeadLetter(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ports.AppendLogDeadLetter{}, ports.ErrAppendLogDeadLetterNotFound
		}
		return ports.AppendLogDeadLetter{}, err
	}
	return record, nil
}

func (s *Store) ClaimAppendLogDeadLetterReplay(ctx context.Context, id string, owner string, token string, lease time.Duration) (ports.AppendLogDeadLetter, error) {
	if s == nil || s.db == nil {
		return ports.AppendLogDeadLetter{}, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	token = strings.TrimSpace(token)
	if id == "" || owner == "" || token == "" {
		return ports.AppendLogDeadLetter{}, errors.New("append log dead letter replay id, owner, and token are required")
	}
	if lease < time.Second {
		return ports.AppendLogDeadLetter{}, errors.New("append log dead letter replay lease must be at least one second")
	}
	record, err := scanAppendLogDeadLetter(s.db.QueryRowContext(ctx, claimAppendLogDeadLetterReplaySQL(), id, owner, token, int64(lease/time.Second)))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.AppendLogDeadLetter{}, s.appendLogDeadLetterClaimConflict(ctx, id)
	}
	if err != nil {
		return ports.AppendLogDeadLetter{}, fmt.Errorf("claim append log dead letter %q replay: %w", id, err)
	}
	return record, nil
}

func claimAppendLogDeadLetterReplaySQL() string {
	return `UPDATE append_log_dead_letters
SET replay_owner = $2,
    replay_token = $3,
    replay_lease_expires_at = NOW() + ($4 * INTERVAL '1 second'),
    replay_attempt_count = replay_attempt_count + 1,
    last_replay_started_at = NOW(),
    last_replay_finished_at = NULL,
    last_replay_error_category = '',
    updated_at = NOW()
WHERE id = $1
  AND status = 'pending'
  AND (replay_token = '' OR replay_lease_expires_at IS NULL OR replay_lease_expires_at <= NOW())
RETURNING ` + appendLogDeadLetterColumns()
}

func (s *Store) RenewAppendLogDeadLetterReplay(ctx context.Context, id string, token string, lease time.Duration) error {
	if lease < time.Second {
		return errors.New("append log dead letter replay lease must be at least one second")
	}
	return s.updateAppendLogDeadLetterReplayClaim(ctx, id, token, renewAppendLogDeadLetterReplaySQL, int64(lease/time.Second))
}

func (s *Store) CompleteAppendLogDeadLetterReplay(ctx context.Context, id string, token string, actor string, reason string) error {
	return s.completeAppendLogDeadLetterReplayWithAudit(ctx, id, token, actor, reason)
}

func (s *Store) ReleaseAppendLogDeadLetterReplay(ctx context.Context, id string, token string, errorCategory string) error {
	errorCategory = strings.TrimSpace(errorCategory)
	if len(errorCategory) > 64 {
		errorCategory = errorCategory[:64]
	}
	return s.updateAppendLogDeadLetterReplayClaim(ctx, id, token, releaseAppendLogDeadLetterReplaySQL, errorCategory)
}

const renewAppendLogDeadLetterReplaySQL = `UPDATE append_log_dead_letters
SET replay_lease_expires_at = NOW() + ($3 * INTERVAL '1 second'), updated_at = NOW()
WHERE id = $1 AND status = 'pending' AND replay_token = $2 AND replay_lease_expires_at > NOW()`

const completeAppendLogDeadLetterReplaySQL = `UPDATE append_log_dead_letters
SET status = 'replayed', replayed_at = NOW(), replay_owner = '', replay_token = '', replay_lease_expires_at = NULL, last_replay_finished_at = NOW(), last_replay_error_category = '', updated_at = NOW()
WHERE id = $1 AND status = 'pending' AND replay_token = $2 AND replay_lease_expires_at > NOW()`

const releaseAppendLogDeadLetterReplaySQL = `UPDATE append_log_dead_letters
SET replay_owner = '', replay_token = '', replay_lease_expires_at = NULL, last_replay_finished_at = NOW(), last_replay_error_category = $3, updated_at = NOW()
WHERE id = $1 AND status = 'pending' AND replay_token = $2 AND replay_lease_expires_at > NOW()`

func (s *Store) updateAppendLogDeadLetterReplayClaim(ctx context.Context, id string, token string, query string, extra ...any) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	token = strings.TrimSpace(token)
	if id == "" || token == "" {
		return errors.New("append log dead letter replay id and token are required")
	}
	args := []any{id, token}
	args = append(args, extra...)
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update append log dead letter %q replay claim: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update append log dead letter %q replay claim rows affected: %w", id, err)
	}
	if rows == 0 {
		return s.appendLogDeadLetterReplayClaimConflict(ctx, id)
	}
	return nil
}

func (s *Store) appendLogDeadLetterClaimConflict(ctx context.Context, id string) error {
	var status string
	var token string
	err := s.db.QueryRowContext(ctx, `SELECT status, replay_token FROM append_log_dead_letters WHERE id = $1`, id).Scan(&status, &token)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrAppendLogDeadLetterNotFound
	}
	if err != nil {
		return fmt.Errorf("query append log dead letter %q replay claim: %w", id, err)
	}
	if status == ports.AppendLogDeadLetterStatusReplayed {
		return ports.ErrAppendLogDeadLetterAlreadyReplayed
	}
	if token != "" {
		return ports.ErrAppendLogDeadLetterReplayClaimed
	}
	return fmt.Errorf("append log dead letter %q has status %q", id, status)
}

func (s *Store) appendLogDeadLetterReplayClaimConflict(ctx context.Context, id string) error {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM append_log_dead_letters WHERE id = $1`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrAppendLogDeadLetterNotFound
	}
	if err != nil {
		return fmt.Errorf("query append log dead letter %q replay claim: %w", id, err)
	}
	if status == ports.AppendLogDeadLetterStatusReplayed {
		return ports.ErrAppendLogDeadLetterAlreadyReplayed
	}
	return ports.ErrAppendLogDeadLetterReplayClaimInvalid
}

func (s *Store) DiscardAppendLogDeadLetter(ctx context.Context, id string, actor string, reason string) error {
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if actor == "" || reason == "" {
		return errors.New("discard actor and reason are required")
	}
	return s.transitionAppendLogDeadLetterWithAudit(ctx, id, ports.AppendLogDeadLetterStatusDiscarded, actor, reason, "")
}

func (s *Store) completeAppendLogDeadLetterReplayWithAudit(ctx context.Context, id string, token string, actor string, reason string) error {
	id = strings.TrimSpace(id)
	token = strings.TrimSpace(token)
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if id == "" || token == "" || actor == "" || reason == "" {
		return errors.New("replay id, token, actor, and reason are required")
	}
	return s.transitionAppendLogDeadLetterWithAudit(ctx, id, ports.AppendLogDeadLetterStatusReplayed, actor, reason, token)
}

func (s *Store) transitionAppendLogDeadLetterWithAudit(ctx context.Context, id string, status string, actor string, reason string, token string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if id == "" || actor == "" || reason == "" {
		return errors.New("dead-letter id, actor, and reason are required")
	}
	var query string
	var args []any
	switch status {
	case ports.AppendLogDeadLetterStatusReplayed:
		query = completeAppendLogDeadLetterReplaySQL
		args = []any{id, strings.TrimSpace(token)}
	case ports.AppendLogDeadLetterStatusDiscarded:
		query = `UPDATE append_log_dead_letters SET status = $2, updated_at = NOW(), discarded_at = NOW(), discard_reason = $3 WHERE id = $1 AND status = 'pending' AND (replay_token = '' OR replay_lease_expires_at IS NULL OR replay_lease_expires_at <= NOW())`
		args = []any{id, status, reason}
	default:
		return fmt.Errorf("unsupported append log dead letter status %q", status)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin append log dead letter %s: %w", status, err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update append log dead letter %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update append log dead letter %q rows affected: %w", id, err)
	}
	if rows == 0 {
		_ = tx.Rollback()
		if status == ports.AppendLogDeadLetterStatusReplayed {
			return s.appendLogDeadLetterReplayClaimConflict(ctx, id)
		}
		return s.appendLogDeadLetterStatusConflict(ctx, id, status)
	}
	if _, err := tx.ExecContext(ctx, appendLogDeadLetterAuditInsertSQL, id, status, actor, reason); err != nil {
		return fmt.Errorf("audit append log dead letter %q %s: %w", id, status, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit append log dead letter %q %s: %w", id, status, err)
	}
	if status == ports.AppendLogDeadLetterStatusReplayed {
		telemetry.IncrementMain(ctx, appendLogDeadLetterMetricKeys[8], 1)
	} else {
		telemetry.IncrementMain(ctx, appendLogDeadLetterMetricKeys[9], 1)
	}
	return nil
}

func (s *Store) GetAppendLogDeadLetterBacklog(ctx context.Context) (ports.AppendLogDeadLetterBacklog, error) {
	if s == nil || s.db == nil {
		return ports.AppendLogDeadLetterBacklog{}, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return ports.AppendLogDeadLetterBacklog{}, err
	}
	var backlog ports.AppendLogDeadLetterBacklog
	var oldest sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT
  COUNT(*) FILTER (WHERE status = 'pending'),
  COUNT(*) FILTER (WHERE status IN ('replayed', 'discarded')),
  COALESCE(SUM(payload_bytes) FILTER (WHERE status = 'pending'), 0),
  MIN(created_at) FILTER (WHERE status = 'pending')
FROM append_log_dead_letters`).Scan(
		&backlog.PendingRecords,
		&backlog.TerminalRecords,
		&backlog.PendingPayloadBytes,
		&oldest,
	)
	if err != nil {
		return ports.AppendLogDeadLetterBacklog{}, fmt.Errorf("get append log dead letter backlog: %w", err)
	}
	if oldest.Valid {
		backlog.OldestPendingAt = oldest.Time
	}
	policy := s.appendLog.deadLetterPolicy
	backlog.PendingRetention = policy.DeadLetterPendingRetention
	backlog.TerminalRetention = policy.DeadLetterTerminalRetention
	backlog.WarningRecords = policy.DeadLetterWarningRecords
	backlog.HardRecords = policy.DeadLetterHardRecords
	backlog.WarningBytes = policy.DeadLetterWarningBytes
	backlog.HardBytes = policy.DeadLetterHardBytes
	annotateAppendLogDeadLetterBacklog(ctx, backlog, policy, "observed")
	return backlog, nil
}

var appendLogDeadLetterMetricKeys = [...]string{
	"append_log.dead_letter.pending_records.max",
	"append_log.dead_letter.pending_payload_bytes.max",
	"append_log.dead_letter.oldest_pending_age_seconds.max",
	"append_log.dead_letter.cleanup.deleted.count",
	"append_log.dead_letter.cleanup.empty.count",
	"append_log.dead_letter.cleanup.failed.count",
	"append_log.dead_letter.hard_limit_rejection.count",
	"append_log.dead_letter.backlog_warning.count",
	"append_log.dead_letter.replay.completed.count",
	"append_log.dead_letter.discard.completed.count",
}

var appendLogDeadLetterForcePurgeMetricKeys = map[string]string{
	"deleted":      "append_log.dead_letter.force_purge.deleted.count",
	"not_found":    "append_log.dead_letter.force_purge.not_found.count",
	"not_pending":  "append_log.dead_letter.force_purge.not_pending.count",
	"active_claim": "append_log.dead_letter.force_purge.active_claim.count",
	"failed":       "append_log.dead_letter.force_purge.failed.count",
}

func annotateAppendLogDeadLetterBacklog(ctx context.Context, backlog ports.AppendLogDeadLetterBacklog, policy config.StateStoreConfig, outcome string) {
	telemetry.MaxMain(ctx, appendLogDeadLetterMetricKeys[0], backlog.PendingRecords)
	telemetry.MaxMain(ctx, appendLogDeadLetterMetricKeys[1], backlog.PendingPayloadBytes)
	if !backlog.OldestPendingAt.IsZero() {
		age := time.Since(backlog.OldestPendingAt).Seconds()
		if age > 0 {
			telemetry.MaxMain(ctx, appendLogDeadLetterMetricKeys[2], int64(age))
		}
	}
	telemetry.AnnotateMain(ctx, telemetry.Attrs(
		telemetry.Field{Key: "append_log.dead_letter.last_capacity_outcome", Value: strings.TrimSpace(outcome)},
		telemetry.Field{Key: "append_log.dead_letter.warning_records", Value: policy.DeadLetterWarningRecords},
		telemetry.Field{Key: "append_log.dead_letter.hard_records", Value: policy.DeadLetterHardRecords},
		telemetry.Field{Key: "append_log.dead_letter.warning_bytes", Value: policy.DeadLetterWarningBytes},
		telemetry.Field{Key: "append_log.dead_letter.hard_bytes", Value: policy.DeadLetterHardBytes},
	))
}

func (s *Store) CleanupAppendLogDeadLetters(ctx context.Context, request ports.AppendLogDeadLetterCleanupRequest) (ports.AppendLogDeadLetterCleanupResult, error) {
	result, err := s.cleanupAppendLogDeadLetters(ctx, request)
	if err != nil {
		telemetry.IncrementMain(ctx, appendLogDeadLetterMetricKeys[5], 1)
		return ports.AppendLogDeadLetterCleanupResult{}, err
	}
	if len(result.DeletedIDs) == 0 {
		telemetry.IncrementMain(ctx, appendLogDeadLetterMetricKeys[4], 1)
	} else {
		telemetry.IncrementMain(ctx, appendLogDeadLetterMetricKeys[3], int64(len(result.DeletedIDs)))
	}
	return result, nil
}

func (s *Store) cleanupAppendLogDeadLetters(ctx context.Context, request ports.AppendLogDeadLetterCleanupRequest) (ports.AppendLogDeadLetterCleanupResult, error) {
	if s == nil || s.db == nil {
		return ports.AppendLogDeadLetterCleanupResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return ports.AppendLogDeadLetterCleanupResult{}, err
	}
	request.Actor = strings.TrimSpace(request.Actor)
	request.Reason = strings.TrimSpace(request.Reason)
	request.AfterID = strings.TrimSpace(request.AfterID)
	if request.TerminalBefore.IsZero() {
		return ports.AppendLogDeadLetterCleanupResult{}, errors.New("terminal retention cutoff is required")
	}
	if request.Actor == "" || request.Reason == "" {
		return ports.AppendLogDeadLetterCleanupResult{}, errors.New("cleanup actor and reason are required")
	}
	limit := appendLogDeadLetterCleanupDefaultLimit
	if request.Limit > 0 {
		if request.Limit > uint32(appendLogDeadLetterCleanupMaxLimit) {
			limit = appendLogDeadLetterCleanupMaxLimit
		} else {
			limit = int(request.Limit)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("begin append log dead letter cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, appendLogDeadLetterCleanupSelectSQL(), request.TerminalBefore.UTC(), request.AfterID, int64(limit)+1)
	if err != nil {
		return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("select append log dead letter cleanup batch: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("scan append log dead letter cleanup batch: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("iterate append log dead letter cleanup batch: %w", err)
	}
	if err := rows.Close(); err != nil {
		return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("close append log dead letter cleanup batch: %w", err)
	}
	hasMore := len(ids) > limit
	if len(ids) > limit {
		ids = ids[:limit]
	}
	result := ports.AppendLogDeadLetterCleanupResult{DeletedIDs: make([]string, 0, len(ids))}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO append_log_dead_letter_audit (dead_letter_id, action, actor, reason) VALUES ($1, 'retention_purge', $2, $3)`, id, request.Actor, request.Reason); err != nil {
			return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("audit append log dead letter %q cleanup: %w", id, err)
		}
		deleteResult, err := tx.ExecContext(ctx, `DELETE FROM append_log_dead_letters WHERE id = $1 AND status IN ('replayed', 'discarded') AND updated_at < $2`, id, request.TerminalBefore.UTC())
		if err != nil {
			return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("delete append log dead letter %q: %w", id, err)
		}
		deleted, err := deleteResult.RowsAffected()
		if err != nil {
			return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("delete append log dead letter %q rows affected: %w", id, err)
		}
		if deleted != 1 {
			return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("append log dead letter %q changed during cleanup", id)
		}
		result.DeletedIDs = append(result.DeletedIDs, id)
	}
	if len(result.DeletedIDs) > 0 {
		result.NextAfterID = result.DeletedIDs[len(result.DeletedIDs)-1]
	}
	result.HasMore = hasMore
	if err := tx.Commit(); err != nil {
		return ports.AppendLogDeadLetterCleanupResult{}, fmt.Errorf("commit append log dead letter cleanup: %w", err)
	}
	return result, nil
}

func appendLogDeadLetterCleanupSelectSQL() string {
	return `SELECT id
FROM append_log_dead_letters
WHERE status IN ('replayed', 'discarded')
  AND updated_at < $1
  AND id > $2
ORDER BY id ASC
LIMIT $3
FOR UPDATE SKIP LOCKED`
}

// ForcePurgeAppendLogDeadLetter deletes one explicitly identified pending
// recovery record. The audit write and payload deletion commit together.
func (s *Store) ForcePurgeAppendLogDeadLetter(ctx context.Context, request ports.AppendLogDeadLetterForcePurgeRequest) error {
	err := s.forcePurgeAppendLogDeadLetter(ctx, request)
	outcome := appendLogDeadLetterForcePurgeOutcome(err)
	telemetry.IncrementMain(ctx, appendLogDeadLetterForcePurgeMetricKeys[outcome], 1)
	telemetry.AnnotateMain(ctx, telemetry.Attrs(
		telemetry.Field{Key: "append_log.dead_letter.last_force_purge_outcome", Value: outcome},
	))
	return err
}

func (s *Store) forcePurgeAppendLogDeadLetter(ctx context.Context, request ports.AppendLogDeadLetterForcePurgeRequest) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return err
	}
	request.ID = strings.TrimSpace(request.ID)
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Actor = strings.TrimSpace(request.Actor)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.ID == "" || request.TenantID == "" || request.Actor == "" || request.Reason == "" {
		return errors.New("dead letter id, tenant id, authenticated actor, and reason are required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin append log dead letter forced purge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	var activeClaim bool
	err = tx.QueryRowContext(ctx, appendLogDeadLetterForcePurgeSelectSQL, request.ID, request.TenantID).Scan(&status, &activeClaim)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrAppendLogDeadLetterNotFound
	}
	if err != nil {
		return fmt.Errorf("lock append log dead letter forced purge target: %w", err)
	}
	if strings.TrimSpace(status) != ports.AppendLogDeadLetterStatusPending {
		return ports.ErrAppendLogDeadLetterNotPending
	}
	if activeClaim {
		return ports.ErrAppendLogDeadLetterReplayClaimed
	}
	if _, err := tx.ExecContext(ctx, appendLogDeadLetterAuditInsertSQL, request.ID, "forced_pending_purge", request.Actor, request.Reason); err != nil {
		return fmt.Errorf("audit append log dead letter forced purge: %w", err)
	}
	result, err := tx.ExecContext(ctx, appendLogDeadLetterForcePurgeDeleteSQL, request.ID, request.TenantID)
	if err != nil {
		return fmt.Errorf("delete append log dead letter forced purge target: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read append log dead letter forced purge result: %w", err)
	}
	if deleted != 1 {
		return fmt.Errorf("append log dead letter forced purge deleted %d records, want 1", deleted)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit append log dead letter forced purge: %w", err)
	}
	return nil
}

func appendLogDeadLetterForcePurgeOutcome(err error) string {
	switch {
	case err == nil:
		return "deleted"
	case errors.Is(err, ports.ErrAppendLogDeadLetterNotFound):
		return "not_found"
	case errors.Is(err, ports.ErrAppendLogDeadLetterNotPending):
		return "not_pending"
	case errors.Is(err, ports.ErrAppendLogDeadLetterReplayClaimed):
		return "active_claim"
	default:
		return "failed"
	}
}

func (s *Store) appendLogDeadLetterStatusConflict(ctx context.Context, id string, targetStatus string) error {
	var currentStatus string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM append_log_dead_letters WHERE id = $1`, id).Scan(&currentStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrAppendLogDeadLetterNotFound
	}
	if err != nil {
		return fmt.Errorf("query append log dead letter %q status: %w", id, err)
	}
	return appendLogDeadLetterTransitionConflictError(id, targetStatus, currentStatus)
}

func appendLogDeadLetterTransitionConflictError(id string, targetStatus string, currentStatus string) error {
	if strings.TrimSpace(targetStatus) == ports.AppendLogDeadLetterStatusReplayed && strings.TrimSpace(currentStatus) == ports.AppendLogDeadLetterStatusReplayed {
		return ports.ErrAppendLogDeadLetterAlreadyReplayed
	}
	return fmt.Errorf("append log dead letter %q has status %q", id, currentStatus)
}

func appendLogDeadLetterSelectSQL() string {
	return `SELECT ` + appendLogDeadLetterColumns() + ` FROM append_log_dead_letters`
}

func appendLogDeadLetterColumns() string {
	return `id, status, subject, operation, event_id, event_kind, tenant_id, source_id,
       runtime_id, job_id, error_category, error_message, retry_count, max_attempts,
       payload_hash, payload_bytes, event_json, created_at, updated_at, replayed_at,
       discarded_at, discard_reason, replay_owner, replay_token, replay_lease_expires_at,
       replay_attempt_count, last_replay_started_at, last_replay_finished_at,
       last_replay_error_category`
}

func appendLogDeadLetterListQuery(filter ports.AppendLogDeadLetterFilter) (string, []any) {
	normalized := normalizeAppendLogDeadLetterFilter(filter)
	var (
		where []string
		args  []any
	)
	if normalized.Status != "" && normalized.Status != "all" {
		args = append(args, normalized.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if normalized.Subject != "" {
		args = append(args, normalized.Subject)
		where = append(where, fmt.Sprintf("subject = $%d", len(args)))
	}
	if normalized.RuntimeID != "" {
		args = append(args, normalized.RuntimeID)
		where = append(where, fmt.Sprintf("runtime_id = $%d", len(args)))
	}
	if normalized.SourceID != "" {
		args = append(args, normalized.SourceID)
		where = append(where, fmt.Sprintf("source_id = $%d", len(args)))
	}
	if len(where) == 0 {
		where = append(where, "TRUE")
	}
	args = append(args, int64(normalized.Limit))
	return appendLogDeadLetterSelectSQL() + " WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY updated_at ASC, id ASC LIMIT $%d", len(args)), args
}

func normalizeAppendLogDeadLetterFilter(filter ports.AppendLogDeadLetterFilter) ports.AppendLogDeadLetterFilter {
	filter.Status = strings.TrimSpace(filter.Status)
	if filter.Status == "" {
		filter.Status = ports.AppendLogDeadLetterStatusPending
	}
	filter.Subject = strings.TrimSpace(filter.Subject)
	filter.RuntimeID = strings.TrimSpace(filter.RuntimeID)
	filter.SourceID = strings.TrimSpace(filter.SourceID)
	if filter.Limit == 0 {
		filter.Limit = appendLogDeadLetterDefaultLimit
	}
	if filter.Limit > appendLogDeadLetterMaxLimit {
		filter.Limit = appendLogDeadLetterMaxLimit
	}
	return filter
}

func normalizeAppendLogDeadLetter(record ports.AppendLogDeadLetter) ports.AppendLogDeadLetter {
	record.ID = strings.TrimSpace(record.ID)
	record.Status = strings.TrimSpace(record.Status)
	if record.Status == "" {
		record.Status = ports.AppendLogDeadLetterStatusPending
	}
	record.Subject = strings.TrimSpace(record.Subject)
	record.Operation = strings.TrimSpace(record.Operation)
	if record.Operation == "" {
		record.Operation = "append"
	}
	record.EventID = strings.TrimSpace(record.EventID)
	record.EventKind = strings.TrimSpace(record.EventKind)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.RuntimeID = strings.TrimSpace(record.RuntimeID)
	record.JobID = strings.TrimSpace(record.JobID)
	record.ErrorCategory = strings.TrimSpace(record.ErrorCategory)
	record.ErrorMessage = strings.TrimSpace(record.ErrorMessage)
	record.PayloadHash = strings.TrimSpace(record.PayloadHash)
	if record.PayloadBytes < 0 {
		record.PayloadBytes = 0
	}
	return record
}

func validateAppendLogDeadLetter(record ports.AppendLogDeadLetter) error {
	if record.ID == "" {
		return errors.New("append log dead letter id is required")
	}
	switch record.Status {
	case ports.AppendLogDeadLetterStatusPending, ports.AppendLogDeadLetterStatusReplayed, ports.AppendLogDeadLetterStatusDiscarded:
	default:
		return fmt.Errorf("unsupported append log dead letter status %q", record.Status)
	}
	if record.Subject == "" {
		return errors.New("append log dead letter subject is required")
	}
	if record.EventID == "" {
		return errors.New("append log dead letter event id is required")
	}
	if record.EventKind == "" {
		return errors.New("append log dead letter event kind is required")
	}
	if record.PayloadHash == "" {
		return errors.New("append log dead letter payload hash is required")
	}
	if record.Event == nil {
		return errors.New("append log dead letter event is required")
	}
	return nil
}

type appendLogDeadLetterScanner interface {
	Scan(dest ...any) error
}

func scanAppendLogDeadLetter(scanner appendLogDeadLetterScanner) (ports.AppendLogDeadLetter, error) {
	var (
		record               ports.AppendLogDeadLetter
		eventJSON            []byte
		createdAt            time.Time
		updatedAt            time.Time
		replayedAt           sql.NullTime
		discardedAt          sql.NullTime
		replayLeaseExpiresAt sql.NullTime
		lastReplayStartedAt  sql.NullTime
		lastReplayFinishedAt sql.NullTime
		discardReason        string
	)
	if err := scanner.Scan(
		&record.ID,
		&record.Status,
		&record.Subject,
		&record.Operation,
		&record.EventID,
		&record.EventKind,
		&record.TenantID,
		&record.SourceID,
		&record.RuntimeID,
		&record.JobID,
		&record.ErrorCategory,
		&record.ErrorMessage,
		&record.RetryCount,
		&record.MaxAttempts,
		&record.PayloadHash,
		&record.PayloadBytes,
		&eventJSON,
		&createdAt,
		&updatedAt,
		&replayedAt,
		&discardedAt,
		&discardReason,
		&record.Replay.Owner,
		&record.Replay.Token,
		&replayLeaseExpiresAt,
		&record.Replay.AttemptCount,
		&lastReplayStartedAt,
		&lastReplayFinishedAt,
		&record.Replay.LastErrorCategory,
	); err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	var event cerebrov1.EventEnvelope
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(eventJSON, &event); err != nil {
		return ports.AppendLogDeadLetter{}, fmt.Errorf("unmarshal append log dead letter event %q: %w", record.ID, err)
	}
	record.Event = &event
	record.CreatedAt = createdAt
	record.UpdatedAt = updatedAt
	if replayedAt.Valid {
		record.ReplayedAt = replayedAt.Time
	}
	if discardedAt.Valid {
		record.DiscardedAt = discardedAt.Time
	}
	record.DiscardReason = strings.TrimSpace(discardReason)
	record.Replay.Owner = strings.TrimSpace(record.Replay.Owner)
	record.Replay.Token = strings.TrimSpace(record.Replay.Token)
	record.Replay.LastErrorCategory = strings.TrimSpace(record.Replay.LastErrorCategory)
	if replayLeaseExpiresAt.Valid {
		record.Replay.LeaseExpiresAt = replayLeaseExpiresAt.Time
	}
	if lastReplayStartedAt.Valid {
		record.Replay.LastStartedAt = lastReplayStartedAt.Time
	}
	if lastReplayFinishedAt.Valid {
		record.Replay.LastFinishedAt = lastReplayFinishedAt.Time
	}
	return record, nil
}

func (s *Store) ensureAppendLogDeadLetterTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureStatements(ctx, &s.appendLog.deadLetters, "append_log_dead_letters", ensureAppendLogDeadLetterStatements)
}

var _ ports.AppendLogDeadLetterStore = (*Store)(nil)
var _ ports.AppendLogDeadLetterForcePurgeStore = (*Store)(nil)
