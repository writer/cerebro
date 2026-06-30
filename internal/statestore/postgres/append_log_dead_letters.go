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
	"github.com/writer/cerebro/internal/ports"
)

const appendLogDeadLetterDefaultLimit = uint32(50)
const appendLogDeadLetterMaxLimit = uint32(500)

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
  discard_reason TEXT NOT NULL DEFAULT ''
)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_status_updated_idx ON append_log_dead_letters (status, updated_at ASC, id ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_subject_status_idx ON append_log_dead_letters (subject, status, updated_at ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_runtime_status_idx ON append_log_dead_letters (runtime_id, status, updated_at ASC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS append_log_dead_letters_source_status_idx ON append_log_dead_letters (source_id, status, updated_at ASC)`,
}

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
	_, err = s.db.ExecContext(ctx, `
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
              discard_reason = ''`,
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
	return nil
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

func (s *Store) MarkAppendLogDeadLetterReplayed(ctx context.Context, id string) error {
	return s.updateAppendLogDeadLetterStatus(ctx, id, ports.AppendLogDeadLetterStatusReplayed, "")
}

func (s *Store) DiscardAppendLogDeadLetter(ctx context.Context, id string, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("discard reason is required")
	}
	return s.updateAppendLogDeadLetterStatus(ctx, id, ports.AppendLogDeadLetterStatusDiscarded, reason)
}

func (s *Store) updateAppendLogDeadLetterStatus(ctx context.Context, id string, status string, reason string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogDeadLetterTables(ctx); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("append log dead letter id is required")
	}
	status = strings.TrimSpace(status)
	var (
		query string
		args  []any
	)
	switch status {
	case ports.AppendLogDeadLetterStatusReplayed:
		query = `UPDATE append_log_dead_letters SET status = $2, updated_at = NOW(), replayed_at = NOW() WHERE id = $1 AND status = 'pending'`
		args = []any{id, status}
	case ports.AppendLogDeadLetterStatusDiscarded:
		query = `UPDATE append_log_dead_letters SET status = $2, updated_at = NOW(), discarded_at = NOW(), discard_reason = $3 WHERE id = $1 AND status = 'pending'`
		args = []any{id, status, strings.TrimSpace(reason)}
	default:
		return fmt.Errorf("unsupported append log dead letter status %q", status)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update append log dead letter %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update append log dead letter %q rows affected: %w", id, err)
	}
	if rows == 0 {
		return ports.ErrAppendLogDeadLetterNotFound
	}
	return nil
}

func appendLogDeadLetterSelectSQL() string {
	return `SELECT id, status, subject, operation, event_id, event_kind, tenant_id, source_id,
       runtime_id, job_id, error_category, error_message, retry_count, max_attempts,
       payload_hash, payload_bytes, event_json, created_at, updated_at, replayed_at,
       discarded_at, discard_reason
FROM append_log_dead_letters`
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
		record        ports.AppendLogDeadLetter
		eventJSON     []byte
		createdAt     time.Time
		updatedAt     time.Time
		replayedAt    sql.NullTime
		discardedAt   sql.NullTime
		discardReason string
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
	return record, nil
}

func (s *Store) ensureAppendLogDeadLetterTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureStatements(ctx, &s.appendLog.deadLetters, "append_log_dead_letters", ensureAppendLogDeadLetterStatements)
}

var _ ports.AppendLogDeadLetterStore = (*Store)(nil)
