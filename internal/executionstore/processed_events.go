package executionstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ProcessedEventRecord struct {
	Namespace      string
	EventKey       string
	Status         string
	PayloadHash    string
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	ProcessedAt    time.Time
	ExpiresAt      time.Time
	DuplicateCount int
}

const (
	ProcessedEventStatusProcessing = "processing"
	ProcessedEventStatusProcessed  = "processed"
)

func (s *SQLiteStore) LookupProcessedEvent(ctx context.Context, namespace, eventKey string, observedAt time.Time) (*ProcessedEventRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	eventKey = strings.TrimSpace(eventKey)
	if namespace == "" || eventKey == "" {
		return nil, fmt.Errorf("processed event namespace and key are required")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin processed event lookup tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, namespace, observedAt); err != nil {
		return nil, fmt.Errorf("prune expired processed events: %w", err)
	}

	var record ProcessedEventRecord
	err = tx.QueryRowContext(ctx, `
		SELECT namespace, event_key, status, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		FROM processed_events
		WHERE namespace = ? AND event_key = ?
	`, namespace, eventKey).Scan(
		&record.Namespace,
		&record.EventKey,
		&record.Status,
		&record.PayloadHash,
		&record.FirstSeenAt,
		&record.LastSeenAt,
		&record.ProcessedAt,
		&record.ExpiresAt,
		&record.DuplicateCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit processed event lookup: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load processed event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit processed event lookup: %w", err)
	}
	return &record, nil
}

func (s *SQLiteStore) TouchProcessedEvent(ctx context.Context, namespace, eventKey string, observedAt time.Time, ttl time.Duration) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	eventKey = strings.TrimSpace(eventKey)
	if namespace == "" || eventKey == "" {
		return fmt.Errorf("processed event namespace and key are required")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}
	if ttl <= 0 {
		return fmt.Errorf("processed event ttl must be > 0")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin processed event touch tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, namespace, observedAt); err != nil {
		return fmt.Errorf("prune expired processed events: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE processed_events
		SET last_seen_at = ?,
			expires_at = ?,
			duplicate_count = duplicate_count + 1
		WHERE namespace = ? AND event_key = ?
	`, observedAt, observedAt.Add(ttl), namespace, eventKey)
	if err != nil {
		return fmt.Errorf("touch processed event: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read touched processed event rows: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("processed event %s/%s not found", namespace, eventKey)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit processed event touch: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ClaimProcessedEvent(ctx context.Context, record ProcessedEventRecord, maxRecords int) (bool, *ProcessedEventRecord, error) {
	if s == nil || s.db == nil {
		return true, nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	record.Namespace = strings.TrimSpace(record.Namespace)
	record.EventKey = strings.TrimSpace(record.EventKey)
	record.PayloadHash = strings.TrimSpace(record.PayloadHash)
	record.Status = strings.TrimSpace(record.Status)
	if record.Namespace == "" || record.EventKey == "" {
		return false, nil, fmt.Errorf("processed event namespace and key are required")
	}
	if record.Status == "" {
		record.Status = ProcessedEventStatusProcessing
	}
	claimAt := time.Now().UTC()
	if record.FirstSeenAt.IsZero() {
		record.FirstSeenAt = claimAt
	} else {
		record.FirstSeenAt = record.FirstSeenAt.UTC()
	}
	if record.LastSeenAt.IsZero() {
		record.LastSeenAt = record.FirstSeenAt
	} else {
		record.LastSeenAt = record.LastSeenAt.UTC()
	}
	if record.ProcessedAt.IsZero() {
		record.ProcessedAt = claimAt
	} else {
		record.ProcessedAt = record.ProcessedAt.UTC()
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = claimAt
	} else {
		record.ExpiresAt = record.ExpiresAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, fmt.Errorf("begin processed event claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, record.Namespace, claimAt); err != nil {
		return false, nil, fmt.Errorf("prune expired processed events: %w", err)
	}

	var existing ProcessedEventRecord
	err = tx.QueryRowContext(ctx, `
		SELECT namespace, event_key, status, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		FROM processed_events
		WHERE namespace = ? AND event_key = ?
	`, record.Namespace, record.EventKey).Scan(
		&existing.Namespace,
		&existing.EventKey,
		&existing.Status,
		&existing.PayloadHash,
		&existing.FirstSeenAt,
		&existing.LastSeenAt,
		&existing.ProcessedAt,
		&existing.ExpiresAt,
		&existing.DuplicateCount,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, nil, fmt.Errorf("load processed event for claim: %w", err)
	}

	claimed := false
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO processed_events (
				namespace, event_key, status, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, record.Namespace, record.EventKey, record.Status, record.PayloadHash, record.FirstSeenAt, record.LastSeenAt, record.ProcessedAt, record.ExpiresAt, record.DuplicateCount); err != nil {
			return false, nil, fmt.Errorf("insert processed event claim: %w", err)
		}
		claimed = true
	} else {
		existing.PayloadHash = strings.TrimSpace(existing.PayloadHash)
		if record.PayloadHash == "" || existing.PayloadHash == "" || existing.PayloadHash != record.PayloadHash {
			if strings.TrimSpace(existing.Status) == ProcessedEventStatusProcessing {
				if err := tx.Commit(); err != nil {
					return false, nil, fmt.Errorf("commit processed event claim: %w", err)
				}
				return false, &existing, nil
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE processed_events
				SET status = ?, payload_hash = ?, first_seen_at = ?, last_seen_at = ?, processed_at = ?, expires_at = ?, duplicate_count = ?
				WHERE namespace = ? AND event_key = ?
			`, record.Status, record.PayloadHash, existing.FirstSeenAt, record.LastSeenAt, record.ProcessedAt, record.ExpiresAt, record.DuplicateCount, record.Namespace, record.EventKey); err != nil {
				return false, nil, fmt.Errorf("replace processed event claim: %w", err)
			}
			claimed = true
			existing = ProcessedEventRecord{}
		}
	}

	if maxRecords > 0 && claimed {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM processed_events
			WHERE namespace = ?
			  AND event_key IN (
				SELECT event_key
				FROM processed_events
				WHERE namespace = ?
				ORDER BY processed_at DESC, event_key DESC
				LIMIT -1 OFFSET ?
			  )
		`, record.Namespace, record.Namespace, maxRecords); err != nil {
			return false, nil, fmt.Errorf("trim processed events: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("commit processed event claim: %w", err)
	}
	if claimed {
		return true, nil, nil
	}
	return false, &existing, nil
}

func (s *SQLiteStore) TryClaimProcessedEvent(ctx context.Context, record ProcessedEventRecord, maxRecords int) (bool, error) {
	if s == nil || s.db == nil {
		return true, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	record.Namespace = strings.TrimSpace(record.Namespace)
	record.EventKey = strings.TrimSpace(record.EventKey)
	record.PayloadHash = strings.TrimSpace(record.PayloadHash)
	record.Status = strings.TrimSpace(record.Status)
	if record.Namespace == "" || record.EventKey == "" {
		return false, fmt.Errorf("processed event namespace and key are required")
	}
	if record.Status == "" {
		record.Status = ProcessedEventStatusProcessing
	}
	claimAt := time.Now().UTC()
	if record.FirstSeenAt.IsZero() {
		record.FirstSeenAt = claimAt
	} else {
		record.FirstSeenAt = record.FirstSeenAt.UTC()
	}
	if record.LastSeenAt.IsZero() {
		record.LastSeenAt = record.FirstSeenAt
	} else {
		record.LastSeenAt = record.LastSeenAt.UTC()
	}
	if record.ProcessedAt.IsZero() {
		record.ProcessedAt = claimAt
	} else {
		record.ProcessedAt = record.ProcessedAt.UTC()
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = claimAt
	} else {
		record.ExpiresAt = record.ExpiresAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin processed event fast claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, record.Namespace, claimAt); err != nil {
		return false, fmt.Errorf("prune expired processed events: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO processed_events (
			namespace, event_key, status, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.Namespace, record.EventKey, record.Status, record.PayloadHash, record.FirstSeenAt, record.LastSeenAt, record.ProcessedAt, record.ExpiresAt, record.DuplicateCount)
	if err != nil {
		return false, fmt.Errorf("insert processed event fast claim: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read processed event fast claim rows: %w", err)
	}
	claimed := rowsAffected > 0

	if maxRecords > 0 && claimed {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM processed_events
			WHERE namespace = ?
			  AND event_key IN (
				SELECT event_key
				FROM processed_events
				WHERE namespace = ?
				ORDER BY processed_at DESC, event_key DESC
				LIMIT -1 OFFSET ?
			  )
		`, record.Namespace, record.Namespace, maxRecords); err != nil {
			return false, fmt.Errorf("trim processed events: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit processed event fast claim: %w", err)
	}
	return claimed, nil
}

func (s *SQLiteStore) ListActiveProcessedEventKeys(ctx context.Context, namespace string, observedAt time.Time, limit int) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("processed event namespace is required")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin processed event list tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, namespace, observedAt); err != nil {
		return nil, fmt.Errorf("prune expired processed events: %w", err)
	}

	query := `
		SELECT event_key
		FROM processed_events
		WHERE namespace = ?
		ORDER BY processed_at DESC, event_key DESC
	`
	args := []any{namespace}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list processed event keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	keys := make([]string, 0)
	for rows.Next() {
		var eventKey string
		if err := rows.Scan(&eventKey); err != nil {
			return nil, fmt.Errorf("scan processed event key: %w", err)
		}
		keys = append(keys, eventKey)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate processed event keys: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit processed event list: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) RememberProcessedEvent(ctx context.Context, record ProcessedEventRecord, maxRecords int) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	record.Namespace = strings.TrimSpace(record.Namespace)
	record.EventKey = strings.TrimSpace(record.EventKey)
	record.Status = strings.TrimSpace(record.Status)
	record.PayloadHash = strings.TrimSpace(record.PayloadHash)
	if record.Namespace == "" || record.EventKey == "" {
		return fmt.Errorf("processed event namespace and key are required")
	}
	if record.Status == "" {
		record.Status = ProcessedEventStatusProcessed
	}
	if record.FirstSeenAt.IsZero() {
		record.FirstSeenAt = time.Now().UTC()
	} else {
		record.FirstSeenAt = record.FirstSeenAt.UTC()
	}
	if record.LastSeenAt.IsZero() {
		record.LastSeenAt = record.FirstSeenAt
	} else {
		record.LastSeenAt = record.LastSeenAt.UTC()
	}
	if record.ProcessedAt.IsZero() {
		record.ProcessedAt = record.LastSeenAt
	} else {
		record.ProcessedAt = record.ProcessedAt.UTC()
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.ProcessedAt
	} else {
		record.ExpiresAt = record.ExpiresAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin processed event remember tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, record.Namespace, record.ProcessedAt); err != nil {
		return fmt.Errorf("prune expired processed events: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO processed_events (
			namespace, event_key, status, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, event_key) DO UPDATE SET
			status = excluded.status,
			payload_hash = excluded.payload_hash,
			last_seen_at = excluded.last_seen_at,
			processed_at = excluded.processed_at,
			expires_at = excluded.expires_at
	`, record.Namespace, record.EventKey, record.Status, record.PayloadHash, record.FirstSeenAt, record.LastSeenAt, record.ProcessedAt, record.ExpiresAt, record.DuplicateCount); err != nil {
		return fmt.Errorf("persist processed event: %w", err)
	}

	if maxRecords > 0 {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM processed_events
			WHERE namespace = ?
			  AND event_key IN (
				SELECT event_key
				FROM processed_events
				WHERE namespace = ?
				ORDER BY processed_at DESC, event_key DESC
				LIMIT -1 OFFSET ?
			  )
		`, record.Namespace, record.Namespace, maxRecords); err != nil {
			return fmt.Errorf("trim processed events: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit processed event remember: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteProcessedEvent(ctx context.Context, namespace, eventKey string) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	eventKey = strings.TrimSpace(eventKey)
	if namespace == "" || eventKey == "" {
		return fmt.Errorf("processed event namespace and key are required")
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND event_key = ?
	`, namespace, eventKey); err != nil {
		return fmt.Errorf("delete processed event: %w", err)
	}
	return nil
}
