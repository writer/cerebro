package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Compile-time check that PostgresIdempotencyStore implements IdempotencyStore.
var _ IdempotencyStore = (*PostgresIdempotencyStore)(nil)

// PostgresIdempotencyStore implements IdempotencyStore using PostgreSQL.
type PostgresIdempotencyStore struct {
	db *sql.DB
}

// NewPostgresIdempotencyStore creates a new Postgres-backed idempotency store.
func NewPostgresIdempotencyStore(db *sql.DB) *PostgresIdempotencyStore {
	return &PostgresIdempotencyStore{db: db}
}

// EnsureSchema creates the idempotency table if it does not already exist.
func (s *PostgresIdempotencyStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS job_idempotency (
			message_id  TEXT PRIMARY KEY,
			status      TEXT NOT NULL DEFAULT 'processing',
			worker_id   TEXT NOT NULL DEFAULT '',
			processed_at BIGINT NOT NULL DEFAULT 0,
			expires_at  BIGINT NOT NULL DEFAULT 0
		)
	`)
	return err
}

// MarkProcessing attempts to mark a message as being processed.
// Returns true if this is the first time seeing this message (or the previous
// record expired). Returns false if the message was already completed or is
// currently being processed by another worker.
func (s *PostgresIdempotencyStore) MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error) {
	if messageID == "" {
		return false, fmt.Errorf("message ID required")
	}

	now := time.Now().UTC().Unix()
	expiresAt := now + int64(ttl.Seconds())

	// Attempt to insert a new record. ON CONFLICT DO NOTHING avoids errors
	// when the message_id already exists.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO job_idempotency (message_id, status, worker_id, processed_at, expires_at)
		 VALUES ($1, 'processing', $2, $3, $4)
		 ON CONFLICT (message_id) DO NOTHING`,
		messageID, workerID, now, expiresAt,
	)
	if err != nil {
		return false, fmt.Errorf("insert idempotency record: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check rows affected: %w", err)
	}
	if rows > 0 {
		// Fresh insert – we own this message.
		return true, nil
	}

	// Row already exists. Check whether it is completed or still live.
	var status string
	var existingExpiry int64
	err = s.db.QueryRowContext(ctx,
		`SELECT status, expires_at FROM job_idempotency WHERE message_id = $1`,
		messageID,
	).Scan(&status, &existingExpiry)
	if err != nil {
		return false, fmt.Errorf("check existing idempotency record: %w", err)
	}

	// If the record is completed, do not allow re-processing.
	if status == idempotencyStatusCompleted {
		return false, nil
	}

	// If the record is not completed and has expired, take it over.
	if existingExpiry < now {
		_, err = s.db.ExecContext(ctx,
			`UPDATE job_idempotency
			 SET status = 'processing', worker_id = $1, processed_at = $2, expires_at = $3
			 WHERE message_id = $4`,
			workerID, now, expiresAt, messageID,
		)
		if err != nil {
			return false, fmt.Errorf("replace expired idempotency record: %w", err)
		}
		return true, nil
	}

	// Record exists, not completed, and not expired – another worker owns it.
	return false, nil
}

// MarkCompleted marks a message as successfully processed.
// The record is kept for 24 hours for debugging/auditing before cleanup.
func (s *PostgresIdempotencyStore) MarkCompleted(ctx context.Context, messageID string) error {
	if messageID == "" {
		return fmt.Errorf("message ID required")
	}

	now := time.Now().UTC().Unix()
	expiresAt := now + 24*60*60

	_, err := s.db.ExecContext(ctx,
		`UPDATE job_idempotency SET status = 'completed', processed_at = $1, expires_at = $2 WHERE message_id = $3`,
		now, expiresAt, messageID,
	)
	return err
}

// MarkFailed removes the processing lock so the message can be retried.
func (s *PostgresIdempotencyStore) MarkFailed(ctx context.Context, messageID string) error {
	if messageID == "" {
		return fmt.Errorf("message ID required")
	}

	_, err := s.db.ExecContext(ctx,
		`DELETE FROM job_idempotency WHERE message_id = $1`,
		messageID,
	)
	return err
}

// IsProcessed checks if a message was already successfully processed.
func (s *PostgresIdempotencyStore) IsProcessed(ctx context.Context, messageID string) (bool, error) {
	if messageID == "" {
		return false, fmt.Errorf("message ID required")
	}

	var status string
	err := s.db.QueryRowContext(ctx,
		`SELECT status FROM job_idempotency WHERE message_id = $1`,
		messageID,
	).Scan(&status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return status == idempotencyStatusCompleted, nil
}

// CleanupExpired removes expired idempotency records. Should be called
// periodically (e.g. via a scheduled goroutine) to prevent unbounded growth.
func (s *PostgresIdempotencyStore) CleanupExpired(ctx context.Context) error {
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM job_idempotency WHERE expires_at < $1 AND expires_at > 0`,
		now,
	)
	return err
}
