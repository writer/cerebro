package jobs

import (
	"context"
	"time"
)

// IdempotencyStore tracks processed message IDs to prevent duplicate processing.
type IdempotencyStore interface {
	// MarkProcessing attempts to mark a message as being processed.
	// Returns true if this is the first time seeing this message.
	// Returns false if the message was already processed or is being processed.
	MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error)

	// MarkCompleted marks a message as successfully processed.
	MarkCompleted(ctx context.Context, messageID string) error

	// MarkFailed removes the processing lock so the message can be retried.
	MarkFailed(ctx context.Context, messageID string) error

	// IsProcessed checks if a message was already successfully processed.
	IsProcessed(ctx context.Context, messageID string) (bool, error)
}

const (
	idempotencyStatusProcessing = "processing"
	idempotencyStatusCompleted  = "completed"
)

// NoOpIdempotencyStore is a no-op implementation for testing or when idempotency is disabled.
type NoOpIdempotencyStore struct{}

func (s *NoOpIdempotencyStore) MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error) {
	return true, nil
}
func (s *NoOpIdempotencyStore) MarkCompleted(ctx context.Context, messageID string) error {
	return nil
}
func (s *NoOpIdempotencyStore) MarkFailed(ctx context.Context, messageID string) error {
	return nil
}
func (s *NoOpIdempotencyStore) IsProcessed(ctx context.Context, messageID string) (bool, error) {
	return false, nil
}
