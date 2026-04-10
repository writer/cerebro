package jobs

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestPostgresIdempotencyStore(t *testing.T) *PostgresIdempotencyStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := NewPostgresIdempotencyStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return store
}

func TestPostgresIdempotencyStore_EnsureSchema(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)

	// Calling EnsureSchema again should be idempotent.
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("second EnsureSchema call failed: %v", err)
	}
}

func TestPostgresIdempotencyStore_MarkProcessing(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	ok, err := store.MarkProcessing(ctx, "msg-1", "worker-a", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if !ok {
		t.Fatal("expected MarkProcessing to return true for new message")
	}
}

func TestPostgresIdempotencyStore_MarkProcessingEmptyID(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	_, err := store.MarkProcessing(ctx, "", "worker-a", 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for empty message ID")
	}
}

func TestPostgresIdempotencyStore_DuplicateProcessingPrevention(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	ok, err := store.MarkProcessing(ctx, "msg-dup", "worker-a", 5*time.Minute)
	if err != nil {
		t.Fatalf("first MarkProcessing: %v", err)
	}
	if !ok {
		t.Fatal("expected first MarkProcessing to return true")
	}

	// Second call with a different worker should return false (already being processed).
	ok, err = store.MarkProcessing(ctx, "msg-dup", "worker-b", 5*time.Minute)
	if err != nil {
		t.Fatalf("second MarkProcessing: %v", err)
	}
	if ok {
		t.Fatal("expected second MarkProcessing to return false for duplicate message")
	}
}

func TestPostgresIdempotencyStore_CompletedMessageBlocking(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	ok, err := store.MarkProcessing(ctx, "msg-complete", "worker-a", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if !ok {
		t.Fatal("expected MarkProcessing to return true")
	}

	if err := store.MarkCompleted(ctx, "msg-complete"); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}

	// Attempting to process a completed message should return false.
	ok, err = store.MarkProcessing(ctx, "msg-complete", "worker-b", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing after completed: %v", err)
	}
	if ok {
		t.Fatal("expected MarkProcessing to return false for completed message")
	}
}

func TestPostgresIdempotencyStore_ExpiredRecordReplacement(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	// Insert a normal processing record.
	ok, err := store.MarkProcessing(ctx, "msg-expired", "worker-a", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if !ok {
		t.Fatal("expected initial MarkProcessing to return true")
	}

	// Force the record to be expired by setting expires_at to the past.
	_, err = store.db.ExecContext(ctx,
		`UPDATE job_idempotency SET expires_at = $1 WHERE message_id = $2`,
		time.Now().UTC().Unix()-10, "msg-expired",
	)
	if err != nil {
		t.Fatalf("force expiry: %v", err)
	}

	// A new worker should be able to take over the expired record.
	ok, err = store.MarkProcessing(ctx, "msg-expired", "worker-b", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing after expiry: %v", err)
	}
	if !ok {
		t.Fatal("expected MarkProcessing to return true for expired record")
	}
}

func TestPostgresIdempotencyStore_MarkFailedAllowsRetry(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	ok, err := store.MarkProcessing(ctx, "msg-fail", "worker-a", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if !ok {
		t.Fatal("expected MarkProcessing to return true")
	}

	if err := store.MarkFailed(ctx, "msg-fail"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	// After failure, a new attempt should succeed.
	ok, err = store.MarkProcessing(ctx, "msg-fail", "worker-b", 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkProcessing after MarkFailed: %v", err)
	}
	if !ok {
		t.Fatal("expected MarkProcessing to return true after MarkFailed")
	}
}

func TestPostgresIdempotencyStore_IsProcessed(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	// Unknown message should not be processed.
	processed, err := store.IsProcessed(ctx, "msg-unknown")
	if err != nil {
		t.Fatalf("IsProcessed: %v", err)
	}
	if processed {
		t.Fatal("expected IsProcessed to return false for unknown message")
	}

	// A message that is still processing should not be considered processed.
	ok, err := store.MarkProcessing(ctx, "msg-check", "worker-a", 5*time.Minute)
	if err != nil || !ok {
		t.Fatalf("MarkProcessing: ok=%v err=%v", ok, err)
	}
	processed, err = store.IsProcessed(ctx, "msg-check")
	if err != nil {
		t.Fatalf("IsProcessed for processing message: %v", err)
	}
	if processed {
		t.Fatal("expected IsProcessed to return false for processing message")
	}

	// After completing, message should be processed.
	if err := store.MarkCompleted(ctx, "msg-check"); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	processed, err = store.IsProcessed(ctx, "msg-check")
	if err != nil {
		t.Fatalf("IsProcessed for completed message: %v", err)
	}
	if !processed {
		t.Fatal("expected IsProcessed to return true for completed message")
	}
}

func TestPostgresIdempotencyStore_IsProcessedEmptyID(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	_, err := store.IsProcessed(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty message ID")
	}
}

func TestPostgresIdempotencyStore_MarkCompletedEmptyID(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	if err := store.MarkCompleted(ctx, ""); err == nil {
		t.Fatal("expected error for empty message ID")
	}
}

func TestPostgresIdempotencyStore_MarkFailedEmptyID(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	if err := store.MarkFailed(ctx, ""); err == nil {
		t.Fatal("expected error for empty message ID")
	}
}

func TestPostgresIdempotencyStore_CleanupExpired(t *testing.T) {
	store := newTestPostgresIdempotencyStore(t)
	ctx := context.Background()

	// Insert two records with normal TTLs.
	ok, err := store.MarkProcessing(ctx, "msg-old", "worker-a", 5*time.Minute)
	if err != nil || !ok {
		t.Fatalf("MarkProcessing (old): ok=%v err=%v", ok, err)
	}
	ok, err = store.MarkProcessing(ctx, "msg-new", "worker-a", 1*time.Hour)
	if err != nil || !ok {
		t.Fatalf("MarkProcessing (new): ok=%v err=%v", ok, err)
	}

	// Force the "old" record to be expired.
	_, err = store.db.ExecContext(ctx,
		`UPDATE job_idempotency SET expires_at = $1 WHERE message_id = $2`,
		time.Now().UTC().Unix()-10, "msg-old",
	)
	if err != nil {
		t.Fatalf("force expiry: %v", err)
	}

	if err := store.CleanupExpired(ctx); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}

	// The expired record should be gone.
	var count int
	err = store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM job_idempotency WHERE message_id = $1`, "msg-old",
	).Scan(&count)
	if err != nil {
		t.Fatalf("check old record: %v", err)
	}
	if count != 0 {
		t.Fatal("expected expired record to be cleaned up")
	}

	// The non-expired record should still exist.
	err = store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM job_idempotency WHERE message_id = $1`, "msg-new",
	).Scan(&count)
	if err != nil {
		t.Fatalf("check new record: %v", err)
	}
	if count != 1 {
		t.Fatal("expected non-expired record to still exist")
	}
}
