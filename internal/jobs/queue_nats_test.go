package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Compile-time interface satisfaction check.
var _ Queue = (*NATSQueue)(nil)

// ---------------------------------------------------------------------------
// Deduplication ID generation (reuses the package-level helper)
// ---------------------------------------------------------------------------

func TestNATSDeduplicationIDForMessage_DefaultsToUnique(t *testing.T) {
	now := time.Unix(1_700_000_000, 123456789)
	msg := JobMessage{JobID: "nats-job-1", Attempt: 0}

	got := deduplicationIDForMessage(msg, now)
	want := "nats-job-1:0:1700000000123456789"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNATSDeduplicationIDForMessage_OverridesJobIDOnRetry(t *testing.T) {
	now := time.Unix(1_700_000_100, 987654321)
	msg := JobMessage{JobID: "nats-job-2", Attempt: 3, DeduplicationID: "nats-job-2"}

	got := deduplicationIDForMessage(msg, now)
	want := "nats-job-2:3:1700000100987654321"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNATSDeduplicationIDForMessage_RespectsCustomID(t *testing.T) {
	now := time.Unix(1_700_000_200, 555555555)
	msg := JobMessage{JobID: "nats-job-3", Attempt: 1, DeduplicationID: "my-custom-id"}

	got := deduplicationIDForMessage(msg, now)
	if got != "my-custom-id" {
		t.Fatalf("expected custom deduplication id, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Receipt handle mapping logic
// ---------------------------------------------------------------------------

func TestNATSQueue_ReceiptHandleMapping(t *testing.T) {
	// Verify that the pending sync.Map correctly stores and retrieves entries.
	q := &NATSQueue{}

	// Simulate storing a handle.
	handle := "test-handle-abc"
	q.pending.Store(handle, "placeholder")

	// Lookup should succeed.
	v, ok := q.pending.Load(handle)
	if !ok {
		t.Fatal("expected to find handle in pending map")
	}
	if v.(string) != "placeholder" {
		t.Fatalf("unexpected value: %v", v)
	}

	// LoadAndDelete should remove the entry.
	v, ok = q.pending.LoadAndDelete(handle)
	if !ok {
		t.Fatal("expected LoadAndDelete to succeed")
	}
	if v.(string) != "placeholder" {
		t.Fatalf("unexpected value after LoadAndDelete: %v", v)
	}

	// Second lookup should fail.
	_, ok = q.pending.Load(handle)
	if ok {
		t.Fatal("expected handle to be absent after deletion")
	}
}

// ---------------------------------------------------------------------------
// NATSQueueConfig validation / constructor
// ---------------------------------------------------------------------------

func TestNATSQueueConfig_Fields(t *testing.T) {
	cfg := NATSQueueConfig{
		Stream:       "JOBS",
		Subject:      "jobs.work",
		Consumer:     "worker",
		CreateStream: false,
	}
	if cfg.Stream != "JOBS" || cfg.Subject != "jobs.work" || cfg.Consumer != "worker" {
		t.Fatalf("config fields mismatch: %+v", cfg)
	}
}

func TestNewNATSQueue_SetsFields(t *testing.T) {
	// We cannot pass a real JetStreamContext without a NATS connection, but
	// we can verify that the struct fields are populated correctly by passing
	// nil (constructor does not dereference js when CreateStream is false).
	q := NewNATSQueue(nil, NATSQueueConfig{
		Stream:       "TEST_STREAM",
		Subject:      "test.subject",
		Consumer:     "test-consumer",
		CreateStream: false,
	})
	if q.stream != "TEST_STREAM" {
		t.Fatalf("expected stream TEST_STREAM, got %s", q.stream)
	}
	if q.subject != "test.subject" {
		t.Fatalf("expected subject test.subject, got %s", q.subject)
	}
	if q.consumer != "test-consumer" {
		t.Fatalf("expected consumer test-consumer, got %s", q.consumer)
	}
}

// ---------------------------------------------------------------------------
// Delete / ExtendVisibility error paths
// ---------------------------------------------------------------------------

func TestNATSQueue_Delete_EmptyHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.Delete(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty receipt handle")
	}
}

func TestNATSQueue_Delete_UnknownHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown receipt handle")
	}
}

func TestNATSQueue_ExtendVisibility_EmptyHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.ExtendVisibility(context.Background(), "", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for empty receipt handle")
	}
}

func TestNATSQueue_ExtendVisibility_UnknownHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.ExtendVisibility(context.Background(), "nonexistent", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for unknown receipt handle")
	}
}

func TestNATSQueue_RetryLater_EmptyHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.RetryLater(context.Background(), "", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for empty receipt handle")
	}
}

func TestNATSQueue_RetryLater_UnknownHandle(t *testing.T) {
	q := &NATSQueue{}
	err := q.RetryLater(context.Background(), "nonexistent", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for unknown receipt handle")
	}
}

// ---------------------------------------------------------------------------
// Batch helpers with empty input
// ---------------------------------------------------------------------------

func TestNATSQueue_DeleteBatch_Empty(t *testing.T) {
	q := &NATSQueue{}
	succ, failed, err := q.DeleteBatch(context.Background(), nil)
	if err != nil || succ != 0 || len(failed) != 0 {
		t.Fatalf("expected no-op, got succeeded=%d failed=%v err=%v", succ, failed, err)
	}
}

func TestNATSQueue_ExtendVisibilityBatch_Empty(t *testing.T) {
	q := &NATSQueue{}
	succ, failed, err := q.ExtendVisibilityBatch(context.Background(), nil, 30*time.Second)
	if err != nil || succ != 0 || failed != 0 {
		t.Fatalf("expected no-op, got succeeded=%d failed=%d err=%v", succ, failed, err)
	}
}

// ---------------------------------------------------------------------------
// JobMessage JSON round-trip (validates the struct tags used during Enqueue)
// ---------------------------------------------------------------------------

func TestJobMessage_JSONRoundTrip(t *testing.T) {
	msg := JobMessage{
		JobID:           "job-42",
		GroupID:         "grp-1",
		CorrelationID:   "corr-1",
		Attempt:         2,
		DeduplicationID: "dedup-1",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out JobMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != msg {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", out, msg)
	}
}

// ---------------------------------------------------------------------------
// MockQueue interface compliance (from worker_test.go) is already verified
// there via `var _ Queue = (*MockQueue)(nil)`.  We add the same check for
// NATSQueue above.
// ---------------------------------------------------------------------------
