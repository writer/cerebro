package events

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileOutboxFlushSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	outbox := newFileOutbox(path, outboxConfig{})

	for i := 0; i < 2; i++ {
		record := outboxRecord{
			Subject: "cerebro.events.finding.created",
			Payload: json.RawMessage(`{"id":"evt"}`),
		}
		if err := outbox.enqueue(record); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	result, err := outbox.flush(func(record outboxRecord) error {
		return nil
	})
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if result.Published != 2 {
		t.Fatalf("expected 2 records published, got %d", result.Published)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected outbox file to be removed, got err=%v", err)
	}
}

func TestFileOutboxFlushFailureRetainsRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	outbox := newFileOutbox(path, outboxConfig{MaxAttempts: 10})

	for i := 0; i < 2; i++ {
		record := outboxRecord{
			Subject: "cerebro.events.scan.completed",
			Payload: json.RawMessage(`{"id":"evt"}`),
		}
		if err := outbox.enqueue(record); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	result, err := outbox.flush(func(record outboxRecord) error {
		return errors.New("publish failed")
	})
	if err == nil {
		t.Fatal("expected flush error")
	}
	if result.Published != 0 {
		t.Fatalf("expected 0 published records, got %d", result.Published)
	}
	if result.Remaining != 2 {
		t.Fatalf("expected 2 remaining records, got %d", result.Remaining)
	}

	result, err = outbox.flush(func(record outboxRecord) error {
		return nil
	})
	if err != nil {
		t.Fatalf("flush retry: %v", err)
	}
	if result.Published != 2 {
		t.Fatalf("expected 2 records published after retry, got %d", result.Published)
	}
}

func TestFileOutboxFlushQuarantinesPoisonAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outbox.jsonl")
	dlqPath := filepath.Join(dir, "outbox.dlq.jsonl")
	outbox := newFileOutbox(path, outboxConfig{MaxAttempts: 1, DLQPath: dlqPath})

	record := outboxRecord{
		Subject: "cerebro.events.scan.completed",
		Payload: json.RawMessage(`{"id":"evt"}`),
	}
	if err := outbox.enqueue(record); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	result, err := outbox.flush(func(record outboxRecord) error {
		return errors.New("permanent failure")
	})
	if err != nil {
		t.Fatalf("expected poisoned record to be quarantined, got error: %v", err)
	}
	if result.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined record, got %d", result.Quarantined)
	}

	if _, err := os.Stat(dlqPath); err != nil {
		t.Fatalf("expected dlq file to exist: %v", err)
	}
}

func TestFileOutboxEnqueueAppliesLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outbox.jsonl")
	outbox := newFileOutbox(path, outboxConfig{MaxRecords: 1, MaxAge: time.Hour})

	if err := outbox.enqueue(outboxRecord{
		Subject:   "cerebro.events.scan.completed",
		Payload:   json.RawMessage(`{"id":"evt-1"}`),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("enqueue old record: %v", err)
	}

	if err := outbox.enqueue(outboxRecord{
		Subject: "cerebro.events.scan.completed",
		Payload: json.RawMessage(`{"id":"evt-2"}`),
	}); err != nil {
		t.Fatalf("enqueue new record: %v", err)
	}

	stats, err := outbox.stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Depth != 1 {
		t.Fatalf("expected outbox depth 1 after retention limits, got %d", stats.Depth)
	}
}
