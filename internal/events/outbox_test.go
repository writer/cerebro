package events

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileOutboxFlushSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	outbox := newFileOutbox(path)

	for i := 0; i < 2; i++ {
		record := outboxRecord{
			Subject: "cerebro.events.finding.created",
			Payload: json.RawMessage(`{"id":"evt"}`),
		}
		if err := outbox.enqueue(record); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	published, err := outbox.flush(func(record outboxRecord) error {
		return nil
	})
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if published != 2 {
		t.Fatalf("expected 2 records published, got %d", published)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected outbox file to be removed, got err=%v", err)
	}
}

func TestFileOutboxFlushFailureRetainsRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	outbox := newFileOutbox(path)

	for i := 0; i < 2; i++ {
		record := outboxRecord{
			Subject: "cerebro.events.scan.completed",
			Payload: json.RawMessage(`{"id":"evt"}`),
		}
		if err := outbox.enqueue(record); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	published, err := outbox.flush(func(record outboxRecord) error {
		return errors.New("publish failed")
	})
	if err == nil {
		t.Fatal("expected flush error")
	}
	if published != 0 {
		t.Fatalf("expected 0 published records, got %d", published)
	}

	published, err = outbox.flush(func(record outboxRecord) error {
		return nil
	})
	if err != nil {
		t.Fatalf("flush retry: %v", err)
	}
	if published != 2 {
		t.Fatalf("expected 2 records published after retry, got %d", published)
	}
}
