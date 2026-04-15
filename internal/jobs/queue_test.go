package jobs

import (
	"fmt"
	"testing"
	"time"
)

func TestDeduplicationIDForMessage_DefaultsToUnique(t *testing.T) {
	now := time.Unix(1_700_000_000, 123456789)
	msg := JobMessage{JobID: "job-123", Attempt: 0}

	got := deduplicationIDForMessage(msg, now)
	want := fmt.Sprintf("job-123:0:%d", now.UnixNano())
	if got != want {
		t.Fatalf("expected deduplication id %q, got %q", want, got)
	}
}

func TestDeduplicationIDForMessage_OverridesJobIDOnRetry(t *testing.T) {
	now := time.Unix(1_700_000_100, 987654321)
	msg := JobMessage{JobID: "job-123", Attempt: 2, DeduplicationID: "job-123"}

	got := deduplicationIDForMessage(msg, now)
	want := fmt.Sprintf("job-123:2:%d", now.UnixNano())
	if got != want {
		t.Fatalf("expected deduplication id %q, got %q", want, got)
	}
}

func TestDeduplicationIDForMessage_RespectsCustomID(t *testing.T) {
	now := time.Unix(1_700_000_200, 555555555)
	msg := JobMessage{JobID: "job-123", Attempt: 2, DeduplicationID: "custom-id"}

	got := deduplicationIDForMessage(msg, now)
	if got != "custom-id" {
		t.Fatalf("expected custom deduplication id, got %q", got)
	}
}
