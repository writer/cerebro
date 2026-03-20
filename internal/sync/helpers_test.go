package sync

import (
	"testing"
	"time"
)

func TestTimeToString(t *testing.T) {
	if got := timeToString(nil); got != "" {
		t.Fatalf("expected empty string for nil time, got %q", got)
	}

	ts := time.Date(2026, 3, 12, 21, 30, 0, 0, time.UTC)
	if got := timeToString(&ts); got != ts.Format(time.RFC3339) {
		t.Fatalf("unexpected formatted time: %q", got)
	}
}
