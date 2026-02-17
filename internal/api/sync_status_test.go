package api

import (
	"testing"
	"time"
)

func TestParseLastSyncValue(t *testing.T) {
	t.Run("time value", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		parsed := parseLastSyncValue(now)
		if !parsed.Equal(now) {
			t.Fatalf("expected %s, got %s", now, parsed)
		}
	})

	t.Run("rfc3339 nano string", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		parsed := parseLastSyncValue(now.Format(time.RFC3339Nano))
		if !parsed.Equal(now) {
			t.Fatalf("expected %s, got %s", now, parsed)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		parsed := parseLastSyncValue("not-a-time")
		if !parsed.IsZero() {
			t.Fatalf("expected zero time, got %s", parsed)
		}
	})
}

func TestParseLastSyncRow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("lowercase key", func(t *testing.T) {
		parsed := parseLastSyncRow(map[string]interface{}{"last_sync": now})
		if !parsed.Equal(now) {
			t.Fatalf("expected %s, got %s", now, parsed)
		}
	})

	t.Run("uppercase key", func(t *testing.T) {
		parsed := parseLastSyncRow(map[string]interface{}{"LAST_SYNC": now})
		if !parsed.Equal(now) {
			t.Fatalf("expected %s, got %s", now, parsed)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		parsed := parseLastSyncRow(map[string]interface{}{"other": now})
		if !parsed.IsZero() {
			t.Fatalf("expected zero time, got %s", parsed)
		}
	})
}
