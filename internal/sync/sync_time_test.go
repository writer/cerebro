package sync

import (
	"context"
	"testing"
	"time"
)

func TestDeriveIncrementalStart(t *testing.T) {
	base := time.Date(2026, 2, 16, 10, 0, 0, 0, time.FixedZone("offset", -7*60*60))

	t.Run("zero time", func(t *testing.T) {
		start, ok := deriveIncrementalStart(time.Time{}, 5*time.Minute)
		if ok {
			t.Fatalf("expected no start for zero time, got %s", start)
		}
	})

	t.Run("with lookback", func(t *testing.T) {
		start, ok := deriveIncrementalStart(base, 5*time.Minute)
		if !ok {
			t.Fatalf("expected incremental start")
		}
		expected := base.UTC().Add(-5 * time.Minute)
		if !start.Equal(expected) {
			t.Fatalf("expected %s, got %s", expected, start)
		}
	})

	t.Run("without lookback", func(t *testing.T) {
		start, ok := deriveIncrementalStart(base, 0)
		if !ok {
			t.Fatalf("expected incremental start")
		}
		expected := base.UTC()
		if !start.Equal(expected) {
			t.Fatalf("expected %s, got %s", expected, start)
		}
	})

	t.Run("force full backfill context", func(t *testing.T) {
		ctx := withForceFullBackfill(context.Background())
		if !shouldForceFullBackfill(ctx) {
			t.Fatalf("expected force-full-backfill marker")
		}
	})

	t.Run("default context does not force full backfill", func(t *testing.T) {
		if shouldForceFullBackfill(context.Background()) {
			t.Fatalf("did not expect force-full-backfill marker")
		}
	})
}
