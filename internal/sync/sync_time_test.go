package sync

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
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

func TestIncrementalStartTime_UsesPersistedWatermarkForIncrementalTables(t *testing.T) {
	original := queryLatestTableSyncTime
	t.Cleanup(func() { queryLatestTableSyncTime = original })

	persisted := time.Date(2026, 2, 24, 12, 30, 0, 0, time.UTC)
	queryLatestTableSyncTime = func(_ context.Context, _ warehouse.SyncWarehouse, _ string, _ string, _ bool) (time.Time, error) {
		return persisted, nil
	}

	e := &SyncEngine{}

	tests := []struct {
		name     string
		table    string
		lookback time.Duration
	}{
		{name: "securityhub", table: "aws_securityhub_findings", lookback: securityHubIncrementalLookback},
		{name: "guardduty", table: "aws_guardduty_findings", lookback: guardDutyIncrementalLookback},
		{name: "inspector", table: "aws_inspector2_findings", lookback: inspectorIncrementalLookback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, ok := e.incrementalStartTime(context.Background(), tt.table, "us-east-1", true, tt.lookback)
			if !ok {
				t.Fatalf("expected incremental start for %s", tt.table)
			}
			expected := persisted.Add(-tt.lookback)
			if !start.Equal(expected) {
				t.Fatalf("expected %s, got %s", expected, start)
			}
		})
	}
}

func TestIncrementalStartTime_LookupErrorReturnsNoStart(t *testing.T) {
	original := queryLatestTableSyncTime
	t.Cleanup(func() { queryLatestTableSyncTime = original })

	queryLatestTableSyncTime = func(_ context.Context, _ warehouse.SyncWarehouse, _ string, _ string, _ bool) (time.Time, error) {
		return time.Time{}, errors.New("lookup failed")
	}

	e := &SyncEngine{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	start, ok := e.incrementalStartTime(context.Background(), "aws_securityhub_findings", "us-east-1", true, securityHubIncrementalLookback)
	if ok {
		t.Fatalf("expected no incremental start when lookup fails")
	}
	if !start.IsZero() {
		t.Fatalf("expected zero start time, got %s", start)
	}
}

func TestIncrementalStartTime_ForceFullBackfillBypassesWatermarkLookup(t *testing.T) {
	original := queryLatestTableSyncTime
	t.Cleanup(func() { queryLatestTableSyncTime = original })

	called := false
	queryLatestTableSyncTime = func(_ context.Context, _ warehouse.SyncWarehouse, _ string, _ string, _ bool) (time.Time, error) {
		called = true
		return time.Now().UTC(), nil
	}

	e := &SyncEngine{}
	ctx := withForceFullBackfill(context.Background())
	start, ok := e.incrementalStartTime(ctx, "aws_securityhub_findings", "us-east-1", true, securityHubIncrementalLookback)
	if ok {
		t.Fatalf("expected force-full-backfill to disable incremental start")
	}
	if !start.IsZero() {
		t.Fatalf("expected zero start time, got %s", start)
	}
	if called {
		t.Fatalf("expected watermark lookup to be skipped when forcing full backfill")
	}
}

func TestQueryLatestTableSyncTime_UsesWarehouseInterface(t *testing.T) {
	expected := time.Date(2026, 3, 10, 12, 34, 56, 0, time.UTC)
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(query, "WHERE REGION = ?") {
				t.Fatalf("expected regional filter in query, got %q", query)
			}
			if len(args) != 1 || args[0] != "us-east-1" {
				t.Fatalf("expected region arg us-east-1, got %#v", args)
			}
			return &snowflake.QueryResult{
				Rows: []map[string]any{{"SYNC_TIME": expected.Format(time.RFC3339Nano)}},
			}, nil
		},
	}

	got, err := queryLatestTableSyncTime(context.Background(), store, "aws_securityhub_findings", "us-east-1", true)
	if err != nil {
		t.Fatalf("queryLatestTableSyncTime returned error: %v", err)
	}
	if !got.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, got)
	}
	if len(store.Queries) != 1 {
		t.Fatalf("expected 1 recorded query, got %d", len(store.Queries))
	}
}
