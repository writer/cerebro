package bootstrap

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSourceRuntimeHealthRecordIncludesScheduleReceipt(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		Id:           "runtime-1",
		SourceId:     "generated",
		TenantId:     "tenant",
		LastSyncedAt: timestamppb.New(now.Add(-time.Hour)),
		Config: map[string]string{
			"expected_cadence_seconds": "3600",
			"stale_after_seconds":      "7200",
		},
	}

	record, err := (&App{}).sourceRuntimeHealthRecord(context.Background(), runtime, now)
	if err != nil {
		t.Fatalf("sourceRuntimeHealthRecord() error = %v", err)
	}
	if record.ExpectedCadenceSeconds == nil || *record.ExpectedCadenceSeconds != 3600 {
		t.Fatalf("ExpectedCadenceSeconds = %v, want 3600", record.ExpectedCadenceSeconds)
	}
	if record.StaleAfterSeconds == nil || *record.StaleAfterSeconds != 7200 {
		t.Fatalf("StaleAfterSeconds = %v, want 7200", record.StaleAfterSeconds)
	}
	if !record.ScheduleContextConfigured {
		t.Fatal("ScheduleContextConfigured = false, want true")
	}
	if record.Status != "healthy" {
		t.Fatalf("Status = %q, want healthy", record.Status)
	}
}

func TestRuntimeHealthStatusHonorsStaleAfter(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		LastSyncedAt: timestamppb.New(now.Add(-2 * time.Hour)),
		Config: map[string]string{
			"stale_after_seconds": "3600",
		},
	}

	if got := runtimeHealthStatus(runtime, now); got != "stale" {
		t.Fatalf("runtimeHealthStatus() = %q, want stale", got)
	}
}

func TestSourceRuntimeHealthRecordHandlesPartialAndInvalidScheduleReceipt(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		config         map[string]string
		wantCadence    *int64
		wantStale      *int64
		wantConfigured bool
	}{
		{
			name: "cadence only",
			config: map[string]string{
				"expected_cadence_seconds": " 1800 ",
			},
			wantCadence:    int64Ptr(1800),
			wantConfigured: true,
		},
		{
			name: "stale only",
			config: map[string]string{
				"stale_after_seconds": "3600",
			},
			wantStale:      int64Ptr(3600),
			wantConfigured: true,
		},
		{
			name: "invalid values ignored",
			config: map[string]string{
				"expected_cadence_seconds": "invalid",
				"stale_after_seconds":      "-1",
			},
		},
		{
			name: "zero values ignored",
			config: map[string]string{
				"expected_cadence_seconds": "0",
				"stale_after_seconds":      "0",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, err := (&App{}).sourceRuntimeHealthRecord(context.Background(), &cerebrov1.SourceRuntime{
				Id:           "runtime-1",
				SourceId:     "generated",
				TenantId:     "tenant",
				LastSyncedAt: timestamppb.New(now),
				Config:       test.config,
			}, now)
			if err != nil {
				t.Fatalf("sourceRuntimeHealthRecord() error = %v", err)
			}
			assertOptionalInt64(t, "ExpectedCadenceSeconds", record.ExpectedCadenceSeconds, test.wantCadence)
			assertOptionalInt64(t, "StaleAfterSeconds", record.StaleAfterSeconds, test.wantStale)
			if record.ScheduleContextConfigured != test.wantConfigured {
				t.Fatalf("ScheduleContextConfigured = %v, want %v", record.ScheduleContextConfigured, test.wantConfigured)
			}
		})
	}
}

func TestRuntimeHealthStatusStaleBoundaryAndFailurePrecedence(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		lastSynced time.Time
		config     map[string]string
		want       string
	}{
		{
			name:       "exact threshold is healthy",
			lastSynced: now.Add(-time.Hour),
			config:     map[string]string{"stale_after_seconds": "3600"},
			want:       "healthy",
		},
		{
			name:       "over threshold is stale",
			lastSynced: now.Add(-time.Hour - time.Second),
			config:     map[string]string{"stale_after_seconds": "3600"},
			want:       "stale",
		},
		{
			name:       "failure beats stale",
			lastSynced: now.Add(-2 * time.Hour),
			config: map[string]string{
				"stale_after_seconds":               "3600",
				runtimeLastFailureCategoryConfigKey: "auth_error",
			},
			want: "failing",
		},
		{
			name:       "large int64 stale window",
			lastSynced: now.Add(-2 * time.Hour),
			config:     map[string]string{"stale_after_seconds": "4294967296"},
			want:       "healthy",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{
				LastSyncedAt: timestamppb.New(test.lastSynced),
				Config:       test.config,
			}
			if got := runtimeHealthStatus(runtime, now); got != test.want {
				t.Fatalf("runtimeHealthStatus() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSourceRuntimeHealthSummariesAggregateBySource(t *testing.T) {
	graphLag := int64(7200)
	staleAfter := int64(3600)
	records := []sourceRuntimeHealthRecord{
		{
			RuntimeID:          "runtime-a",
			SourceID:           "okta",
			Status:             "healthy",
			ContractProbeState: "passing",
			LatestGraphRun:     sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "completed"}),
			GraphLagSeconds:    &graphLag,
			StaleAfterSeconds:  &staleAfter,
		},
		{
			RuntimeID:          "runtime-b",
			SourceID:           "okta",
			Status:             "failing",
			CursorPending:      true,
			ContractProbeState: "failure",
			LatestGraphRun:     sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "failed"}),
			StaleAfterSeconds:  &staleAfter,
		},
		{
			RuntimeID:          "runtime-c",
			SourceID:           "panopticon",
			Status:             "unknown",
			ContractProbeState: "not_configured",
		},
	}

	summaries := sourceRuntimeHealthSummaries(records)

	if len(summaries) != 2 {
		t.Fatalf("len(sourceRuntimeHealthSummaries()) = %d, want 2", len(summaries))
	}
	okta := summaries[0]
	if okta.SourceID != "okta" || okta.Total != 2 || okta.Healthy != 1 || okta.Failing != 1 {
		t.Fatalf("okta summary = %+v", okta)
	}
	if okta.CursorPending != 1 || okta.GraphBehind != 1 || okta.GraphFailed != 1 {
		t.Fatalf("okta graph/cursor summary = %+v", okta)
	}
	if okta.ContractProbePassing != 1 || okta.ContractProbeFailure != 1 {
		t.Fatalf("okta contract summary = %+v", okta)
	}
	panopticon := summaries[1]
	if panopticon.SourceID != "panopticon" || panopticon.Total != 1 || panopticon.Unknown != 1 || panopticon.GraphNotObserved != 1 || panopticon.ContractProbeNotConfigured != 1 {
		t.Fatalf("panopticon summary = %+v", panopticon)
	}
}

func int64Ptr(value int64) *int64 {
	return &value
}

func assertOptionalInt64(t *testing.T, label string, got *int64, want *int64) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("%s = %v, want nil", label, *got)
		}
		return
	}
	if got == nil || *got != *want {
		t.Fatalf("%s = %v, want %v", label, got, *want)
	}
}
