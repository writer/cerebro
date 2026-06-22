package connectordiagnostics

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcehealthview"
)

func TestFromHealthBuildsOrderedRuntimeTimeline(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	duration := int64(12)
	timeline := FromHealth([]sourcehealthview.Record{{
		RuntimeID:          "runtime-a",
		SourceID:           "github",
		TenantID:           "tenant-a",
		Status:             "healthy",
		LastSyncedAt:       now.Format(time.RFC3339Nano),
		ContractProbeState: "passing",
		RecentSync:         sourcehealthview.Sync{RecordsAccepted: 4},
		LatestGraphRun: &sourcehealthview.GraphRun{
			ID:                "graph-a",
			Status:            "completed",
			StartedAt:         now.Add(-time.Minute).Format(time.RFC3339Nano),
			FinishedAt:        now.Format(time.RFC3339Nano),
			EntitiesProjected: 7,
			LinksProjected:    3,
			DurationSeconds:   &duration,
		},
		LatestFindingEvaluation: &sourcehealthview.FindingEvaluation{
			ID:               "eval-a",
			Status:           "completed",
			FinishedAt:       now.Add(time.Minute).Format(time.RFC3339Nano),
			EventsEvaluated:  5,
			GraphRowsRead:    2,
			FindingsUpserted: 1,
		},
	}})

	wantStages := []string{"setup", "source_sync", "contract_probe", "graph_projection", "finding_evaluation"}
	if len(timeline) != len(wantStages) {
		t.Fatalf("timeline length = %d, want %d: %#v", len(timeline), len(wantStages), timeline)
	}
	for i, stage := range wantStages {
		if got := timeline[i].Stage; got != stage {
			t.Fatalf("timeline[%d].stage = %q, want %q", i, got, stage)
		}
		if got := timeline[i].Status; got != "success" {
			t.Fatalf("timeline[%d].status = %q, want success", i, got)
		}
	}
	if got := timeline[3].CorrelationID; got != "graph-a" {
		t.Fatalf("graph correlation_id = %q, want graph-a", got)
	}
	if got := timeline[4].FindingsEvaluated; got != 7 {
		t.Fatalf("findings_evaluated = %d, want 7", got)
	}
	if got := timeline[4].FindingsOpened; got != 1 {
		t.Fatalf("findings_opened = %d, want 1", got)
	}
}

func TestFromPreflightClassifiesBlockedChecks(t *testing.T) {
	timeline := FromPreflight(Preflight{
		GeneratedAt: "2026-06-15T10:00:00Z",
		SourceID:    "github",
		RuntimeID:   "runtime-a",
		TenantID:    "tenant-a",
		Status:      "blocked",
		Summary:     "Fix blocking checks.",
		NextAction:  "fix_blocking_checks",
		Checks: []PreflightCheck{{
			ID:         "credential",
			Label:      "Credential",
			Status:     "blocked",
			Detail:     "Credential is unavailable.",
			NextAction: "configure_credential",
		}},
	})

	if len(timeline) != 2 {
		t.Fatalf("timeline length = %d, want 2", len(timeline))
	}
	for i, entry := range timeline {
		if entry.Status != "failed" {
			t.Fatalf("timeline[%d].status = %q, want failed", i, entry.Status)
		}
		if entry.FailureClass != "preflight_blocked" {
			t.Fatalf("timeline[%d].failure_class = %q, want preflight_blocked", i, entry.FailureClass)
		}
	}
}
