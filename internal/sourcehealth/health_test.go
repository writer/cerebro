package sourcehealth

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateClassifiesRuntimeFreshness(t *testing.T) {
	staleAfter := int64(3600)
	graphLag := int64(7200)
	tests := []struct {
		name             string
		record           Record
		wantFreshness    string
		wantFailureClass string
		wantGraphState   string
		wantSourceState  string
		wantBackfill     bool
		wantNextAction   string
		wantRecommended  string
	}{
		{
			name: "healthy",
			record: Record{
				EnabledState:      "enabled",
				Status:            "healthy",
				LatestGraphRun:    &GraphRun{Status: "completed"},
				GraphLagSeconds:   int64Ptr(60),
				StaleAfterSeconds: &staleAfter,
			},
			wantFreshness:   "healthy",
			wantGraphState:  "current",
			wantSourceState: "current",
			wantNextAction:  "monitor",
		},
		{
			name: "missing graph",
			record: Record{
				EnabledState:      "enabled",
				Status:            "healthy",
				GraphLagSeconds:   &graphLag,
				StaleAfterSeconds: &staleAfter,
			},
			wantFreshness:    "graph_missing",
			wantFailureClass: "graph_ingest_missing",
			wantGraphState:   "not_observed",
			wantSourceState:  "current",
			wantBackfill:     true,
			wantNextAction:   "plan_backfill",
			wantRecommended:  "source-runtime-backfill",
		},
		{
			name: "source failed",
			record: Record{
				EnabledState:        "enabled",
				Status:              "failing",
				LastFailureCategory: "auth_error",
				LatestGraphRun:      &GraphRun{Status: "completed"},
				StaleAfterSeconds:   &staleAfter,
			},
			wantFreshness:    "source_failed",
			wantFailureClass: "auth_error",
			wantGraphState:   "current",
			wantSourceState:  "failed",
			wantNextAction:   "fix_source_sync",
		},
		{
			name: "disabled",
			record: Record{
				EnabledState: "disabled",
				Status:       "unknown",
			},
			wantFreshness:    "disabled",
			wantFailureClass: "disabled",
			wantGraphState:   "not_observed",
			wantSourceState:  "unknown",
			wantNextAction:   "review_runtime_enablement",
		},
		{
			name: "running graph remains healthy",
			record: Record{
				EnabledState:   "enabled",
				Status:         "healthy",
				LatestGraphRun: &GraphRun{Status: "running"},
			},
			wantFreshness:   "healthy",
			wantGraphState:  "running",
			wantSourceState: "current",
			wantNextAction:  "monitor",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Evaluate(test.record)
			if got.FreshnessState != test.wantFreshness {
				t.Fatalf("FreshnessState = %q, want %q; state=%+v", got.FreshnessState, test.wantFreshness, got)
			}
			if got.FailureClass != test.wantFailureClass {
				t.Fatalf("FailureClass = %q, want %q; state=%+v", got.FailureClass, test.wantFailureClass, got)
			}
			if got.GraphIngestState != test.wantGraphState {
				t.Fatalf("GraphIngestState = %q, want %q; state=%+v", got.GraphIngestState, test.wantGraphState, got)
			}
			if got.SourceSyncState != test.wantSourceState {
				t.Fatalf("SourceSyncState = %q, want %q; state=%+v", got.SourceSyncState, test.wantSourceState, got)
			}
			if got.BackfillEligible != test.wantBackfill {
				t.Fatalf("BackfillEligible = %v, want %v; state=%+v", got.BackfillEligible, test.wantBackfill, got)
			}
			if got.NextAction != test.wantNextAction {
				t.Fatalf("NextAction = %q, want %q; state=%+v", got.NextAction, test.wantNextAction, got)
			}
			if got.RecommendedWorkflow != test.wantRecommended {
				t.Fatalf("RecommendedWorkflow = %q, want %q; state=%+v", got.RecommendedWorkflow, test.wantRecommended, got)
			}
		})
	}
}

func TestContractProbeStatus(t *testing.T) {
	tests := map[string]string{
		"passing":        "success",
		" success ":      "success",
		"failure":        "failure",
		"failed":         "failure",
		"stale":          "stale",
		"not_configured": "unknown",
		"":               "unknown",
	}
	for input, want := range tests {
		if got := ContractProbeStatus(input); got != want {
			t.Fatalf("ContractProbeStatus(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRecordFromRuntimeTreatsZeroProtoTimestampAsUnset(t *testing.T) {
	now := time.Date(2026, 6, 18, 20, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		Id:           "writer-evidence-cas",
		SourceId:     "evidence_cas",
		TenantId:     "writer",
		LastSyncedAt: &timestamppb.Timestamp{},
		Config:       map[string]string{StaleAfterSecondsConfigKey: "3600"},
	}

	record := RecordFromRuntime(runtime, now)

	if record.Status != "unknown" {
		t.Fatalf("Status = %q, want unknown for zero proto timestamp", record.Status)
	}
	if record.SyncLagSeconds != nil {
		t.Fatalf("SyncLagSeconds = %v, want nil for zero proto timestamp", *record.SyncLagSeconds)
	}
	if got := RuntimeContractProbeState(runtime); got != "unknown" {
		t.Fatalf("RuntimeContractProbeState = %q, want unknown for zero proto timestamp", got)
	}
}

func TestLinkStatusRollup(t *testing.T) {
	tests := []struct {
		resource string
		caseLink string
		want     string
	}{
		{resource: "linked", caseLink: "linked", want: "linked"},
		{resource: "missing", caseLink: "linked", want: "missing_resource"},
		{resource: "linked", caseLink: "missing", want: "missing_case"},
		{resource: "missing", caseLink: "missing", want: "orphan"},
		{resource: "not_applicable", caseLink: "not_supplied", want: "linked"},
	}
	for _, test := range tests {
		if got := LinkStatusRollup(test.resource, test.caseLink); got != test.want {
			t.Fatalf("LinkStatusRollup(%q, %q) = %q, want %q", test.resource, test.caseLink, got, test.want)
		}
	}
}

func TestValidationFieldClass(t *testing.T) {
	tests := map[string]string{
		"missing_required_attribute":     "attribute",
		"missing_required_payload_field": "payload_field",
		"missing_canonical_field":        "canonical_field",
		"invalid_event":                  "unknown",
	}
	for input, want := range tests {
		if got := ValidationFieldClass(input); got != want {
			t.Fatalf("ValidationFieldClass(%q) = %q, want %q", input, got, want)
		}
	}
}

func int64Ptr(value int64) *int64 {
	return &value
}
