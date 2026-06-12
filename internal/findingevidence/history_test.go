package findingevidence

import (
	"slices"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMergePreservesRunHistoryAndGraphPaths(t *testing.T) {
	firstObserved := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	secondObserved := firstObserved.Add(time.Hour)
	first := testEvidence("run-1", firstObserved, "urn:cerebro:writer:github_user:alice")
	second := testEvidence("run-2", secondObserved, "urn:cerebro:writer:github_user:bob")

	merged := Merge(first, second)
	if got := merged.GetRunId(); got != "run-2" {
		t.Fatalf("RunId = %q, want latest run-2", got)
	}
	if !slices.Contains(merged.GetRunIds(), "run-1") || !slices.Contains(merged.GetRunIds(), "run-2") {
		t.Fatalf("RunIds = %#v, want both runs", merged.GetRunIds())
	}
	if got := merged.GetObservationCount(); got != 2 {
		t.Fatalf("ObservationCount = %d, want 2", got)
	}
	if got := len(merged.GetObservations()); got != 2 {
		t.Fatalf("len(Observations) = %d, want 2", got)
	}
	if !slices.Contains(merged.GetGraphPathUrns(), "urn:cerebro:writer:github_user:alice") ||
		!slices.Contains(merged.GetGraphPathUrns(), "urn:cerebro:writer:github_user:bob") {
		t.Fatalf("GraphPathUrns = %#v, want both distinct paths", merged.GetGraphPathUrns())
	}
	if got := len(merged.GetGraphRows()[0].GetPaths()); got != 2 {
		t.Fatalf("len(GraphRows[0].Paths) = %d, want 2", got)
	}
	if got := merged.GetCreatedAt().AsTime(); !got.Equal(firstObserved) {
		t.Fatalf("CreatedAt = %v, want first observed %v", got, firstObserved)
	}
	if got := merged.GetLastObservedAt().AsTime(); !got.Equal(secondObserved) {
		t.Fatalf("LastObservedAt = %v, want second observed %v", got, secondObserved)
	}
}

func testEvidence(runID string, observedAt time.Time, fromURN string) *cerebrov1.FindingEvidence {
	return &cerebrov1.FindingEvidence{
		Id:             "evidence-1",
		RuntimeId:      "runtime-1",
		RuleId:         "rule-1",
		FindingId:      "finding-1",
		RunId:          runID,
		ClaimIds:       []string{"claim-" + runID},
		EventIds:       []string{"event-1"},
		GraphRootUrns:  []string{"urn:cerebro:writer:identity:alice"},
		CreatedAt:      timestamppb.New(observedAt),
		LastObservedAt: timestamppb.New(observedAt),
		GraphRows: []*cerebrov1.GraphEvidenceRow{
			{
				Label: "identity_path",
				Attributes: map[string]string{
					"kind": "active_access",
				},
				Paths: []*cerebrov1.GraphEvidencePath{
					{
						FromUrn:    fromURN,
						Relation:   "acted_on",
						ToUrn:      "urn:cerebro:writer:github_code_repository:repo-1",
						ObservedAt: observedAt.Format(time.RFC3339),
					},
				},
			},
		},
		GraphPathUrns: []string{fromURN, "urn:cerebro:writer:github_code_repository:repo-1"},
	}
}
