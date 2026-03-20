package knowledge

import (
	"testing"
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestObservationWrappersRoundTripRecords(t *testing.T) {
	baseAt := time.Date(2026, 3, 14, 15, 0, 0, 0, time.UTC)

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:         "service:payments",
		Kind:       graph.NodeKindService,
		Name:       "Payments",
		Properties: map[string]any{"service_id": "payments"},
	})

	result, err := WriteObservation(g, ObservationWriteRequest{
		SubjectID:       "service:payments",
		ObservationType: "deployment",
		Summary:         "payments deployed",
		SourceSystem:    "test",
		SourceEventID:   "evt-1",
		ObservedAt:      baseAt,
		ValidFrom:       baseAt,
		RecordedAt:      baseAt,
		Confidence:      0.9,
	})
	if err != nil {
		t.Fatalf("WriteObservation returned error: %v", err)
	}

	record, ok := GetObservationRecord(g, result.ObservationID, baseAt.Add(time.Minute), baseAt.Add(time.Minute))
	if !ok {
		t.Fatalf("GetObservationRecord did not return written observation")
	}
	if record.SubjectID != "service:payments" {
		t.Fatalf("expected subject service:payments, got %q", record.SubjectID)
	}

	records := QueryObservations(g, KnowledgeArtifactQueryOptions{
		Type:       "deployment",
		ValidAt:    baseAt.Add(time.Minute),
		RecordedAt: baseAt.Add(time.Minute),
	})
	if len(records.Artifacts) != 1 {
		t.Fatalf("expected 1 observation record, got %d", len(records.Artifacts))
	}
}

func TestClaimWrappersExposeQueryGroupingAndConflicts(t *testing.T) {
	baseAt := time.Date(2026, 3, 14, 16, 0, 0, 0, time.UTC)

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:         "service:payments",
		Kind:       graph.NodeKindService,
		Name:       "Payments",
		Properties: map[string]any{"service_id": "payments"},
	})
	g.AddNode(&graph.Node{
		ID:         "person:alice",
		Kind:       graph.NodeKindPerson,
		Name:       "Alice",
		Properties: map[string]any{"name": "Alice"},
	})
	g.AddNode(&graph.Node{
		ID:         "person:bob",
		Kind:       graph.NodeKindPerson,
		Name:       "Bob",
		Properties: map[string]any{"name": "Bob"},
	})

	first, err := WriteClaim(g, ClaimWriteRequest{
		ID:            "claim:payments:owner:alice",
		SubjectID:     "service:payments",
		Predicate:     "owner",
		ObjectID:      "person:alice",
		SourceName:    "catalog",
		SourceType:    "system",
		SourceSystem:  "test",
		SourceEventID: "evt-claim-1",
		ObservedAt:    baseAt,
		ValidFrom:     baseAt,
		RecordedAt:    baseAt,
		Confidence:    0.9,
	})
	if err != nil {
		t.Fatalf("WriteClaim(first) returned error: %v", err)
	}

	_, err = WriteClaim(g, ClaimWriteRequest{
		ID:            "claim:payments:owner:bob",
		SubjectID:     "service:payments",
		Predicate:     "owner",
		ObjectID:      "person:bob",
		SourceName:    "runbook",
		SourceType:    "document",
		SourceSystem:  "test",
		SourceEventID: "evt-claim-2",
		ObservedAt:    baseAt.Add(time.Minute),
		ValidFrom:     baseAt.Add(time.Minute),
		RecordedAt:    baseAt.Add(time.Minute),
		Confidence:    0.8,
	})
	if err != nil {
		t.Fatalf("WriteClaim(second) returned error: %v", err)
	}

	claims := QueryClaims(g, ClaimQueryOptions{
		SubjectID:  "service:payments",
		ValidAt:    baseAt.Add(2 * time.Minute),
		RecordedAt: baseAt.Add(2 * time.Minute),
		Limit:      10,
		Offset:     0,
	})
	if len(claims.Claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(claims.Claims))
	}

	record, ok := GetClaimRecord(g, first.ClaimID, baseAt.Add(2*time.Minute), baseAt.Add(2*time.Minute))
	if !ok {
		t.Fatalf("GetClaimRecord did not return first claim")
	}
	if record.SubjectID != "service:payments" {
		t.Fatalf("expected subject service:payments, got %q", record.SubjectID)
	}

	groups := QueryClaimGroups(g, ClaimGroupQueryOptions{
		SubjectID:          "service:payments",
		IncludeSingleValue: true,
		ValidAt:            baseAt.Add(2 * time.Minute),
		RecordedAt:         baseAt.Add(2 * time.Minute),
	})
	if len(groups.Groups) != 1 {
		t.Fatalf("expected 1 claim group, got %d", len(groups.Groups))
	}

	group, ok := GetClaimGroupRecord(g, groups.Groups[0].ID, baseAt.Add(2*time.Minute), baseAt.Add(2*time.Minute), true)
	if !ok {
		t.Fatalf("GetClaimGroupRecord did not return claim group")
	}
	if len(group.Values) != 2 {
		t.Fatalf("expected 2 grouped values, got %d", len(group.Values))
	}

	explanation, ok := ExplainClaim(g, first.ClaimID, baseAt.Add(2*time.Minute), baseAt.Add(2*time.Minute))
	if !ok {
		t.Fatalf("ExplainClaim did not return explanation")
	}
	if explanation.Claim.ID != first.ClaimID {
		t.Fatalf("expected explanation for %q, got %q", first.ClaimID, explanation.Claim.ID)
	}

	report := BuildClaimConflictReport(g, ClaimConflictReportOptions{
		ValidAt:      baseAt.Add(2 * time.Minute),
		RecordedAt:   baseAt.Add(2 * time.Minute),
		MaxConflicts: 10,
	})
	if len(report.Conflicts) == 0 {
		t.Fatalf("expected at least one conflict")
	}
}
