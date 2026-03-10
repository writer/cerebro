package graph

import (
	"strings"
	"testing"
	"time"
)

func TestQueryKnowledgeArtifactsAndWriteObservation(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: knowledgeTestProperties(baseAt)})
	evidenceProps := knowledgeTestProperties(baseAt)
	evidenceProps["evidence_type"] = "document"
	evidenceProps["detail"] = "Runbook excerpt"
	g.AddNode(&Node{ID: "evidence:runbook", Kind: NodeKindEvidence, Name: "Runbook", Properties: evidenceProps})

	observation, err := WriteObservation(g, ObservationWriteRequest{
		ID:              "observation:payments:runtime",
		SubjectID:       "service:payments",
		ObservationType: "runtime_signal",
		Summary:         "Error rate increased after deploy",
		SourceSystem:    "agent",
		ObservedAt:      baseAt.Add(30 * time.Minute),
		ValidFrom:       baseAt.Add(30 * time.Minute),
		RecordedAt:      baseAt.Add(30 * time.Minute),
		TransactionFrom: baseAt.Add(30 * time.Minute),
		Metadata: map[string]any{
			"severity": "high",
		},
	})
	if err != nil {
		t.Fatalf("write observation: %v", err)
	}

	claim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		EvidenceIDs:     []string{"evidence:runbook", observation.ObservationID},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt.Add(time.Hour),
		ValidFrom:       baseAt.Add(time.Hour),
		RecordedAt:      baseAt.Add(time.Hour),
		TransactionFrom: baseAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("write claim: %v", err)
	}

	observations := QueryObservations(g, KnowledgeArtifactQueryOptions{
		TargetID:   "service:payments",
		ClaimID:    claim.ClaimID,
		RecordedAt: baseAt.Add(2 * time.Hour),
		ValidAt:    baseAt.Add(2 * time.Hour),
	})
	if len(observations.Artifacts) != 1 {
		t.Fatalf("expected one observation artifact, got %+v", observations.Artifacts)
	}
	artifact := observations.Artifacts[0]
	if artifact.Kind != NodeKindObservation {
		t.Fatalf("expected observation kind, got %+v", artifact)
	}
	if artifact.SubjectID != "service:payments" {
		t.Fatalf("expected subject_id service:payments, got %+v", artifact)
	}
	if artifact.Derived.ClaimCount != 1 {
		t.Fatalf("expected claim linkage, got %+v", artifact.Derived)
	}
	if artifact.Metadata["severity"] != "high" {
		t.Fatalf("expected severity metadata, got %#v", artifact.Metadata)
	}

	evidence := QueryEvidence(g, KnowledgeArtifactQueryOptions{
		ClaimID:    claim.ClaimID,
		RecordedAt: baseAt.Add(2 * time.Hour),
		ValidAt:    baseAt.Add(2 * time.Hour),
	})
	if len(evidence.Artifacts) != 1 {
		t.Fatalf("expected one evidence artifact, got %+v", evidence.Artifacts)
	}
	if evidence.Artifacts[0].Kind != NodeKindEvidence {
		t.Fatalf("expected evidence kind, got %+v", evidence.Artifacts[0])
	}
}

func TestClaimGroupsTimelineExplanationAndDiff(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: knowledgeTestProperties(baseAt)})
	evidenceProps := knowledgeTestProperties(baseAt)
	evidenceProps["evidence_type"] = "document"
	evidenceProps["detail"] = "Runbook excerpt"
	g.AddNode(&Node{ID: "evidence:runbook", Kind: NodeKindEvidence, Name: "Runbook", Properties: evidenceProps})

	observation, err := WriteObservation(g, ObservationWriteRequest{
		ID:              "observation:payments:manual-review",
		SubjectID:       "service:payments",
		ObservationType: "manual_review_signal",
		Summary:         "Reviewer confirmed Alice owns the service",
		SourceSystem:    "analyst",
		ObservedAt:      baseAt.Add(50 * time.Minute),
		ValidFrom:       baseAt.Add(50 * time.Minute),
		RecordedAt:      baseAt.Add(50 * time.Minute),
		TransactionFrom: baseAt.Add(50 * time.Minute),
	})
	if err != nil {
		t.Fatalf("write observation: %v", err)
	}

	priorClaim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:carol",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:carol@example.com",
		Status:          "corrected",
		SourceName:      "Archive",
		SourceType:      "document",
		SourceSystem:    "docs",
		ObservedAt:      baseAt.Add(45 * time.Minute),
		ValidFrom:       baseAt.Add(45 * time.Minute),
		RecordedAt:      baseAt.Add(45 * time.Minute),
		TransactionFrom: baseAt.Add(45 * time.Minute),
	})
	if err != nil {
		t.Fatalf("write prior claim: %v", err)
	}

	aliceClaim, err := WriteClaim(g, ClaimWriteRequest{
		ID:                "claim:payments:owner:alice",
		SubjectID:         "service:payments",
		Predicate:         "owner",
		ObjectID:          "person:alice@example.com",
		EvidenceIDs:       []string{"evidence:runbook", observation.ObservationID},
		SourceName:        "CMDB",
		SourceType:        "system",
		SourceSystem:      "cmdb",
		ObservedAt:        baseAt.Add(time.Hour),
		ValidFrom:         baseAt.Add(time.Hour),
		RecordedAt:        baseAt.Add(time.Hour),
		TransactionFrom:   baseAt.Add(time.Hour),
		SupersedesClaimID: priorClaim.ClaimID,
	})
	if err != nil {
		t.Fatalf("write alice claim: %v", err)
	}

	bobClaim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		ObservedAt:      baseAt.Add(2 * time.Hour),
		ValidFrom:       baseAt.Add(2 * time.Hour),
		RecordedAt:      baseAt.Add(2 * time.Hour),
		TransactionFrom: baseAt.Add(2 * time.Hour),
		SourceSystem:    "api",
	})
	if err != nil {
		t.Fatalf("write bob claim: %v", err)
	}

	supportClaim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice:support",
		SubjectID:       "service:payments",
		Predicate:       "ownership_review",
		ObjectID:        "person:alice@example.com",
		ObservedAt:      baseAt.Add(90 * time.Minute),
		ValidFrom:       baseAt.Add(90 * time.Minute),
		RecordedAt:      baseAt.Add(90 * time.Minute),
		TransactionFrom: baseAt.Add(90 * time.Minute),
		SourceSystem:    "jira",
	})
	if err != nil {
		t.Fatalf("write support claim: %v", err)
	}
	refutingClaim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:bob:review",
		SubjectID:       "service:payments",
		Predicate:       "ownership_review",
		ObjectID:        "person:bob@example.com",
		ObservedAt:      baseAt.Add(125 * time.Minute),
		ValidFrom:       baseAt.Add(125 * time.Minute),
		RecordedAt:      baseAt.Add(125 * time.Minute),
		TransactionFrom: baseAt.Add(125 * time.Minute),
		SourceSystem:    "analyst",
	})
	if err != nil {
		t.Fatalf("write refuting claim: %v", err)
	}

	g.AddEdge(&Edge{ID: supportClaim.ClaimID + "->" + aliceClaim.ClaimID + ":supports", Source: supportClaim.ClaimID, Target: aliceClaim.ClaimID, Kind: EdgeKindSupports, Effect: EdgeEffectAllow, Properties: knowledgeTestProperties(baseAt.Add(90 * time.Minute))})
	g.AddEdge(&Edge{ID: refutingClaim.ClaimID + "->" + aliceClaim.ClaimID + ":refutes", Source: refutingClaim.ClaimID, Target: aliceClaim.ClaimID, Kind: EdgeKindRefutes, Effect: EdgeEffectAllow, Properties: knowledgeTestProperties(baseAt.Add(125 * time.Minute))})

	groups := QueryClaimGroups(g, ClaimGroupQueryOptions{
		SubjectID:          "service:payments",
		Predicate:          "owner",
		IncludeResolved:    true,
		IncludeClaims:      true,
		IncludeSingleValue: true,
		RecordedAt:         baseAt.Add(3 * time.Hour),
		ValidAt:            baseAt.Add(3 * time.Hour),
	})
	if len(groups.Groups) != 1 {
		t.Fatalf("expected one claim group, got %+v", groups.Groups)
	}
	group := groups.Groups[0]
	if !group.Derived.NeedsAdjudication {
		t.Fatalf("expected group to need adjudication, got %+v", group)
	}
	if group.Derived.RecommendedAction != "adjudicate" {
		t.Fatalf("expected adjudicate action, got %+v", group.Derived)
	}
	if len(group.Values) < 2 {
		t.Fatalf("expected multiple values, got %+v", group.Values)
	}

	timeline, ok := GetClaimTimeline(g, aliceClaim.ClaimID, ClaimTimelineOptions{
		ValidAt:    baseAt.Add(3 * time.Hour),
		RecordedAt: baseAt.Add(3 * time.Hour),
	})
	if !ok {
		t.Fatal("expected claim timeline")
	}
	if timeline.Summary.ClaimEntries < 4 {
		t.Fatalf("expected claim entries for support/refute/conflict chain, got %+v", timeline.Summary)
	}
	if timeline.Summary.ObservationEntries < 1 || timeline.Summary.EvidenceEntries < 1 || timeline.Summary.SourceEntries < 1 {
		t.Fatalf("expected observation/evidence/source timeline entries, got %+v", timeline.Summary)
	}

	explanation, ok := ExplainClaim(g, aliceClaim.ClaimID, baseAt.Add(3*time.Hour), baseAt.Add(3*time.Hour))
	if !ok {
		t.Fatal("expected claim explanation")
	}
	if !explanation.Summary.Supported || !explanation.Summary.SourceBacked {
		t.Fatalf("expected supported, source-backed claim explanation, got %+v", explanation.Summary)
	}
	if !explanation.Summary.Conflicted || !explanation.Summary.NeedsAdjudication {
		t.Fatalf("expected conflicted explanation with adjudication need, got %+v", explanation.Summary)
	}
	if len(explanation.WhyTrue) == 0 || len(explanation.WhyDisputed) == 0 || len(explanation.RepairActions) == 0 {
		t.Fatalf("expected populated explanation strings, got %+v", explanation)
	}

	diffs := DiffClaims(g, ClaimDiffQueryOptions{
		SubjectID:       "service:payments",
		Predicate:       "owner",
		IncludeResolved: true,
		FromValidAt:     baseAt.Add(70 * time.Minute),
		FromRecordedAt:  baseAt.Add(70 * time.Minute),
		ToValidAt:       baseAt.Add(3 * time.Hour),
		ToRecordedAt:    baseAt.Add(3 * time.Hour),
	})
	if diffs.Summary.AddedClaims < 1 {
		t.Fatalf("expected added claims in diff, got %+v", diffs.Summary)
	}
	foundBob := false
	for _, diff := range diffs.Diffs {
		if diff.ClaimID == bobClaim.ClaimID && diff.ChangeType == "added" {
			foundBob = true
			break
		}
	}
	if !foundBob {
		t.Fatalf("expected bob claim in diff results, got %+v", diffs.Diffs)
	}
}

func knowledgeTestProperties(at time.Time) map[string]any {
	return map[string]any{
		"observed_at":      at.UTC().Format(time.RFC3339),
		"valid_from":       at.UTC().Format(time.RFC3339),
		"recorded_at":      at.UTC().Format(time.RFC3339),
		"transaction_from": at.UTC().Format(time.RFC3339),
	}
}

func TestExplainClaimIncludesSourceRecords(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: knowledgeTestProperties(baseAt)})

	claim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt,
		ValidFrom:       baseAt,
		RecordedAt:      baseAt,
		TransactionFrom: baseAt,
	})
	if err != nil {
		t.Fatalf("write claim: %v", err)
	}

	explanation, ok := ExplainClaim(g, claim.ClaimID, baseAt.Add(time.Hour), baseAt.Add(time.Hour))
	if !ok {
		t.Fatal("expected explanation")
	}
	if len(explanation.Sources) != 1 {
		t.Fatalf("expected one source record, got %+v", explanation.Sources)
	}
	if !strings.EqualFold(explanation.Sources[0].CanonicalName, "CMDB") {
		t.Fatalf("expected CMDB source, got %+v", explanation.Sources[0])
	}
}

func TestGetClaimGroupRecordIncludesSingleValueGroups(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: knowledgeTestProperties(baseAt)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: knowledgeTestProperties(baseAt)})

	claim, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt,
		ValidFrom:       baseAt,
		RecordedAt:      baseAt,
		TransactionFrom: baseAt,
	})
	if err != nil {
		t.Fatalf("write claim: %v", err)
	}

	groupID := buildClaimGroupID("service:payments", "owner")
	record, ok := GetClaimGroupRecord(g, groupID, baseAt.Add(time.Hour), baseAt.Add(time.Hour), false)
	if !ok {
		t.Fatalf("expected single-value claim group for %q", claim.ClaimID)
	}
	if record.ID != groupID {
		t.Fatalf("expected group id %q, got %+v", groupID, record)
	}
	if record.Derived.NeedsAdjudication {
		t.Fatalf("did not expect adjudication on single-value group, got %+v", record.Derived)
	}
}
