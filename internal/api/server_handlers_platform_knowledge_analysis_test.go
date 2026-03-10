package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestPlatformKnowledgeObservationAndClaimAnalysisEndpoints(t *testing.T) {
	s := newTestServer(t)
	baseAt, aliceClaimID, bobClaimID, seedObservationID := seedPlatformKnowledgeScenario(t, s)
	g := s.app.SecurityGraph

	create := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/observations", map[string]any{
		"subject_id":       "service:payments",
		"observation_type": "manual_review_signal",
		"summary":          "Secondary reviewer confirmed Alice owns payments",
		"source_system":    "analyst",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201 for platform observation write, got %d: %s", create.Code, create.Body.String())
	}
	createBody := decodeJSON(t, create)
	createdObservationID, _ := createBody["observation_id"].(string)
	if createdObservationID == "" {
		t.Fatalf("expected observation_id, got %#v", createBody)
	}
	if node, ok := g.GetNode(createdObservationID); !ok || node == nil || node.Kind != graph.NodeKindObservation {
		t.Fatalf("expected observation node %q, got %#v", createdObservationID, node)
	}

	observations := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/observations?target_id=service:payments", nil)
	if observations.Code != http.StatusOK {
		t.Fatalf("expected 200 for observations list, got %d: %s", observations.Code, observations.Body.String())
	}
	obsBody := decodeJSON(t, observations)
	if obsBody["count"].(float64) < 2 {
		t.Fatalf("expected at least two observations, got %#v", obsBody)
	}

	observationDetail := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/observations/"+seedObservationID, nil)
	if observationDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 for observation detail, got %d: %s", observationDetail.Code, observationDetail.Body.String())
	}
	observationDetailBody := decodeJSON(t, observationDetail)
	if observationDetailBody["kind"] != string(graph.NodeKindObservation) {
		t.Fatalf("expected observation kind, got %#v", observationDetailBody)
	}

	evidence := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/evidence?claim_id="+aliceClaimID, nil)
	if evidence.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence list, got %d: %s", evidence.Code, evidence.Body.String())
	}
	evidenceBody := decodeJSON(t, evidence)
	if evidenceBody["count"].(float64) != 1 {
		t.Fatalf("expected one evidence record, got %#v", evidenceBody)
	}

	groups := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-groups?subject_id=service:payments&predicate=owner&include_resolved=true&include_single_value=true", nil)
	if groups.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim groups, got %d: %s", groups.Code, groups.Body.String())
	}
	groupsBody := decodeJSON(t, groups)
	groupRecords, ok := groupsBody["groups"].([]any)
	if !ok || len(groupRecords) != 1 {
		t.Fatalf("expected one claim group, got %#v", groupsBody["groups"])
	}
	groupRecord := groupRecords[0].(map[string]any)
	groupID, _ := groupRecord["id"].(string)
	derived := groupRecord["derived"].(map[string]any)
	if derived["needs_adjudication"] != true || derived["recommended_action"] != "adjudicate" {
		t.Fatalf("expected adjudication queue state, got %#v", derived)
	}

	groupDetail := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-groups/"+groupID+"?include_resolved=true", nil)
	if groupDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim group detail, got %d: %s", groupDetail.Code, groupDetail.Body.String())
	}

	timeline := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+aliceClaimID+"/timeline", nil)
	if timeline.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim timeline, got %d: %s", timeline.Code, timeline.Body.String())
	}
	timelineBody := decodeJSON(t, timeline)
	timelineSummary := timelineBody["summary"].(map[string]any)
	if timelineSummary["observation_entries"].(float64) < 1 || timelineSummary["support_entries"].(float64) < 1 || timelineSummary["conflict_entries"].(float64) < 1 {
		t.Fatalf("expected support, conflict, and observation timeline entries, got %#v", timelineSummary)
	}

	explanation := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+aliceClaimID+"/explanation", nil)
	if explanation.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim explanation, got %d: %s", explanation.Code, explanation.Body.String())
	}
	explanationBody := decodeJSON(t, explanation)
	whyTrue, ok := explanationBody["why_true"].([]any)
	if !ok || len(whyTrue) == 0 {
		t.Fatalf("expected why_true entries, got %#v", explanationBody["why_true"])
	}
	whyDisputed, ok := explanationBody["why_disputed"].([]any)
	if !ok || len(whyDisputed) == 0 {
		t.Fatalf("expected why_disputed entries, got %#v", explanationBody["why_disputed"])
	}
	repairActions, ok := explanationBody["repair_actions"].([]any)
	if !ok || len(repairActions) == 0 {
		t.Fatalf("expected repair actions, got %#v", explanationBody["repair_actions"])
	}

	diffURL := "/api/v1/platform/knowledge/claim-diffs?subject_id=service:payments&predicate=owner&include_resolved=true" +
		"&from_valid_at=" + baseAt.Add(70*time.Minute).UTC().Format(time.RFC3339) +
		"&from_recorded_at=" + baseAt.Add(70*time.Minute).UTC().Format(time.RFC3339) +
		"&to_valid_at=" + baseAt.Add(3*time.Hour).UTC().Format(time.RFC3339) +
		"&to_recorded_at=" + baseAt.Add(3*time.Hour).UTC().Format(time.RFC3339)
	diffs := do(t, s, http.MethodGet, diffURL, nil)
	if diffs.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim diffs, got %d: %s", diffs.Code, diffs.Body.String())
	}
	diffsBody := decodeJSON(t, diffs)
	diffSummary := diffsBody["summary"].(map[string]any)
	if diffSummary["added_claims"].(float64) < 1 {
		t.Fatalf("expected added claims in diff, got %#v", diffSummary)
	}
	foundBob := false
	for _, raw := range diffsBody["diffs"].([]any) {
		diffRecord := raw.(map[string]any)
		if diffRecord["claim_id"] == bobClaimID && diffRecord["change_type"] == "added" {
			foundBob = true
			break
		}
	}
	if !foundBob {
		t.Fatalf("expected bob claim in diff results, got %#v", diffsBody["diffs"])
	}
}

func TestPlatformKnowledgeAnalysisRejectsInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-groups?needs_adjudication=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid needs_adjudication, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-diffs?from_recorded_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid from_recorded_at, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/knowledge/observations/observation:missing?recorded_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid observation recorded_at, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPlatformKnowledgeClaimGroupDetailIncludesSingleValueGroups(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProps)})

	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	}); err != nil {
		t.Fatalf("write claim: %v", err)
	}

	groupID := "claim_group:service-payments:owner"
	resp := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-groups/"+groupID, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for single-value claim group detail, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if body["id"] != groupID {
		t.Fatalf("expected group id %q, got %#v", groupID, body)
	}
	derived := body["derived"].(map[string]any)
	if derived["needs_adjudication"] != false {
		t.Fatalf("did not expect adjudication for single-value group, got %#v", derived)
	}
}

func seedPlatformKnowledgeScenario(t *testing.T, s *Server) (time.Time, string, string, string) {
	t.Helper()
	g := s.app.SecurityGraph
	baseAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:carol@example.com", Kind: graph.NodeKindPerson, Name: "Carol", Properties: cloneJSONMap(baseProps)})
	evidenceProps := cloneJSONMap(baseProps)
	evidenceProps["evidence_type"] = "document"
	evidenceProps["detail"] = "Runbook excerpt"
	g.AddNode(&graph.Node{ID: "evidence:runbook", Kind: graph.NodeKindEvidence, Name: "Runbook", Properties: evidenceProps})

	observation, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
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
	priorClaim, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	aliceClaim, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	bobClaim, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	supportClaim, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	refutingClaim, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	edgeProps := map[string]any{
		"observed_at":      baseAt.Add(125 * time.Minute).UTC().Format(time.RFC3339),
		"valid_from":       baseAt.Add(125 * time.Minute).UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.Add(125 * time.Minute).UTC().Format(time.RFC3339),
		"transaction_from": baseAt.Add(125 * time.Minute).UTC().Format(time.RFC3339),
	}
	g.AddEdge(&graph.Edge{ID: supportClaim.ClaimID + "->" + aliceClaim.ClaimID + ":supports", Source: supportClaim.ClaimID, Target: aliceClaim.ClaimID, Kind: graph.EdgeKindSupports, Effect: graph.EdgeEffectAllow, Properties: cloneJSONMap(edgeProps)})
	g.AddEdge(&graph.Edge{ID: refutingClaim.ClaimID + "->" + aliceClaim.ClaimID + ":refutes", Source: refutingClaim.ClaimID, Target: aliceClaim.ClaimID, Kind: graph.EdgeKindRefutes, Effect: graph.EdgeEffectAllow, Properties: cloneJSONMap(edgeProps)})

	return baseAt, aliceClaim.ClaimID, bobClaim.ClaimID, observation.ObservationID
}
