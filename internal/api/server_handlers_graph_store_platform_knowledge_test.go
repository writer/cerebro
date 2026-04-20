package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

type stubGraphMutator struct {
	graph *graph.Graph
	err   error
}

func (s stubGraphMutator) MutateSecurityGraph(_ context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.graph == nil {
		return nil, errPlatformKnowledgeUnavailable
	}
	if err := mutate(s.graph); err != nil {
		return nil, err
	}
	return s.graph, nil
}

type platformKnowledgeStoreFixture struct {
	graph         *graph.Graph
	aliceClaimID  string
	evidenceID    string
	observationID string
}

func buildGraphStorePlatformKnowledgeFixture(t *testing.T) platformKnowledgeStoreFixture {
	t.Helper()

	s := newTestServer(t)
	_, aliceClaimID, _, observationID := seedPlatformKnowledgeScenario(t, s)

	return platformKnowledgeStoreFixture{
		graph:         s.app.SecurityGraph.Clone(),
		aliceClaimID:  aliceClaimID,
		evidenceID:    "evidence:runbook",
		observationID: observationID,
	}
}

func appendPlatformKnowledgeSupportChain(t *testing.T, g *graph.Graph, targetClaimID string, length int) []string {
	t.Helper()
	claimIDs := make([]string, 0, length)
	baseAt := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	nextTarget := targetClaimID
	for i := 0; i < length; i++ {
		claimID := fmt.Sprintf("claim:payments:owner:alice:chain:%d", i+1)
		at := baseAt.Add(time.Duration(i) * time.Minute)
		if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
			ID:              claimID,
			SubjectID:       "service:payments",
			Predicate:       "ownership_review",
			ObjectID:        "person:alice@example.com",
			SourceSystem:    "chain-test",
			ObservedAt:      at,
			ValidFrom:       at,
			RecordedAt:      at,
			TransactionFrom: at,
		}); err != nil {
			t.Fatalf("write support chain claim %d: %v", i+1, err)
		}
		edgeProps := map[string]any{
			"observed_at":      at.UTC().Format(time.RFC3339),
			"valid_from":       at.UTC().Format(time.RFC3339),
			"recorded_at":      at.UTC().Format(time.RFC3339),
			"transaction_from": at.UTC().Format(time.RFC3339),
		}
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", claimID, nextTarget, graph.EdgeKindSupports),
			Source:     claimID,
			Target:     nextTarget,
			Kind:       graph.EdgeKindSupports,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneJSONMap(edgeProps),
		})
		claimIDs = append(claimIDs, claimID)
		nextTarget = claimID
	}
	return claimIDs
}

func TestPlatformKnowledgeReadHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	s := newStoreBackedGraphServer(t, fixture.graph)

	claims := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?subject_id=service:payments&predicate=owner&include_resolved=true", nil)
	if claims.Code != http.StatusOK {
		t.Fatalf("expected claim list 200, got %d: %s", claims.Code, claims.Body.String())
	}
	claimsBody := decodeJSON(t, claims)
	if got := int(claimsBody["count"].(float64)); got < 2 {
		t.Fatalf("expected multiple claims from store-backed handler, got %#v", claimsBody)
	}

	evidence := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/evidence?claim_id="+fixture.aliceClaimID, nil)
	if evidence.Code != http.StatusOK {
		t.Fatalf("expected evidence list 200, got %d: %s", evidence.Code, evidence.Body.String())
	}
	evidenceBody := decodeJSON(t, evidence)
	if got := int(evidenceBody["count"].(float64)); got != 1 {
		t.Fatalf("expected one evidence record from store-backed handler, got %#v", evidenceBody)
	}

	observation := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/observations/"+fixture.observationID, nil)
	if observation.Code != http.StatusOK {
		t.Fatalf("expected observation detail 200, got %d: %s", observation.Code, observation.Body.String())
	}
	observationBody := decodeJSON(t, observation)
	if observationBody["kind"] != string(graph.NodeKindObservation) {
		t.Fatalf("expected observation detail from store-backed handler, got %#v", observationBody)
	}

	groups := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claim-groups?subject_id=service:payments&predicate=owner&include_resolved=true&include_single_value=true", nil)
	if groups.Code != http.StatusOK {
		t.Fatalf("expected claim groups 200, got %d: %s", groups.Code, groups.Body.String())
	}
	groupsBody := decodeJSON(t, groups)
	groupRecords, ok := groupsBody["groups"].([]any)
	if !ok || len(groupRecords) != 1 {
		t.Fatalf("expected one claim group from store-backed handler, got %#v", groupsBody["groups"])
	}

	explanation := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID+"/explanation", nil)
	if explanation.Code != http.StatusOK {
		t.Fatalf("expected claim explanation 200, got %d: %s", explanation.Code, explanation.Body.String())
	}
	explanationBody := decodeJSON(t, explanation)
	whyTrue, ok := explanationBody["why_true"].([]any)
	if !ok || len(whyTrue) == 0 {
		t.Fatalf("expected explanation content from store-backed handler, got %#v", explanationBody)
	}
}

func TestPlatformKnowledgeDetailHandlersUseStoreSubgraphWhenSnapshotsUnavailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: fixture.graph})

	claim := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID, nil)
	if claim.Code != http.StatusOK {
		t.Fatalf("expected claim detail 200, got %d: %s", claim.Code, claim.Body.String())
	}
	claimBody := decodeJSON(t, claim)
	if claimBody["id"] != fixture.aliceClaimID {
		t.Fatalf("expected claim detail from store subgraph, got %#v", claimBody)
	}
	claimDerived, ok := claimBody["derived"].(map[string]any)
	if !ok || claimDerived["supported"] != true || claimDerived["conflicted"] != true {
		t.Fatalf("expected supported conflicting claim detail, got %#v", claimBody["derived"])
	}

	evidence := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/evidence/"+fixture.evidenceID, nil)
	if evidence.Code != http.StatusOK {
		t.Fatalf("expected evidence detail 200, got %d: %s", evidence.Code, evidence.Body.String())
	}
	evidenceBody := decodeJSON(t, evidence)
	if evidenceBody["kind"] != string(graph.NodeKindEvidence) {
		t.Fatalf("expected evidence detail from store subgraph, got %#v", evidenceBody)
	}

	observation := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/observations/"+fixture.observationID, nil)
	if observation.Code != http.StatusOK {
		t.Fatalf("expected observation detail 200, got %d: %s", observation.Code, observation.Body.String())
	}
	observationBody := decodeJSON(t, observation)
	if observationBody["kind"] != string(graph.NodeKindObservation) {
		t.Fatalf("expected observation detail from store subgraph, got %#v", observationBody)
	}

	explanation := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID+"/explanation", nil)
	if explanation.Code != http.StatusOK {
		t.Fatalf("expected claim explanation 200, got %d: %s", explanation.Code, explanation.Body.String())
	}
	explanationBody := decodeJSON(t, explanation)
	whyTrue, ok := explanationBody["why_true"].([]any)
	if !ok || len(whyTrue) == 0 {
		t.Fatalf("expected explanation content from store subgraph, got %#v", explanationBody)
	}

	timeline := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID+"/timeline", nil)
	if timeline.Code != http.StatusOK {
		t.Fatalf("expected claim timeline 200, got %d: %s", timeline.Code, timeline.Body.String())
	}
	timelineBody := decodeJSON(t, timeline)
	timelineSummary, ok := timelineBody["summary"].(map[string]any)
	if !ok || timelineSummary["total_entries"].(float64) < 1 {
		t.Fatalf("expected timeline content from store subgraph, got %#v", timelineBody)
	}

	proofs := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID+"/proofs", nil)
	if proofs.Code != http.StatusOK {
		t.Fatalf("expected claim proofs 200, got %d: %s", proofs.Code, proofs.Body.String())
	}
	proofsBody := decodeJSON(t, proofs)
	proofSummary, ok := proofsBody["summary"].(map[string]any)
	if !ok || proofSummary["total_proofs"].(float64) < 1 {
		t.Fatalf("expected proof fragments from store subgraph, got %#v", proofsBody)
	}
}

func TestPlatformKnowledgeRecursiveClaimHandlersUseFullStoreGraphWhenSnapshotsUnavailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	chainIDs := appendPlatformKnowledgeSupportChain(t, fixture.graph, fixture.aliceClaimID, 4)
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: fixture.graph})

	timeline := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/"+fixture.aliceClaimID+"/timeline", nil)
	if timeline.Code != http.StatusOK {
		t.Fatalf("expected claim timeline 200, got %d: %s", timeline.Code, timeline.Body.String())
	}
	timelineBody := decodeJSON(t, timeline)
	entries, ok := timelineBody["entries"].([]any)
	if !ok {
		t.Fatalf("expected timeline entries, got %#v", timelineBody["entries"])
	}
	deepestClaimID := chainIDs[len(chainIDs)-1]
	foundDeepest := false
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		claim, ok := entry["claim"].(map[string]any)
		if !ok {
			continue
		}
		if claim["id"] == deepestClaimID {
			foundDeepest = true
			break
		}
	}
	if !foundDeepest {
		t.Fatalf("expected deepest support claim %q in timeline entries, got %#v", deepestClaimID, entries)
	}
}

func TestPlatformKnowledgeReadHandlersPreferLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: fixture.graph,
			store: failingSnapshotGraphStore{GraphStore: fixture.graph},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?subject_id=service:payments&predicate=owner&include_resolved=true", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected claim list 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestPlatformKnowledgeDetailHandlersPreferLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	store := &countingSnapshotStore{GraphStore: fixture.graph}
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: fixture.graph,
			store: store,
		},
	})
	t.Cleanup(func() { s.Close() })

	for _, path := range []string{
		"/api/v1/platform/knowledge/claims/" + fixture.aliceClaimID,
		"/api/v1/platform/knowledge/evidence/" + fixture.evidenceID,
		"/api/v1/platform/knowledge/observations/" + fixture.observationID,
		"/api/v1/platform/knowledge/claims/" + fixture.aliceClaimID + "/explanation",
		"/api/v1/platform/knowledge/claims/" + fixture.aliceClaimID + "/timeline",
		"/api/v1/platform/knowledge/claims/" + fixture.aliceClaimID + "/proofs",
	} {
		resp := do(t, s, http.MethodGet, path, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d: %s", path, resp.Code, resp.Body.String())
		}
	}

	if got := store.count.Load(); got != 0 {
		t.Fatalf("expected live graph detail handlers to avoid snapshots, got %d snapshot calls", got)
	}
}

func TestPlatformKnowledgeAdjudicationUsesGraphMutatorWhenRawGraphUnavailable(t *testing.T) {
	fixture := buildGraphStorePlatformKnowledgeFixture(t)
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		graphRuntime: stubGraphRuntime{store: fixture.graph},
		graphMutator: stubGraphMutator{graph: fixture.graph},
	})
	t.Cleanup(func() { s.Close() })

	if s.app.SecurityGraph != nil {
		t.Fatalf("expected dependency bundle to start without a direct security graph, got %p", s.app.SecurityGraph)
	}

	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	resp := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claim-groups/claim_group:service-payments:owner/adjudications", map[string]any{
		"action":                 "accept_existing",
		"authoritative_claim_id": fixture.aliceClaimID,
		"actor":                  "reviewer:alice",
		"rationale":              "authoritative source",
		"source_system":          "api",
		"source_event_id":        "adj-001",
		"observed_at":            base.Format(time.RFC3339),
		"valid_from":             base.Format(time.RFC3339),
		"recorded_at":            base.Format(time.RFC3339),
		"transaction_from":       base.Format(time.RFC3339),
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected adjudication 201, got %d: %s", resp.Code, resp.Body.String())
	}

	body := decodeJSON(t, resp)
	createdClaimID, _ := body["created_claim_id"].(string)
	if createdClaimID == "" {
		t.Fatalf("expected created claim id from store-backed adjudication, got %#v", body)
	}
	node, ok := fixture.graph.GetNode(createdClaimID)
	if !ok || node == nil || node.Kind != graph.NodeKindClaim {
		t.Fatalf("expected adjudication to mutate graph through graph mutator, got %#v", node)
	}
}
