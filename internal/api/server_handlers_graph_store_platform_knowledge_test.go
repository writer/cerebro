package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type platformKnowledgeStoreFixture struct {
	graph         *graph.Graph
	aliceClaimID  string
	observationID string
}

func buildGraphStorePlatformKnowledgeFixture(t *testing.T) platformKnowledgeStoreFixture {
	t.Helper()

	s := newTestServer(t)
	_, aliceClaimID, _, observationID := seedPlatformKnowledgeScenario(t, s)

	return platformKnowledgeStoreFixture{
		graph:         s.app.SecurityGraph.Clone(),
		aliceClaimID:  aliceClaimID,
		observationID: observationID,
	}
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
