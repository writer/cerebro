package api

import (
	"context"
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
