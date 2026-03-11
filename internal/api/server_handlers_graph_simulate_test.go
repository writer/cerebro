package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestGraphSimulateEndpoint_WithMutations(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "role-1", Kind: graph.NodeKindRole, Name: "role-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 100000.0}})
	g.AddEdge(&graph.Edge{ID: "user-role", Source: "user-1", Target: "role-1", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-customer", Source: "role-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	w := do(t, s, http.MethodPost, "/api/v1/graph/simulate", map[string]any{
		"mutations": []map[string]any{
			{"type": "remove_edge", "source": "user-1", "target": "role-1", "kind": "can_assume"},
			{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": true}},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	delta, ok := body["delta"].(map[string]any)
	if !ok {
		t.Fatalf("expected delta object, got %T", body["delta"])
	}
	if _, ok := delta["risk_score_delta"]; !ok {
		t.Fatalf("expected risk_score_delta in response delta, got %v", delta)
	}

	before, ok := body["before"].(map[string]any)
	if !ok {
		t.Fatalf("expected before object, got %T", body["before"])
	}
	if arr, ok := before["affected_arr"].(float64); !ok || arr <= 0 {
		t.Fatalf("expected positive affected_arr in before snapshot, got %v", before["affected_arr"])
	}

	// Simulation must not mutate the live graph.
	edges := g.GetOutEdges("user-1")
	found := false
	for _, edge := range edges {
		if edge.Target == "role-1" && edge.Kind == graph.EdgeKindCanAssume {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected original graph edge to remain after simulation")
	}
}

func TestGraphSimulateEndpoint_RequiresMutations(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/graph/simulate", map[string]any{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
