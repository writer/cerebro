package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreSimulationTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "role-1", Kind: graph.NodeKindRole, Name: "role-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 100000.0}})
	g.AddEdge(&graph.Edge{ID: "user-role", Source: "user-1", Target: "role-1", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-customer", Source: "role-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()
	return g
}

func TestGraphSimulationHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	sim := newStoreBackedGraphServer(t, buildGraphStoreSimulationTestGraph())

	w := do(t, sim, http.MethodPost, "/api/v1/graph/simulate", map[string]any{
		"mutations": []map[string]any{
			{"type": "remove_edge", "source": "user-1", "target": "role-1", "kind": "can_assume"},
			{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": true}},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected simulate 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if _, ok := body["delta"].(map[string]any); !ok {
		t.Fatalf("expected delta object from store-backed simulate handler, got %#v", body["delta"])
	}

	reorgGraph := graph.New()
	seedSimulateReorgGraph(reorgGraph)
	reorg := newStoreBackedGraphServer(t, reorgGraph)

	resp := do(t, reorg, http.MethodPost, "/api/v1/org/reorg-simulations", map[string]any{
		"changes": []map[string]any{{
			"person":         "person:bob@example.com",
			"new_department": "Platform",
			"new_manager":    "person:vp@example.com",
		}},
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected reorg simulation 200, got %d: %s", resp.Code, resp.Body.String())
	}
	decoded := decodeJSON(t, resp)
	if _, ok := decoded["recommended_actions"].([]any); !ok {
		t.Fatalf("expected recommended_actions from store-backed reorg handler, got %#v", decoded["recommended_actions"])
	}
}
