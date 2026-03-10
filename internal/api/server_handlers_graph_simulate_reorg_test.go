package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphSimulateReorgEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedSimulateReorgGraph(s.app.SecurityGraph)

	body := map[string]any{
		"changes": []map[string]any{
			{
				"person":         "person:bob@example.com",
				"new_department": "Platform",
				"new_manager":    "person:vp@example.com",
			},
		},
	}
	w := do(t, s, http.MethodPost, "/api/v1/org/reorg-simulations", body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Deprecation"); got != "" {
		t.Fatalf("did not expect deprecation header on org reorg endpoint, got %q", got)
	}

	decoded := decodeJSON(t, w)
	bridges, ok := decoded["broken_bridges"].([]any)
	if !ok || len(bridges) == 0 {
		t.Fatalf("expected broken bridges in response, got %T %#v", decoded["broken_bridges"], decoded["broken_bridges"])
	}
	actions, ok := decoded["recommended_actions"].([]any)
	if !ok || len(actions) == 0 {
		t.Fatalf("expected recommended actions in response, got %T %#v", decoded["recommended_actions"], decoded["recommended_actions"])
	}
}

func TestGraphSimulateReorgEndpoint_Validation(t *testing.T) {
	s := newTestServer(t)
	seedSimulateReorgGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodPost, "/api/v1/org/reorg-simulations", map[string]any{"changes": []any{}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty changes, got %d", w.Code)
	}

	w = do(t, s, http.MethodPost, "/api/v1/org/reorg-simulations", map[string]any{
		"changes": []map[string]any{
			{
				"person":         "person:unknown@example.com",
				"new_department": "Platform",
			},
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown person, got %d", w.Code)
	}
}

func TestOrgReorgSimulationEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedSimulateReorgGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodPost, "/api/v1/org/reorg-simulations", map[string]any{
		"changes": []map[string]any{{
			"person":         "person:bob@example.com",
			"new_department": "Platform",
			"new_manager":    "person:vp@example.com",
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for org reorg simulation endpoint, got %d: %s", w.Code, w.Body.String())
	}
	decoded := decodeJSON(t, w)
	if _, ok := decoded["recommended_actions"].([]any); !ok {
		t.Fatalf("expected recommended_actions in org response, got %#v", decoded["recommended_actions"])
	}
}

func seedSimulateReorgGraph(g *graph.Graph) {
	g.AddNode(&graph.Node{ID: "department:support", Kind: graph.NodeKindDepartment, Name: "Support"})
	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "person:vp@example.com", Kind: graph.NodeKindPerson, Name: "VP", Properties: map[string]any{"title": "VP Engineering"}})

	g.AddNode(&graph.Node{ID: "system:payments", Kind: graph.NodeKindApplication, Name: "payments", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	g.AddNode(&graph.Node{ID: "ticket:incident-1", Kind: graph.NodeKindTicket, Name: "Incident 1", Properties: map[string]any{"severity": "high"}})

	g.AddEdge(&graph.Edge{ID: "m1", Source: "person:alice@example.com", Target: "department:support", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m2", Source: "person:bob@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "i1", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 12}})
	g.AddEdge(&graph.Edge{ID: "s1", Source: "person:bob@example.com", Target: "system:payments", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "c1", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "c2", Source: "person:bob@example.com", Target: "customer:acme", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "t1", Source: "ticket:incident-1", Target: "person:alice@example.com", Kind: graph.EdgeKindEscalatedTo, Effect: graph.EdgeEffectAllow})
}
