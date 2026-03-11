package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestEvaluateGraphChangeEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "svc-1", Kind: graph.NodeKindApplication, Name: "svc-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 1500000.0}})
	g.AddEdge(&graph.Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	w := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{
		"id":                     "proposal-1",
		"source":                 "api-test",
		"reason":                 "quarterly review",
		"approval_arr_threshold": 100000.0,
		"mutations":              []map[string]any{{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": false}}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["decision"] != string(graph.DecisionNeedsApproval) {
		t.Fatalf("expected decision %q, got %v", graph.DecisionNeedsApproval, body["decision"])
	}
	if _, ok := body["risk_score_delta"].(float64); !ok {
		t.Fatalf("expected risk_score_delta numeric field, got %T", body["risk_score_delta"])
	}
	if arr, ok := body["affected_arr"].(float64); !ok || arr <= 0 {
		t.Fatalf("expected affected_arr > 0, got %v", body["affected_arr"])
	}
}

func TestEvaluateGraphChangeEndpoint_RequiresMutations(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{"id": "p1"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
