package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphIntelligenceInsightsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:ops", Kind: graph.NodeKindRole, Name: "Ops Role"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddNode(&graph.Node{ID: "node:unknown", Kind: graph.NodeKind("api_intel_unknown_kind_v1"), Name: "Unknown"})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/graph/intelligence/insights?window_days=30&include_counterfactual=false&max_insights=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["risk_score"].(float64); !ok {
		t.Fatalf("expected risk_score, got %#v", body["risk_score"])
	}
	if _, ok := body["coverage"].(float64); !ok {
		t.Fatalf("expected coverage, got %#v", body["coverage"])
	}
	insights, ok := body["insights"].([]any)
	if !ok || len(insights) == 0 {
		t.Fatalf("expected insights, got %#v", body["insights"])
	}
	if len(insights) != 1 {
		t.Fatalf("expected max_insights=1 to limit result to one insight, got %d", len(insights))
	}
	first, ok := insights[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first insight object, got %T", insights[0])
	}
	if _, ok := first["confidence"].(float64); !ok {
		t.Fatalf("expected insight confidence, got %#v", first["confidence"])
	}
	if _, ok := first["coverage"].(float64); !ok {
		t.Fatalf("expected insight coverage, got %#v", first["coverage"])
	}
	if _, ok := first["evidence"].([]any); !ok {
		t.Fatalf("expected insight evidence array, got %#v", first["evidence"])
	}
}

func TestGraphIntelligenceInsightsEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/graph/intelligence/insights?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for window_days=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/intelligence/insights?from=2026-03-01T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is missing to, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/intelligence/insights?include_counterfactual=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_counterfactual, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/intelligence/insights?max_insights=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_insights=0, got %d", w.Code)
	}
}

func TestGraphQueryEndpoint_NeighborsAndPaths(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	neighbors := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&direction=out&limit=10", nil)
	if neighbors.Code != http.StatusOK {
		t.Fatalf("expected 200 neighbors, got %d: %s", neighbors.Code, neighbors.Body.String())
	}
	neighborsBody := decodeJSON(t, neighbors)
	if neighborsBody["mode"] != "neighbors" {
		t.Fatalf("expected neighbors mode, got %#v", neighborsBody["mode"])
	}
	if count, ok := neighborsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one neighbor, got %#v", neighborsBody["count"])
	}

	paths := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=paths&node_id=user:alice&target_id=db:prod&k=2&max_depth=6", nil)
	if paths.Code != http.StatusOK {
		t.Fatalf("expected 200 paths, got %d: %s", paths.Code, paths.Body.String())
	}
	pathsBody := decodeJSON(t, paths)
	if pathsBody["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", pathsBody["mode"])
	}
	if count, ok := pathsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", pathsBody["count"])
	}
}

func TestGraphQueryEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})

	w := do(t, s, http.MethodGet, "/api/v1/graph/query", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing node_id, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=unsupported&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=paths&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target_id in paths mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing node, got %d", w.Code)
	}
}
