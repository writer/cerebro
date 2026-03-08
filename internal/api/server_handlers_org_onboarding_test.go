package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

func TestOrgOnboardingPlanEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgOnboardingGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/org/onboarding/person:newhire@example.com/plan", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["person_id"] != "person:newhire@example.com" {
		t.Fatalf("expected person_id person:newhire@example.com, got %v", body["person_id"])
	}
	if _, ok := body["generated_at"].(string); !ok {
		t.Fatalf("expected generated_at field, got %T", body["generated_at"])
	}
	if cohortSize, ok := body["cohort_size"].(float64); !ok || int(cohortSize) != 2 {
		t.Fatalf("expected cohort_size=2, got %v", body["cohort_size"])
	}
	if body["predecessor_id"] != "person:legacy@example.com" {
		t.Fatalf("expected predecessor_id person:legacy@example.com, got %v", body["predecessor_id"])
	}

	repositories, ok := body["repositories"].([]any)
	if !ok || len(repositories) == 0 {
		t.Fatalf("expected repository recommendations, got %T %#v", body["repositories"], body["repositories"])
	}
}

func TestOrgOnboardingPlanEndpoint_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/org/onboarding/person:missing@example.com/plan", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func seedOrgOnboardingGraph(g *graph.Graph) {
	g.AddNode(&graph.Node{ID: "person:newhire@example.com", Kind: graph.NodeKindPerson, Name: "New Hire", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "platform",
		"status":     "active",
	}})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "platform",
		"status":     "active",
	}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "platform",
		"status":     "active",
	}})
	g.AddNode(&graph.Node{ID: "person:legacy@example.com", Kind: graph.NodeKindPerson, Name: "Legacy", Properties: map[string]any{
		"department":       "engineering",
		"title":            "Senior Engineer",
		"team":             "platform",
		"status":           "terminated",
		"termination_date": "2026-01-20T00:00:00Z",
	}})
	g.AddNode(&graph.Node{ID: "repo:core", Kind: graph.NodeKindRepository, Name: "core-repo"})
	g.AddEdge(&graph.Edge{ID: "alice-core", Source: "person:alice@example.com", Target: "repo:core", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"commit_count": 30}})
	g.AddEdge(&graph.Edge{ID: "bob-core", Source: "person:bob@example.com", Target: "repo:core", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"review_count": 20}})
	g.AddEdge(&graph.Edge{ID: "legacy-core", Source: "person:legacy@example.com", Target: "repo:core", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"commit_count": 40}})
}
