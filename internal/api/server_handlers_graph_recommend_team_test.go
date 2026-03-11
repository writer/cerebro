package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestRecommendTeamEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedRecommendTeamGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodPost, "/api/v1/org/team-recommendations", map[string]any{
		"target_systems": []string{"payment-service", "billing-api"},
		"domains":        []string{"payments", "customer-facing"},
		"team_size":      2,
		"constraints": map[string]any{
			"max_bus_factor_impact":         1,
			"prefer_existing_collaboration": true,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	recommended, ok := body["recommended_team"].([]any)
	if !ok || len(recommended) == 0 {
		t.Fatalf("expected recommended_team payload, got %T %#v", body["recommended_team"], body["recommended_team"])
	}
	analysis, ok := body["analysis"].(map[string]any)
	if !ok {
		t.Fatalf("expected analysis object, got %T", body["analysis"])
	}
	if coverage, ok := analysis["knowledge_coverage"].(float64); !ok || coverage <= 0 {
		t.Fatalf("expected positive knowledge coverage, got %v", analysis["knowledge_coverage"])
	}

	first, ok := recommended[0].(map[string]any)
	if !ok {
		t.Fatalf("expected recommended candidate object, got %T", recommended[0])
	}
	person, ok := first["person"].(map[string]any)
	if !ok {
		t.Fatalf("expected embedded person object, got %T", first["person"])
	}
	if person["id"] == "" {
		t.Fatalf("expected person id in recommendation, got %+v", person)
	}
}

func TestRecommendTeamEndpoint_RequiresTargetSystems(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/org/team-recommendations", map[string]any{
		"team_size": 3,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func seedRecommendTeamGraph(g *graph.Graph) {
	g.AddNode(&graph.Node{ID: "system:payment-service", Kind: graph.NodeKindApplication, Name: "payment-service"})
	g.AddNode(&graph.Node{ID: "system:billing-api", Kind: graph.NodeKindRepository, Name: "billing-api"})

	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&graph.Node{ID: "department:product", Kind: graph.NodeKindDepartment, Name: "Product"})

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"domains":       []string{"payments", "customer-facing"},
		"open_issues":   2,
		"team_count":    1,
		"meeting_hours": 4.0,
	}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{
		"domains":       []string{"payments"},
		"open_issues":   10,
		"team_count":    2,
		"meeting_hours": 10.0,
	}})
	g.AddNode(&graph.Node{ID: "person:carol@example.com", Kind: graph.NodeKindPerson, Name: "Carol", Properties: map[string]any{
		"domains":       []string{"billing"},
		"open_issues":   3,
		"team_count":    1,
		"meeting_hours": 5.0,
	}})

	g.AddEdge(&graph.Edge{ID: "member-alice", Source: "person:alice@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "member-bob", Source: "person:bob@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "member-carol", Source: "person:carol@example.com", Target: "department:product", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})

	g.AddEdge(&graph.Edge{ID: "alice-payment", Source: "person:alice@example.com", Target: "system:payment-service", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"commit_count": 120}})
	g.AddEdge(&graph.Edge{ID: "alice-billing", Source: "person:alice@example.com", Target: "system:billing-api", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"review_count": 60}})
	g.AddEdge(&graph.Edge{ID: "bob-payment", Source: "person:bob@example.com", Target: "system:payment-service", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"review_count": 40}})
	g.AddEdge(&graph.Edge{ID: "carol-billing", Source: "person:carol@example.com", Target: "system:billing-api", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"issue_count": 20}})
	g.AddEdge(&graph.Edge{ID: "alice-bob", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"strength": 0.8}})
}
