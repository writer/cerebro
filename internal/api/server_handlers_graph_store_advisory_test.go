package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreAdvisoryTestGraph() *graph.Graph {
	g := graph.New()
	seedRecommendTeamGraph(g)

	g.AddNode(&graph.Node{ID: "system:auth-svc", Kind: graph.NodeKindApplication, Name: "auth-svc"})
	g.AddNode(&graph.Node{ID: "person:dora@example.com", Kind: graph.NodeKindPerson, Name: "Dora", Properties: map[string]any{"status": "active"}})
	now := time.Now().UTC()
	g.AddEdge(&graph.Edge{
		ID:     "dora-auth",
		Source: "person:dora@example.com",
		Target: "system:auth-svc",
		Kind:   graph.EdgeKindManagedBy,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"commit_count": 120,
			"last_seen":    now,
		},
	})

	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "svc-1", Kind: graph.NodeKindApplication, Name: "svc-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 1500000.0}})
	g.AddEdge(&graph.Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()
	return g
}

func TestGraphAdvisoryHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreAdvisoryTestGraph())

	whoKnows := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=auth-svc&limit=1", nil)
	if whoKnows.Code != http.StatusOK {
		t.Fatalf("expected who-knows 200, got %d: %s", whoKnows.Code, whoKnows.Body.String())
	}

	recommend := do(t, s, http.MethodPost, "/api/v1/org/team-recommendations", map[string]any{
		"target_systems": []string{"payment-service", "billing-api"},
		"team_size":      2,
	})
	if recommend.Code != http.StatusOK {
		t.Fatalf("expected team recommendation 200, got %d: %s", recommend.Code, recommend.Body.String())
	}

	evaluate := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{
		"id":                     "proposal-1",
		"source":                 "api-test",
		"reason":                 "quarterly review",
		"approval_arr_threshold": 100000.0,
		"mutations":              []map[string]any{{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": false}}},
	})
	if evaluate.Code != http.StatusOK {
		t.Fatalf("expected evaluate-change 200, got %d: %s", evaluate.Code, evaluate.Body.String())
	}
}
