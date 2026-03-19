package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreEntityImpactTestGraph() *graph.Graph {
	g := graph.New()

	g.AddNode(&graph.Node{
		ID:   "cust-1",
		Kind: graph.NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"product_tier": "enterprise",
			"industry":     "fintech",
			"region":       "us",
			"arr":          250000,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "cust-2",
		Kind: graph.NodeKindCustomer,
		Name: "Beta",
		Properties: map[string]any{
			"product_tier": "enterprise",
			"industry":     "fintech",
			"region":       "us",
			"arr":          240000,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "cust-3",
		Kind: graph.NodeKindCustomer,
		Name: "Gamma",
		Properties: map[string]any{
			"product_tier": "starter",
			"industry":     "retail",
			"region":       "eu",
			"arr":          12000,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "subscription-1",
		Kind: graph.NodeKindSubscription,
		Name: "Subscription",
		Properties: map[string]any{
			"failed_payment_count": 2,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deal-1",
		Kind: graph.NodeKindDeal,
		Name: "Upsell",
		Properties: map[string]any{
			"deal_value":       80000,
			"days_until_close": 25,
		},
	})

	g.AddEdge(&graph.Edge{ID: "subscription-customer", Source: "subscription-1", Target: "cust-1", Kind: graph.EdgeKindSubscribedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "customer-deal", Source: "cust-1", Target: "deal-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})

	return g
}

func TestEntityImpactHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreEntityImpactTestGraph())

	cohort := do(t, s, http.MethodGet, "/api/v1/entities/cust-1/cohort", nil)
	if cohort.Code != http.StatusOK {
		t.Fatalf("expected entity cohort 200, got %d: %s", cohort.Code, cohort.Body.String())
	}
	cohortBody := decodeJSON(t, cohort)
	members, ok := cohortBody["members"].([]any)
	if !ok || len(members) < 2 {
		t.Fatalf("expected cohort members from store-backed handler, got %#v", cohortBody)
	}

	outlier := do(t, s, http.MethodGet, "/api/v1/entities/cust-1/outlier-score", nil)
	if outlier.Code != http.StatusOK {
		t.Fatalf("expected entity outlier 200, got %d: %s", outlier.Code, outlier.Body.String())
	}
	outlierBody := decodeJSON(t, outlier)
	if _, ok := outlierBody["outlier_score"].(float64); !ok {
		t.Fatalf("expected outlier score from store-backed handler, got %#v", outlierBody)
	}

	impact := do(t, s, http.MethodPost, "/api/v1/impact-analysis", map[string]any{
		"start_node": "subscription-1",
		"scenario":   "revenue_impact",
		"max_depth":  4,
	})
	if impact.Code != http.StatusOK {
		t.Fatalf("expected impact analysis 200, got %d: %s", impact.Code, impact.Body.String())
	}
	impactBody := decodeJSON(t, impact)
	paths, ok := impactBody["paths"].([]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("expected impact paths from store-backed handler, got %#v", impactBody)
	}
}
