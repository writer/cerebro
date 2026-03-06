package graph

import "testing"

func TestImpactPathAnalyzer_RevenueImpact(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "subscription-1", Kind: NodeKindSubscription, Name: "Subscription", Properties: map[string]any{"failed_payment_count": 2}})
	g.AddNode(&Node{ID: "customer-1", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 300000}})
	g.AddNode(&Node{ID: "deal-1", Kind: NodeKindDeal, Name: "Upsell", Properties: map[string]any{"deal_value": 80000, "days_until_close": 25}})

	g.AddEdge(&Edge{ID: "s-c", Source: "subscription-1", Target: "customer-1", Kind: EdgeKindSubscribedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "c-d", Source: "customer-1", Target: "deal-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	analyzer := NewImpactPathAnalyzer(g)
	result := analyzer.Analyze("subscription-1", ImpactScenarioRevenueImpact, 4)

	if len(result.Paths) == 0 {
		t.Fatal("expected impact paths")
	}
	if result.AggregateMetrics["combined_arr"] <= 0 {
		t.Fatalf("expected combined_arr > 0, got %.2f", result.AggregateMetrics["combined_arr"])
	}
}

func TestImpactPathAnalyzer_IncidentBlastRadius(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service-1", Kind: NodeKindApplication, Name: "API Service", Properties: map[string]any{"outage_detected": true}})
	g.AddNode(&Node{ID: "customer-1", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 500000}})
	g.AddNode(&Node{ID: "customer-2", Kind: NodeKindCustomer, Name: "Beta", Properties: map[string]any{"arr": 400000}})

	g.AddEdge(&Edge{ID: "s-c1", Source: "service-1", Target: "customer-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "s-c2", Source: "service-1", Target: "customer-2", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	analyzer := NewImpactPathAnalyzer(g)
	result := analyzer.Analyze("service-1", ImpactScenarioIncidentBlast, 3)

	if result.TotalAffectedEntities < 2 {
		t.Fatalf("expected at least 2 affected entities, got %d", result.TotalAffectedEntities)
	}
	if len(result.Paths) == 0 {
		t.Fatal("expected at least one incident impact path")
	}
}
