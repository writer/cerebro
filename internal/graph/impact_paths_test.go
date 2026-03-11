package graph

import (
	"fmt"
	"testing"
)

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

func TestImpactPathAnalyzer_ChokepointAccountsForAlternatePaths(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "start", Kind: NodeKindSubscription, Name: "Start"})
	g.AddNode(&Node{ID: "bridge", Kind: NodeKindApplication, Name: "Bridge"})
	g.AddNode(&Node{ID: "alt", Kind: NodeKindApplication, Name: "Alt"})
	g.AddNode(&Node{ID: "target-1", Kind: NodeKindCustomer, Name: "Target 1", Properties: map[string]any{"arr": 200000}})
	g.AddNode(&Node{ID: "target-2", Kind: NodeKindCustomer, Name: "Target 2", Properties: map[string]any{"arr": 100000}})

	g.AddEdge(&Edge{ID: "s-b", Source: "start", Target: "bridge", Kind: EdgeKindSubscribedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "s-a", Source: "start", Target: "alt", Kind: EdgeKindSubscribedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "b-t1", Source: "bridge", Target: "target-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "a-t1", Source: "alt", Target: "target-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "b-t2", Source: "bridge", Target: "target-2", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	analyzer := NewImpactPathAnalyzer(g)
	result := analyzer.Analyze("start", ImpactScenarioRevenueImpact, 3)
	if len(result.Paths) != 3 {
		t.Fatalf("expected 3 impact paths, got %d", len(result.Paths))
	}

	var bridge *Chokepoint
	for _, cp := range result.Chokepoints {
		if cp.Node != nil && cp.Node.ID == "bridge" {
			bridge = cp
			break
		}
	}
	if bridge == nil {
		t.Fatal("expected bridge chokepoint to be present")
	}

	if bridge.PathsThrough != 2 {
		t.Fatalf("expected bridge PathsThrough=2, got %d", bridge.PathsThrough)
	}
	if bridge.BlockedPaths != 1 {
		t.Fatalf("expected bridge BlockedPaths=1, got %d", bridge.BlockedPaths)
	}
	if bridge.RemediationImpact != 0.5 {
		t.Fatalf("expected bridge RemediationImpact=0.5, got %.3f", bridge.RemediationImpact)
	}
	if bridge.BetweennessCentrality <= bridge.RemediationImpact {
		t.Fatalf("expected betweenness centrality %.3f to exceed remediation impact %.3f", bridge.BetweennessCentrality, bridge.RemediationImpact)
	}
}

func TestImpactPathAnalyzer_KeepsTopFiftyPathsByScore(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "start", Kind: NodeKindSubscription, Name: "Start"})

	for i := 1; i <= 60; i++ {
		id := fmt.Sprintf("customer-%02d", i)
		g.AddNode(&Node{
			ID:         id,
			Kind:       NodeKindCustomer,
			Name:       id,
			Properties: map[string]any{"arr": float64(i * 100000)},
		})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("edge-%02d", i),
			Source: "start",
			Target: id,
			Kind:   EdgeKindSubscribedTo,
			Effect: EdgeEffectAllow,
		})
	}

	analyzer := NewImpactPathAnalyzer(g)
	result := analyzer.Analyze("start", ImpactScenarioRevenueImpact, 2)

	if len(result.Paths) != 50 {
		t.Fatalf("expected top 50 paths, got %d", len(result.Paths))
	}

	if result.Paths[0].Score < result.Paths[len(result.Paths)-1].Score {
		t.Fatalf("expected descending score order, got first %.2f last %.2f", result.Paths[0].Score, result.Paths[len(result.Paths)-1].Score)
	}

	keptTargets := make(map[string]struct{}, len(result.Paths))
	for _, path := range result.Paths {
		keptTargets[path.EndNode] = struct{}{}
	}
	for i := 1; i <= 10; i++ {
		lowID := fmt.Sprintf("customer-%02d", i)
		if _, ok := keptTargets[lowID]; ok {
			t.Fatalf("expected low-score path target %s to be evicted from top 50", lowID)
		}
	}
}
