package graph

import "testing"

func TestAnalyzeEntityPeerGroups(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "cust-1",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"product_tier": "enterprise",
			"industry":     "fintech",
			"region":       "us",
			"arr":          250000,
		},
	})
	g.AddNode(&Node{
		ID:   "cust-2",
		Kind: NodeKindCustomer,
		Name: "Beta",
		Properties: map[string]any{
			"product_tier": "enterprise",
			"industry":     "fintech",
			"region":       "us",
			"arr":          240000,
		},
	})
	g.AddNode(&Node{
		ID:   "cust-3",
		Kind: NodeKindCustomer,
		Name: "Gamma",
		Properties: map[string]any{
			"product_tier": "starter",
			"industry":     "retail",
			"region":       "eu",
			"arr":          12000,
		},
	})

	analysis := AnalyzeEntityPeerGroups(g, 0.6, 2)
	if analysis.TotalEntities != 3 {
		t.Fatalf("expected 3 entities, got %d", analysis.TotalEntities)
	}
	if len(analysis.Groups) == 0 {
		t.Fatal("expected at least one cohort")
	}

	cohort, ok := GetEntityCohort(g, "cust-1")
	if !ok {
		t.Fatal("expected cohort for cust-1")
	}
	if len(cohort.Members) < 2 {
		t.Fatalf("expected >=2 cohort members, got %d", len(cohort.Members))
	}

	outlier, ok := GetEntityOutlierScore(g, "cust-1")
	if !ok {
		t.Fatal("expected outlier score for cohort member")
	}
	if outlier.OutlierScore < 0 {
		t.Fatalf("invalid outlier score %.2f", outlier.OutlierScore)
	}
}
