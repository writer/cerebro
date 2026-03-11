package graph

import (
	"slices"
	"testing"
	"time"
)

func TestComputeRelationshipHealthWithTemplate_Metrics(t *testing.T) {
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 750000.0}})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"title": "Account Owner"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"title": "Principal Engineer"}})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: map[string]any{"title": "VP Customer Success"}})

	addCustomerTouchpoint(g, "person:alice@example.com", "customer:acme", EdgeKindManagedBy, map[string]any{
		"role":               "account_owner",
		"frequency":          12,
		"strength":           1.4,
		"previous_frequency": 9,
		"previous_strength":  1.1,
		"last_seen":          now.Add(-12 * time.Hour),
	})
	addCustomerTouchpoint(g, "person:bob@example.com", "customer:acme", EdgeKindAssignedTo, map[string]any{
		"role":               "technical_contact",
		"frequency":          10,
		"strength":           1.2,
		"previous_frequency": 8,
		"previous_strength":  1.0,
		"last_seen":          now.Add(-24 * time.Hour),
	})
	addCustomerTouchpoint(g, "person:carol@example.com", "customer:acme", EdgeKindManagedBy, map[string]any{
		"role":               "executive_sponsor",
		"frequency":          4,
		"strength":           0.9,
		"previous_frequency": 3,
		"previous_strength":  0.7,
		"last_seen":          now.Add(-36 * time.Hour),
	})

	addPeopleInteraction(g, "person:alice@example.com", "person:bob@example.com", now.Add(-8*time.Hour), 14, 1.2)
	addPeopleInteraction(g, "person:bob@example.com", "person:carol@example.com", now.Add(-10*time.Hour), 9, 1.0)

	template := IdealRelationshipTemplate{
		MinTouchpoints:      3,
		MinRoleDiversity:    0.5,
		MinInteractionFreq:  0.4,
		MinInternalCohesion: 0.3,
		RequiredRoles:       []string{"account_owner", "technical_contact", "executive_sponsor"},
	}
	health := ComputeRelationshipHealthWithTemplate(g, "customer:acme", template)

	if health.TouchpointCount != 3 {
		t.Fatalf("expected 3 touchpoints, got %d", health.TouchpointCount)
	}
	if health.RoleDiversity <= 0.5 {
		t.Fatalf("expected role diversity > 0.5, got %.3f", health.RoleDiversity)
	}
	if health.InteractionFrequency <= 0.5 {
		t.Fatalf("expected interaction frequency > 0.5, got %.3f", health.InteractionFrequency)
	}
	if health.InternalCohesion <= 0.5 {
		t.Fatalf("expected internal cohesion > 0.5, got %.3f", health.InternalCohesion)
	}
	if health.RecencyScore <= 0.5 {
		t.Fatalf("expected recency score > 0.5, got %.3f", health.RecencyScore)
	}
	if health.HealthScore <= 60 {
		t.Fatalf("expected health score > 60, got %.2f", health.HealthScore)
	}
	if health.TouchpointTrend == "declining" {
		t.Fatalf("expected non-declining touchpoint trend, got %q", health.TouchpointTrend)
	}
}

func TestComputeCustomerRelationshipHealthWithTemplate_AssignsPercentiles(t *testing.T) {
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "customer:healthy", Kind: NodeKindCustomer, Name: "HealthyCo", Properties: map[string]any{"arr": 400000.0}})
	g.AddNode(&Node{ID: "customer:weak", Kind: NodeKindCustomer, Name: "WeakCo", Properties: map[string]any{"arr": 420000.0}})
	g.AddNode(&Node{ID: "person:a", Kind: NodeKindPerson, Name: "A", Properties: map[string]any{"title": "Account Owner"}})
	g.AddNode(&Node{ID: "person:b", Kind: NodeKindPerson, Name: "B", Properties: map[string]any{"title": "Staff Engineer"}})
	g.AddNode(&Node{ID: "person:c", Kind: NodeKindPerson, Name: "C", Properties: map[string]any{"title": "VP Sales"}})
	g.AddNode(&Node{ID: "person:d", Kind: NodeKindPerson, Name: "D", Properties: map[string]any{"title": "Support Engineer"}})

	addCustomerTouchpoint(g, "person:a", "customer:healthy", EdgeKindManagedBy, map[string]any{"role": "account_owner", "frequency": 12, "last_seen": now.Add(-4 * time.Hour), "previous_strength": 0.8})
	addCustomerTouchpoint(g, "person:b", "customer:healthy", EdgeKindAssignedTo, map[string]any{"role": "technical_contact", "frequency": 10, "last_seen": now.Add(-6 * time.Hour), "previous_strength": 0.7})
	addCustomerTouchpoint(g, "person:c", "customer:healthy", EdgeKindManagedBy, map[string]any{"role": "executive_sponsor", "frequency": 5, "last_seen": now.Add(-12 * time.Hour), "previous_strength": 0.6})
	addPeopleInteraction(g, "person:a", "person:b", now.Add(-6*time.Hour), 12, 1.2)
	addPeopleInteraction(g, "person:b", "person:c", now.Add(-8*time.Hour), 7, 1.0)

	addCustomerTouchpoint(g, "person:d", "customer:weak", EdgeKindAssignedTo, map[string]any{
		"role":               "support_contact",
		"frequency":          1,
		"strength":           0.1,
		"previous_frequency": 6,
		"previous_strength":  0.8,
		"last_seen":          now.Add(-180 * 24 * time.Hour),
	})

	template := IdealRelationshipTemplate{
		MinTouchpoints:      3,
		MinRoleDiversity:    0.5,
		MinInteractionFreq:  0.4,
		MinInternalCohesion: 0.35,
		RequiredRoles:       []string{"account_owner", "technical_contact"},
	}
	results := ComputeCustomerRelationshipHealthWithTemplate(g, template)
	if len(results) != 2 {
		t.Fatalf("expected 2 customer health results, got %d", len(results))
	}

	healthy := findCustomerHealth(results, "customer:healthy")
	weak := findCustomerHealth(results, "customer:weak")
	if healthy == nil || weak == nil {
		t.Fatalf("expected both customer metrics, got %+v", results)
	}
	if healthy.HealthScore <= weak.HealthScore {
		t.Fatalf("expected healthy score > weak score (%.2f <= %.2f)", healthy.HealthScore, weak.HealthScore)
	}
	if healthy.CohortPercentile <= weak.CohortPercentile {
		t.Fatalf("expected healthy percentile > weak percentile (%d <= %d)", healthy.CohortPercentile, weak.CohortPercentile)
	}
}

func TestBuildIdealRelationshipTemplate_DerivesRequiredRoles(t *testing.T) {
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	for _, customer := range []*Node{
		{ID: "customer:gold", Kind: NodeKindCustomer, Name: "Gold", Properties: map[string]any{"arr": 1200000.0, "nps": 82, "tenure_years": 4.2, "renewal_rate": 0.95}},
		{ID: "customer:silver", Kind: NodeKindCustomer, Name: "Silver", Properties: map[string]any{"arr": 800000.0, "nps": 76, "tenure_years": 3.1, "renewal_rate": 0.9}},
		{ID: "customer:bronze", Kind: NodeKindCustomer, Name: "Bronze", Properties: map[string]any{"arr": 200000.0, "nps": 20, "tenure_years": 0.8, "renewal_rate": 0.3}},
		{ID: "customer:trial", Kind: NodeKindCustomer, Name: "Trial", Properties: map[string]any{"arr": 90000.0, "nps": 10, "tenure_years": 0.3, "renewal_rate": 0.1}},
	} {
		g.AddNode(customer)
	}

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner", Properties: map[string]any{"title": "Account Owner"}})
	g.AddNode(&Node{ID: "person:tech", Kind: NodeKindPerson, Name: "Tech", Properties: map[string]any{"title": "Principal Engineer"}})
	g.AddNode(&Node{ID: "person:exec", Kind: NodeKindPerson, Name: "Exec", Properties: map[string]any{"title": "VP Customer Success"}})
	g.AddNode(&Node{ID: "person:support", Kind: NodeKindPerson, Name: "Support", Properties: map[string]any{"title": "Support Engineer"}})

	addCustomerTouchpoint(g, "person:owner", "customer:gold", EdgeKindManagedBy, map[string]any{"role": "account_owner", "frequency": 14, "last_seen": now.Add(-4 * time.Hour)})
	addCustomerTouchpoint(g, "person:tech", "customer:gold", EdgeKindAssignedTo, map[string]any{"role": "technical_contact", "frequency": 12, "last_seen": now.Add(-6 * time.Hour)})
	addCustomerTouchpoint(g, "person:exec", "customer:gold", EdgeKindManagedBy, map[string]any{"role": "executive_sponsor", "frequency": 5, "last_seen": now.Add(-8 * time.Hour)})
	addPeopleInteraction(g, "person:owner", "person:tech", now.Add(-3*time.Hour), 15, 1.3)
	addPeopleInteraction(g, "person:tech", "person:exec", now.Add(-6*time.Hour), 10, 1.0)

	addCustomerTouchpoint(g, "person:owner", "customer:silver", EdgeKindManagedBy, map[string]any{"role": "account_owner", "frequency": 10, "last_seen": now.Add(-8 * time.Hour)})
	addCustomerTouchpoint(g, "person:tech", "customer:silver", EdgeKindAssignedTo, map[string]any{"role": "technical_contact", "frequency": 8, "last_seen": now.Add(-12 * time.Hour)})
	addCustomerTouchpoint(g, "person:exec", "customer:silver", EdgeKindManagedBy, map[string]any{"role": "executive_sponsor", "frequency": 4, "last_seen": now.Add(-20 * time.Hour)})

	addCustomerTouchpoint(g, "person:support", "customer:bronze", EdgeKindAssignedTo, map[string]any{"role": "support_contact", "frequency": 1, "last_seen": now.Add(-90 * 24 * time.Hour), "previous_strength": 0.8})
	addCustomerTouchpoint(g, "person:support", "customer:trial", EdgeKindAssignedTo, map[string]any{"role": "support_contact", "frequency": 1, "last_seen": now.Add(-120 * 24 * time.Hour), "previous_strength": 0.7})

	template := BuildIdealRelationshipTemplate(g)
	if template.MinTouchpoints < 2 {
		t.Fatalf("expected template min touchpoints >=2, got %d", template.MinTouchpoints)
	}
	if template.MinRoleDiversity <= 0 {
		t.Fatalf("expected positive role diversity threshold, got %.3f", template.MinRoleDiversity)
	}
	if !slices.Contains(template.RequiredRoles, "account_owner") {
		t.Fatalf("expected account_owner in required roles, got %v", template.RequiredRoles)
	}
	if !slices.Contains(template.RequiredRoles, "technical_contact") {
		t.Fatalf("expected technical_contact in required roles, got %v", template.RequiredRoles)
	}
}

func TestChurnRiskFromTopology_HigherForChurnLikeTopology(t *testing.T) {
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "customer:churned", Kind: NodeKindCustomer, Name: "Churned", Properties: map[string]any{"status": "churned", "arr": 250000.0}})
	g.AddNode(&Node{ID: "customer:at-risk", Kind: NodeKindCustomer, Name: "At Risk", Properties: map[string]any{"arr": 240000.0}})
	g.AddNode(&Node{ID: "customer:healthy", Kind: NodeKindCustomer, Name: "Healthy", Properties: map[string]any{"arr": 260000.0}})
	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner", Properties: map[string]any{"title": "Account Owner"}})
	g.AddNode(&Node{ID: "person:tech", Kind: NodeKindPerson, Name: "Tech", Properties: map[string]any{"title": "Senior Engineer"}})
	g.AddNode(&Node{ID: "person:exec", Kind: NodeKindPerson, Name: "Exec", Properties: map[string]any{"title": "VP"}})

	addCustomerTouchpoint(g, "person:owner", "customer:churned", EdgeKindManagedBy, map[string]any{
		"role":               "account_owner",
		"frequency":          1,
		"strength":           0.1,
		"previous_frequency": 6,
		"previous_strength":  0.9,
		"last_seen":          now.Add(-200 * 24 * time.Hour),
	})
	addCustomerTouchpoint(g, "person:owner", "customer:at-risk", EdgeKindManagedBy, map[string]any{
		"role":               "account_owner",
		"frequency":          2,
		"strength":           0.15,
		"previous_frequency": 7,
		"previous_strength":  0.85,
		"last_seen":          now.Add(-150 * 24 * time.Hour),
	})

	addCustomerTouchpoint(g, "person:owner", "customer:healthy", EdgeKindManagedBy, map[string]any{"role": "account_owner", "frequency": 14, "strength": 1.4, "last_seen": now.Add(-6 * time.Hour)})
	addCustomerTouchpoint(g, "person:tech", "customer:healthy", EdgeKindAssignedTo, map[string]any{"role": "technical_contact", "frequency": 11, "strength": 1.1, "last_seen": now.Add(-8 * time.Hour)})
	addCustomerTouchpoint(g, "person:exec", "customer:healthy", EdgeKindManagedBy, map[string]any{"role": "executive_sponsor", "frequency": 4, "strength": 0.8, "last_seen": now.Add(-12 * time.Hour)})
	addPeopleInteraction(g, "person:owner", "person:tech", now.Add(-4*time.Hour), 13, 1.2)
	addPeopleInteraction(g, "person:tech", "person:exec", now.Add(-5*time.Hour), 8, 1.0)

	atRisk := ChurnRiskFromTopology(g, "customer:at-risk")
	healthy := ChurnRiskFromTopology(g, "customer:healthy")
	if atRisk <= healthy {
		t.Fatalf("expected at-risk churn score > healthy score (%.3f <= %.3f)", atRisk, healthy)
	}
	if atRisk < 0.5 {
		t.Fatalf("expected at-risk churn score >= 0.5, got %.3f", atRisk)
	}
}

func addCustomerTouchpoint(g *Graph, personID, customerID string, kind EdgeKind, properties map[string]any) {
	g.AddEdge(&Edge{
		ID:         personID + "->" + customerID + ":" + string(kind),
		Source:     personID,
		Target:     customerID,
		Kind:       kind,
		Effect:     EdgeEffectAllow,
		Properties: properties,
	})
}

func addPeopleInteraction(g *Graph, left, right string, lastSeen time.Time, frequency float64, strength float64) {
	g.AddEdge(&Edge{
		ID:     left + "<->" + right,
		Source: left,
		Target: right,
		Kind:   EdgeKindInteractedWith,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"last_seen":  lastSeen,
			"frequency":  frequency,
			"strength":   strength,
			"call_count": int(frequency),
		},
	})
}

func findCustomerHealth(values []CustomerRelationshipHealth, customerID string) *CustomerRelationshipHealth {
	for idx := range values {
		if values[idx].CustomerID == customerID {
			return &values[idx]
		}
	}
	return nil
}
