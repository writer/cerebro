package graph

import (
	"testing"
	"time"
)

func TestBusFactorWithWindow(t *testing.T) {
	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	freezeOrgHealthNow(t, now)

	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "svc:payments", Kind: NodeKindApplication, Name: "payments"})

	g.AddEdge(&Edge{
		ID:     "alice-payments",
		Source: "person:alice@example.com",
		Target: "svc:payments",
		Kind:   EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-10 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-payments",
		Source: "person:bob@example.com",
		Target: "svc:payments",
		Kind:   EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-120 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "carol-payments",
		Source: "person:carol@example.com",
		Target: "svc:payments",
		Kind:   EdgeKindCanRead,
	})

	result := BusFactorWithWindow(g, "svc:payments", 90*24*time.Hour)
	if result.Total != 3 {
		t.Fatalf("expected total=3, got %d", result.Total)
	}
	if result.Active != 2 {
		t.Fatalf("expected active=2, got %d", result.Active)
	}
	if result.BusFactor != 2 {
		t.Fatalf("expected bus_factor=2, got %d", result.BusFactor)
	}
	if result.Risk != RiskHigh {
		t.Fatalf("expected risk=%s, got %s", RiskHigh, result.Risk)
	}
	if len(result.ActivePersonIDs) != 2 {
		t.Fatalf("expected 2 active people, got %v", result.ActivePersonIDs)
	}
}

func TestDetectSilos_SharedDependenciesNoInteractions(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:eng", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "department:sales", Kind: NodeKindDepartment, Name: "Sales"})
	g.AddNode(&Node{ID: "person:eng@example.com", Kind: NodeKindPerson, Name: "Eng"})
	g.AddNode(&Node{ID: "person:support@example.com", Kind: NodeKindPerson, Name: "Support"})
	g.AddNode(&Node{ID: "person:sales@example.com", Kind: NodeKindPerson, Name: "Sales"})
	g.AddNode(&Node{ID: "svc:billing", Kind: NodeKindApplication, Name: "billing"})

	g.AddEdge(&Edge{ID: "eng-team", Source: "person:eng@example.com", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "support-team", Source: "person:support@example.com", Target: "department:support", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "sales-team", Source: "person:sales@example.com", Target: "department:sales", Kind: EdgeKindMemberOf})

	g.AddEdge(&Edge{ID: "eng-dep", Source: "person:eng@example.com", Target: "svc:billing", Kind: EdgeKindCanAdmin})
	g.AddEdge(&Edge{ID: "support-dep", Source: "person:support@example.com", Target: "svc:billing", Kind: EdgeKindCanRead})
	g.AddEdge(&Edge{ID: "sales-dep", Source: "person:sales@example.com", Target: "svc:billing", Kind: EdgeKindCanRead})

	g.AddEdge(&Edge{
		ID:     "eng-sales-chat",
		Source: "person:eng@example.com",
		Target: "person:sales@example.com",
		Kind:   EdgeKindInteractedWith,
	})

	silos := DetectSilos(g)
	if len(silos) == 0 {
		t.Fatal("expected at least one silo")
	}

	foundEngSupport := false
	for _, silo := range silos {
		if len(silo.SharedDependencies) != 1 || silo.SharedDependencies[0] != "svc:billing" {
			t.Fatalf("expected shared dependency svc:billing, got %+v", silo.SharedDependencies)
		}
		if silo.InteractionEdgeCount != 0 {
			t.Fatalf("expected zero interactions for silo, got %d", silo.InteractionEdgeCount)
		}
		if silo.TeamAID == "department:eng" && silo.TeamBID == "department:support" {
			foundEngSupport = true
		}
	}
	if !foundEngSupport {
		t.Fatalf("expected Engineering/Support silo, got %+v", silos)
	}
}

func TestBottlenecks_FindsSoleBridge(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:eng", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:ops", Kind: NodeKindDepartment, Name: "Operations"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "person:a", Kind: NodeKindPerson, Name: "A"})
	g.AddNode(&Node{ID: "person:b", Kind: NodeKindPerson, Name: "B"})
	g.AddNode(&Node{ID: "person:c", Kind: NodeKindPerson, Name: "C"})
	g.AddNode(&Node{ID: "person:d", Kind: NodeKindPerson, Name: "D"})

	g.AddEdge(&Edge{ID: "a-dept", Source: "person:a", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "b-dept", Source: "person:b", Target: "department:ops", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "c-dept", Source: "person:c", Target: "department:support", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "d-dept", Source: "person:d", Target: "department:support", Kind: EdgeKindMemberOf})

	g.AddEdge(&Edge{ID: "a-b", Source: "person:a", Target: "person:b", Kind: EdgeKindInteractedWith})
	g.AddEdge(&Edge{ID: "b-c", Source: "person:b", Target: "person:c", Kind: EdgeKindInteractedWith})
	g.AddEdge(&Edge{ID: "b-d", Source: "person:b", Target: "person:d", Kind: EdgeKindInteractedWith})

	results := Bottlenecks(g)
	if len(results) == 0 {
		t.Fatal("expected bottleneck results")
	}
	if results[0].PersonID != "person:b" {
		t.Fatalf("expected person:b as top bottleneck, got %s", results[0].PersonID)
	}
	if !results[0].IsSoleBridge {
		t.Fatalf("expected person:b to be a sole bridge, got %+v", results[0])
	}
	if results[0].BetweennessCentrality <= 0 {
		t.Fatalf("expected positive centrality for person:b, got %.4f", results[0].BetweennessCentrality)
	}
}

func TestDecayingRelationships_DetectsWeakeningEdges(t *testing.T) {
	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	freezeOrgHealthNow(t, now)

	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme"})

	g.AddEdge(&Edge{
		ID:     "alice-bob",
		Source: "person:alice",
		Target: "person:bob",
		Kind:   EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 10,
			"last_seen": now.Add(-200 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-acme",
		Source: "person:alice",
		Target: "customer:acme",
		Kind:   EdgeKindManagedBy,
		Properties: map[string]any{
			"strength":          0.2,
			"previous_strength": 1.0,
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-acme",
		Source: "person:bob",
		Target: "customer:acme",
		Kind:   EdgeKindManagedBy,
		Properties: map[string]any{
			"strength":          0.1,
			"previous_strength": 0.6,
		},
	})

	alerts := DecayingRelationships(g, 0.3)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 decay alerts, got %d (%+v)", len(alerts), alerts)
	}
	if alerts[0].CurrentStrength > alerts[1].CurrentStrength {
		t.Fatalf("expected alerts sorted by current strength ascending, got %+v", alerts)
	}
}

func TestComputeOrgHealthScore_AggregatesMetrics(t *testing.T) {
	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	freezeOrgHealthNow(t, now)

	g := New()
	g.AddNode(&Node{ID: "department:eng", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:ops", Kind: NodeKindDepartment, Name: "Operations"})
	g.AddNode(&Node{ID: "department:sales", Kind: NodeKindDepartment, Name: "Sales"})

	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "person:dan", Kind: NodeKindPerson, Name: "Dan"})

	g.AddNode(&Node{
		ID:         "svc:payments",
		Kind:       NodeKindApplication,
		Name:       "payments",
		Properties: map[string]any{"criticality": "high"},
	})
	g.AddNode(&Node{
		ID:         "svc:analytics",
		Kind:       NodeKindApplication,
		Name:       "analytics",
		Properties: map[string]any{"criticality": "high"},
	})

	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "carol-ops", Source: "person:carol", Target: "department:ops", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "dan-sales", Source: "person:dan", Target: "department:sales", Kind: EdgeKindMemberOf})

	g.AddEdge(&Edge{
		ID:     "alice-payments",
		Source: "person:alice",
		Target: "svc:payments",
		Kind:   EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-5 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-payments",
		Source: "person:bob",
		Target: "svc:payments",
		Kind:   EdgeKindCanRead,
		Properties: map[string]any{
			"last_seen": now.Add(-200 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "dan-payments",
		Source: "person:dan",
		Target: "svc:payments",
		Kind:   EdgeKindCanRead,
		Properties: map[string]any{
			"last_seen": now.Add(-2 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "carol-analytics",
		Source: "person:carol",
		Target: "svc:analytics",
		Kind:   EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-3 * 24 * time.Hour),
		},
	})

	g.AddEdge(&Edge{
		ID:     "alice-carol",
		Source: "person:alice",
		Target: "person:carol",
		Kind:   EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 5,
			"last_seen": now.Add(-1 * 24 * time.Hour),
		},
	})

	score := ComputeOrgHealthScore(g)
	if score.SinglePointsOfFailure != 1 {
		t.Fatalf("expected 1 single point of failure, got %d", score.SinglePointsOfFailure)
	}
	if score.SiloCount < 1 {
		t.Fatalf("expected at least one silo, got %d", score.SiloCount)
	}
	if len(score.BusFactors) < 2 {
		t.Fatalf("expected bus factor results for both services, got %d", len(score.BusFactors))
	}
	if score.CommunicationDensity <= 0 || score.CommunicationDensity >= 1 {
		t.Fatalf("expected communication density between 0 and 1, got %.3f", score.CommunicationDensity)
	}
	if score.OverallScore <= 0 || score.OverallScore >= 100 {
		t.Fatalf("expected overall score in (0,100), got %.2f", score.OverallScore)
	}

	engine := NewRiskEngine(g)
	report := engine.Analyze()
	if report.OrgHealth == nil {
		t.Fatal("expected risk report org health to be populated")
	}
}

func freezeOrgHealthNow(t *testing.T, now time.Time) {
	t.Helper()
	previous := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() {
		orgHealthNowUTC = previous
	})
}
