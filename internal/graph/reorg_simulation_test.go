package graph

import "testing"

func TestSimulateReorg_PersonMoveDetectsBridgeAndMitigations(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})

	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&Node{ID: "person:vp@example.com", Kind: NodeKindPerson, Name: "VP", Properties: map[string]any{"title": "VP Engineering"}})

	g.AddNode(&Node{ID: "system:payments", Kind: NodeKindApplication, Name: "payments", Risk: RiskHigh})
	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme"})
	g.AddNode(&Node{ID: "ticket:incident-1", Kind: NodeKindTicket, Name: "Incident 1", Properties: map[string]any{"severity": "high"}})

	g.AddEdge(&Edge{ID: "m1", Source: "person:alice@example.com", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m2", Source: "person:bob@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "i1", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 12}})
	g.AddEdge(&Edge{ID: "s1", Source: "person:bob@example.com", Target: "system:payments", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "c1", Source: "person:alice@example.com", Target: "customer:acme", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "c2", Source: "person:bob@example.com", Target: "customer:acme", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "t1", Source: "ticket:incident-1", Target: "person:alice@example.com", Kind: EdgeKindEscalatedTo, Effect: EdgeEffectAllow})

	impact, err := SimulateReorg(g, []ReorgChange{{Person: "person:bob@example.com", NewDepartment: "Platform", NewManager: "person:vp@example.com"}})
	if err != nil {
		t.Fatalf("simulate reorg returned error: %v", err)
	}
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if len(impact.BrokenBridges) == 0 {
		t.Fatalf("expected broken bridges after moving sole engineering connector")
	}
	if len(impact.WeakenedPaths) == 0 {
		t.Fatalf("expected weakened paths after reorg")
	}
	if len(impact.RecommendedActions) == 0 {
		t.Fatalf("expected recommended mitigations")
	}
}

func TestSimulateReorg_MergeAndSplitTeams(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "department:payments", Kind: NodeKindDepartment, Name: "Payments"})
	g.AddNode(&Node{ID: "department:billing", Kind: NodeKindDepartment, Name: "Billing"})
	g.AddNode(&Node{ID: "department:infrastructure", Kind: NodeKindDepartment, Name: "Infrastructure"})

	g.AddNode(&Node{ID: "person:paul@example.com", Kind: NodeKindPerson, Name: "Paul", Properties: map[string]any{"department": "payments"}})
	g.AddNode(&Node{ID: "person:bella@example.com", Kind: NodeKindPerson, Name: "Bella", Properties: map[string]any{"department": "billing"}})
	g.AddNode(&Node{ID: "person:ivan@example.com", Kind: NodeKindPerson, Name: "Ivan", Properties: map[string]any{"department": "infrastructure"}})
	g.AddNode(&Node{ID: "person:ivy@example.com", Kind: NodeKindPerson, Name: "Ivy", Properties: map[string]any{"department": "infrastructure"}})

	g.AddEdge(&Edge{ID: "mp", Source: "person:paul@example.com", Target: "department:payments", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mb", Source: "person:bella@example.com", Target: "department:billing", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mi", Source: "person:ivan@example.com", Target: "department:infrastructure", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mj", Source: "person:ivy@example.com", Target: "department:infrastructure", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "ib", Source: "person:paul@example.com", Target: "person:bella@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 8}})

	impact, err := SimulateReorg(g, []ReorgChange{
		{MergeTeams: []string{"team/payments", "team/billing"}},
		{SplitTeam: "team/infrastructure", Into: []string{"team/platform", "team/sre"}},
	})
	if err != nil {
		t.Fatalf("simulate reorg returned error: %v", err)
	}
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if len(impact.BrokenBridges) == 0 {
		t.Fatalf("expected broken bridge signal when merged teams lose explicit bridge")
	}
}

func TestSimulateReorg_ValidationErrors(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})

	if _, err := SimulateReorg(g, nil); err == nil {
		t.Fatal("expected error for empty reorg changes")
	}
	if _, err := SimulateReorg(g, []ReorgChange{{Person: "person:missing@example.com", NewDepartment: "Platform"}}); err == nil {
		t.Fatal("expected error for unknown person")
	}
}
