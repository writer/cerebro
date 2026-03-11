package graph

import (
	"testing"
	"time"
)

func TestGraphApplyDelta_MutatesNodesAndEdges(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user-1", Kind: NodeKindUser, Name: "user-1"})
	g.AddNode(&Node{ID: "role-1", Kind: NodeKindRole, Name: "role-1"})
	g.AddEdge(&Edge{ID: "user-role", Source: "user-1", Target: "role-1", Kind: EdgeKindCanAssume})

	delta := GraphDelta{
		Nodes: []NodeMutation{
			{Action: "add", Node: &Node{ID: "customer-1", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 250000.0}}},
			{Action: "modify", ID: "user-1", Properties: map[string]any{"mfa_enabled": true}},
		},
		Edges: []EdgeMutation{
			{Action: "remove", Source: "user-1", Target: "role-1", Kind: EdgeKindCanAssume},
		},
	}

	if err := g.ApplyDelta(delta); err != nil {
		t.Fatalf("ApplyDelta failed: %v", err)
	}

	if _, ok := g.GetNode("customer-1"); !ok {
		t.Fatal("expected added customer node")
	}
	user, ok := g.GetNode("user-1")
	if !ok {
		t.Fatal("expected existing user node")
	}
	if got, _ := user.Properties["mfa_enabled"].(bool); !got {
		t.Fatalf("expected modified mfa_enabled=true, got %v", user.Properties["mfa_enabled"])
	}

	edges := g.GetOutEdges("user-1")
	for _, edge := range edges {
		if edge.Target == "role-1" && edge.Kind == EdgeKindCanAssume {
			t.Fatal("expected remove edge mutation to remove user->role edge")
		}
	}
}

func TestGraphSimulate_DoesNotMutateOriginalGraphAndComputesImpact(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user-1", Kind: NodeKindUser, Name: "user-1"})
	g.AddNode(&Node{ID: "svc-1", Kind: NodeKindApplication, Name: "svc-1"})
	g.AddNode(&Node{ID: "customer-1", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 500000.0}})
	g.AddEdge(&Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.BuildIndex()

	result, err := g.Simulate(GraphDelta{
		Nodes: []NodeMutation{{
			Action:     "modify",
			ID:         "user-1",
			Properties: map[string]any{"mfa_enabled": true},
		}},
	})
	if err != nil {
		t.Fatalf("Simulate failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil simulation result")
	}

	if len(result.Before.AffectedCustomers) != 1 || result.Before.AffectedCustomers[0].ID != "customer-1" {
		t.Fatalf("expected customer-1 to be affected before simulation, got %+v", result.Before.AffectedCustomers)
	}
	if len(result.After.AffectedCustomers) != 1 || result.After.AffectedCustomers[0].ID != "customer-1" {
		t.Fatalf("expected customer-1 to be affected after simulation, got %+v", result.After.AffectedCustomers)
	}
	if result.Before.AffectedARR != 500000 {
		t.Fatalf("expected before affected ARR 500000, got %.2f", result.Before.AffectedARR)
	}
	if result.After.AffectedARR != 500000 {
		t.Fatalf("expected after affected ARR 500000, got %.2f", result.After.AffectedARR)
	}

	orig, ok := g.GetNode("user-1")
	if !ok {
		t.Fatal("expected original graph user node")
	}
	if _, exists := orig.Properties["mfa_enabled"]; exists {
		t.Fatal("expected original graph to remain unchanged by simulation")
	}
}

func TestGraphApplyDelta_InvalidMutationReturnsError(t *testing.T) {
	g := New()
	err := g.ApplyDelta(GraphDelta{Nodes: []NodeMutation{{Action: "explode", ID: "x"}}})
	if err == nil {
		t.Fatal("expected invalid mutation action to return error")
	}
}

func TestGraphSimulate_PersonDepartureImpact(t *testing.T) {
	now := time.Now().UTC()

	g := New()
	g.AddNode(&Node{
		ID:   "person:alice@example.com",
		Kind: NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"start_date": "2020-01-01",
		},
	})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:charlie@example.com", Kind: NodeKindPerson, Name: "Charlie"})

	g.AddNode(&Node{ID: "department:eng", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:ops", Kind: NodeKindDepartment, Name: "Operations"})

	g.AddNode(&Node{
		ID:   "svc:core",
		Kind: NodeKindApplication,
		Name: "core",
		Properties: map[string]any{
			"criticality": "high",
		},
	})
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"arr":          100000.0,
			"renewal_days": 30,
		},
	})

	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice@example.com", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob@example.com", Target: "department:eng", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "charlie-ops", Source: "person:charlie@example.com", Target: "department:ops", Kind: EdgeKindMemberOf})

	g.AddEdge(&Edge{
		ID:     "alice-core",
		Source: "person:alice@example.com",
		Target: "svc:core",
		Kind:   EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-acme",
		Source: "person:alice@example.com",
		Target: "customer:acme",
		Kind:   EdgeKindManagedBy,
		Properties: map[string]any{
			"strength":          0.2,
			"previous_strength": 0.9,
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-bob",
		Source: "person:alice@example.com",
		Target: "person:bob@example.com",
		Kind:   EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 5,
			"last_seen": now.Add(-24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-charlie",
		Source: "person:alice@example.com",
		Target: "person:charlie@example.com",
		Kind:   EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 4,
			"last_seen": now.Add(-24 * time.Hour),
		},
	})

	result, err := g.Simulate(GraphDelta{
		Nodes: []NodeMutation{{
			Action: "remove",
			ID:     "person:alice@example.com",
		}},
	})
	if err != nil {
		t.Fatalf("Simulate failed: %v", err)
	}
	if result.PersonDepartureImpact == nil {
		t.Fatal("expected person departure impact")
	}

	impact := result.PersonDepartureImpact
	if impact.Person == nil || impact.Person.ID != "person:alice@example.com" {
		t.Fatalf("expected impact person alice, got %+v", impact.Person)
	}
	if !containsNodeID(impact.SystemsBusFactor0, "svc:core") {
		t.Fatalf("expected svc:core in SystemsBusFactor0, got %+v", impact.SystemsBusFactor0)
	}
	if !containsNodeID(impact.CustomersNoContact, "customer:acme") {
		t.Fatalf("expected customer:acme in CustomersNoContact, got %+v", impact.CustomersNoContact)
	}
	if impact.AffectedARR != 100000 {
		t.Fatalf("expected affected ARR 100000, got %.2f", impact.AffectedARR)
	}
	if len(impact.AccessToRevoke) == 0 {
		t.Fatal("expected access revocations to be identified")
	}
	if len(impact.BrokenBridges) == 0 {
		t.Fatal("expected broken team bridges to be identified")
	}

	successors := impact.SuggestedSuccessors["svc:core"]
	if len(successors) == 0 {
		t.Fatalf("expected suggested successors for svc:core, got %+v", impact.SuggestedSuccessors)
	}
	if successors[0].ID != "person:bob@example.com" {
		t.Fatalf("expected bob as top successor for svc:core, got %s", successors[0].ID)
	}
}

func TestGraphSimulate_NonPersonRemovalHasNoPersonDepartureImpact(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "svc-1", Kind: NodeKindApplication, Name: "svc-1"})
	g.AddNode(&Node{ID: "svc-2", Kind: NodeKindApplication, Name: "svc-2"})
	g.AddEdge(&Edge{ID: "svc-link", Source: "svc-1", Target: "svc-2", Kind: EdgeKindConnectsTo, Effect: EdgeEffectAllow})

	result, err := g.Simulate(GraphDelta{
		Nodes: []NodeMutation{{
			Action: "remove",
			ID:     "svc-1",
		}},
	})
	if err != nil {
		t.Fatalf("Simulate failed: %v", err)
	}
	if result.PersonDepartureImpact != nil {
		t.Fatalf("expected nil person departure impact, got %+v", result.PersonDepartureImpact)
	}
}

func containsNodeID(nodes []*Node, id string) bool {
	for _, node := range nodes {
		if node != nil && node.ID == id {
			return true
		}
	}
	return false
}
