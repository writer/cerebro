package graph

import (
	"testing"
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
