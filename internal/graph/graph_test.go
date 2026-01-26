package graph

import (
	"testing"
)

func TestGraph_AddNode(t *testing.T) {
	g := New()

	node := &Node{
		ID:       "arn:aws:iam::123456789012:user/alice",
		Kind:     NodeKindUser,
		Name:     "alice",
		Provider: "aws",
		Account:  "123456789012",
	}

	g.AddNode(node)

	got, ok := g.GetNode(node.ID)
	if !ok {
		t.Fatal("expected node to be found")
	}
	if got.Name != "alice" {
		t.Errorf("expected name alice, got %s", got.Name)
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := New()

	// Add nodes
	user := &Node{ID: "user:alice", Kind: NodeKindUser}
	role := &Node{ID: "role:admin", Kind: NodeKindRole}
	g.AddNode(user)
	g.AddNode(role)

	// Add edge
	edge := &Edge{
		ID:     "user:alice->role:admin",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	}
	g.AddEdge(edge)

	// Verify outbound edges
	outEdges := g.GetOutEdges("user:alice")
	if len(outEdges) != 1 {
		t.Errorf("expected 1 outbound edge, got %d", len(outEdges))
	}

	// Verify inbound edges
	inEdges := g.GetInEdges("role:admin")
	if len(inEdges) != 1 {
		t.Errorf("expected 1 inbound edge, got %d", len(inEdges))
	}
}

func TestGraph_GetNodesByKind(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "bucket:data", Kind: NodeKindBucket})

	users := g.GetNodesByKind(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	identities := g.GetNodesByKind(NodeKindUser, NodeKindRole)
	if len(identities) != 3 {
		t.Errorf("expected 3 identities, got %d", len(identities))
	}
}

func TestGraph_NodeCount(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "1"})
	g.AddNode(&Node{ID: "2"})
	g.AddNode(&Node{ID: "3"})

	if g.NodeCount() != 3 {
		t.Errorf("expected 3 nodes, got %d", g.NodeCount())
	}
}

func TestGraph_EdgeCount(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{ID: "1", Source: "a", Target: "b"})
	g.AddEdge(&Edge{ID: "2", Source: "b", Target: "c"})

	if g.EdgeCount() != 2 {
		t.Errorf("expected 2 edges, got %d", g.EdgeCount())
	}
}

func TestGraph_Clear(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "1"})
	g.AddEdge(&Edge{ID: "1", Source: "a", Target: "b"})

	g.Clear()

	if g.NodeCount() != 0 {
		t.Error("expected 0 nodes after clear")
	}
	if g.EdgeCount() != 0 {
		t.Error("expected 0 edges after clear")
	}
}

func TestGraph_BuildIndex(t *testing.T) {
	g := New()

	// Add test nodes
	g.AddNode(&Node{
		ID:       "user:alice",
		Kind:     NodeKindUser,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskHigh,
	})
	g.AddNode(&Node{
		ID:       "user:bob",
		Kind:     NodeKindUser,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskLow,
	})
	g.AddNode(&Node{
		ID:       "role:admin",
		Kind:     NodeKindRole,
		Account:  "987654321098",
		Provider: "aws",
		Risk:     RiskCritical,
	})
	g.AddNode(&Node{
		ID:       "bucket:data",
		Kind:     NodeKindBucket,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskMedium,
		Properties: map[string]interface{}{
			"public_access_block_enabled": false,
		},
	})

	// Build index
	g.BuildIndex()

	if !g.IsIndexBuilt() {
		t.Error("expected index to be built")
	}

	// Test kind index
	users := g.GetNodesByKindIndexed(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected 2 users from index, got %d", len(users))
	}

	// Test account index
	account1Nodes := g.GetNodesByAccountIndexed("123456789012")
	if len(account1Nodes) != 3 {
		t.Errorf("expected 3 nodes in account 123456789012, got %d", len(account1Nodes))
	}

	// Test risk index
	criticalNodes := g.GetNodesByRisk(RiskCritical)
	if len(criticalNodes) != 1 {
		t.Errorf("expected 1 critical node, got %d", len(criticalNodes))
	}

	// Test crown jewels (high + critical risk)
	crownJewels := g.GetCrownJewels()
	if len(crownJewels) != 2 { // alice (high) and admin (critical)
		t.Errorf("expected 2 crown jewels, got %d", len(crownJewels))
	}

	// Test internet-facing (bucket with public access)
	internetFacing := g.GetInternetFacingNodes()
	if len(internetFacing) != 1 {
		t.Errorf("expected 1 internet-facing node, got %d", len(internetFacing))
	}
}

func TestGraph_InvalidateIndex(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "test", Kind: NodeKindUser})
	g.BuildIndex()

	if !g.IsIndexBuilt() {
		t.Error("expected index to be built")
	}

	g.InvalidateIndex()

	if g.IsIndexBuilt() {
		t.Error("expected index to be invalidated")
	}
}

func TestGraph_IndexFallback(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "123"})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser, Account: "456"})

	// Test without building index - should fall back to scan
	users := g.GetNodesByKindIndexed(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected fallback to find 2 users, got %d", len(users))
	}

	accountNodes := g.GetNodesByAccountIndexed("123")
	if len(accountNodes) != 1 {
		t.Errorf("expected fallback to find 1 node in account, got %d", len(accountNodes))
	}
}

func TestGraph_CrossAccountEdgesIndexed(t *testing.T) {
	g := New()

	// Add nodes in different accounts
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.AddNode(&Node{ID: "role:viewer", Kind: NodeKindRole, Account: "111"})

	// Add cross-account edge
	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})

	// Add same-account edge
	g.AddEdge(&Edge{
		ID:     "same-1",
		Source: "user:alice",
		Target: "role:viewer",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": false,
		},
	})

	g.BuildIndex()

	crossEdges := g.GetCrossAccountEdgesIndexed()
	if len(crossEdges) != 1 {
		t.Errorf("expected 1 cross-account edge, got %d", len(crossEdges))
	}
}
