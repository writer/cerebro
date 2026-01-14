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
