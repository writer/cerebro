package graph

import (
	"context"
	"errors"
	"testing"
)

func TestSnapshotGraphStoreServesColdReadsWithoutMaterializingView(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddEdge(&Edge{
		ID:     "edge:user-service",
		Source: "user:alice",
		Target: "service:payments",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})
	g.BuildIndex()

	store := NewSnapshotGraphStore(CreateSnapshot(g))
	if store == nil {
		t.Fatal("expected snapshot graph store")
	}

	node, ok, err := store.LookupNode(context.Background(), "user:alice")
	if err != nil || !ok {
		t.Fatalf("LookupNode(user:alice) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if node.Name != "Alice" {
		t.Fatalf("LookupNode(user:alice) name = %q, want Alice", node.Name)
	}

	outEdges, err := store.LookupOutEdges(context.Background(), "user:alice")
	if err != nil {
		t.Fatalf("LookupOutEdges(user:alice) error = %v", err)
	}
	if len(outEdges) != 1 || outEdges[0].Target != "service:payments" {
		t.Fatalf("LookupOutEdges(user:alice) = %#v, want service edge", outEdges)
	}
	edge, ok, err := store.LookupEdge(context.Background(), "edge:user-service")
	if err != nil || !ok {
		t.Fatalf("LookupEdge(edge:user-service) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if edge.Target != "service:payments" {
		t.Fatalf("LookupEdge(edge:user-service) target = %q, want service:payments", edge.Target)
	}

	nodeCount, err := store.CountNodes(context.Background())
	if err != nil {
		t.Fatalf("CountNodes() error = %v", err)
	}
	if nodeCount != 2 {
		t.Fatalf("CountNodes() = %d, want 2", nodeCount)
	}

	edgeCount, err := store.CountEdges(context.Background())
	if err != nil {
		t.Fatalf("CountEdges() error = %v", err)
	}
	if edgeCount != 1 {
		t.Fatalf("CountEdges() = %d, want 1", edgeCount)
	}

	if store.view != nil {
		t.Fatal("expected cold-path lookups not to materialize a full graph view")
	}
}

func TestSnapshotGraphStoreRejectsWritesAndLazilyBuildsTraversalView(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddEdge(&Edge{
		ID:     "edge:user-service",
		Source: "user:alice",
		Target: "service:payments",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})
	g.BuildIndex()

	store := NewSnapshotGraphStore(CreateSnapshot(g))

	if err := store.UpsertNode(context.Background(), &Node{ID: "service:new", Kind: NodeKindService}); !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("UpsertNode() error = %v, want ErrStoreReadOnly", err)
	}
	if err := store.DeleteEdge(context.Background(), "edge:user-service"); !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("DeleteEdge() error = %v, want ErrStoreReadOnly", err)
	}

	result, err := store.BlastRadius(context.Background(), "user:alice", 1)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if result == nil || result.TotalCount != 1 {
		t.Fatalf("BlastRadius() = %+v, want one reachable node", result)
	}
	if store.view == nil {
		t.Fatal("expected traversal to lazily materialize a graph view")
	}
}
