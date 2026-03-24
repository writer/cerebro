package graph

import (
	"context"
	"errors"
	"testing"
)

func TestGraphStoreCRUDAndSnapshot(t *testing.T) {
	ctx := context.Background()
	store := GraphStore(New())

	alice := &Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"}
	db := &Node{ID: "db:payments", Kind: NodeKindDatabase, Name: "payments"}
	edge := &Edge{ID: "access:alice:payments", Source: alice.ID, Target: db.ID, Kind: EdgeKindCalls}

	if err := store.UpsertNodesBatch(ctx, []*Node{alice, db}); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}
	if err := store.UpsertEdge(ctx, edge); err != nil {
		t.Fatalf("UpsertEdge() error = %v", err)
	}
	if err := store.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes() error = %v", err)
	}

	node, ok, err := store.LookupNode(ctx, alice.ID)
	if err != nil {
		t.Fatalf("LookupNode() error = %v", err)
	}
	if !ok || node == nil || node.ID != alice.ID {
		t.Fatalf("LookupNode() = (%#v, %v), want %q", node, ok, alice.ID)
	}
	storedEdge, ok, err := store.LookupEdge(ctx, edge.ID)
	if err != nil {
		t.Fatalf("LookupEdge() error = %v", err)
	}
	if !ok || storedEdge == nil || storedEdge.ID != edge.ID {
		t.Fatalf("LookupEdge() = (%#v, %v), want %q", storedEdge, ok, edge.ID)
	}

	nodesByKind, err := store.LookupNodesByKind(ctx, NodeKindPerson)
	if err != nil {
		t.Fatalf("LookupNodesByKind() error = %v", err)
	}
	if len(nodesByKind) != 1 || nodesByKind[0].ID != alice.ID {
		t.Fatalf("LookupNodesByKind() = %#v, want alice only", nodesByKind)
	}

	outEdges, err := store.LookupOutEdges(ctx, alice.ID)
	if err != nil {
		t.Fatalf("LookupOutEdges() error = %v", err)
	}
	if len(outEdges) != 1 || outEdges[0].ID != edge.ID {
		t.Fatalf("LookupOutEdges() = %#v, want %q", outEdges, edge.ID)
	}

	inEdges, err := store.LookupInEdges(ctx, db.ID)
	if err != nil {
		t.Fatalf("LookupInEdges() error = %v", err)
	}
	if len(inEdges) != 1 || inEdges[0].ID != edge.ID {
		t.Fatalf("LookupInEdges() = %#v, want %q", inEdges, edge.ID)
	}

	nodeCount, err := store.CountNodes(ctx)
	if err != nil {
		t.Fatalf("CountNodes() error = %v", err)
	}
	if nodeCount != 2 {
		t.Fatalf("CountNodes() = %d, want 2", nodeCount)
	}

	edgeCount, err := store.CountEdges(ctx)
	if err != nil {
		t.Fatalf("CountEdges() error = %v", err)
	}
	if edgeCount != 1 {
		t.Fatalf("CountEdges() = %d, want 1", edgeCount)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot == nil || len(snapshot.Nodes) != 2 || len(snapshot.Edges) != 1 {
		t.Fatalf("Snapshot() = %#v, want 2 nodes and 1 edge", snapshot)
	}

	if err := store.DeleteEdge(ctx, edge.ID); err != nil {
		t.Fatalf("DeleteEdge() error = %v", err)
	}
	if _, ok, err := store.LookupEdge(ctx, edge.ID); err != nil {
		t.Fatalf("LookupEdge(after remove) error = %v", err)
	} else if ok {
		t.Fatal("expected removed edge to be absent")
	}
	edgeCount, err = store.CountEdges(ctx)
	if err != nil {
		t.Fatalf("CountEdges(after remove) error = %v", err)
	}
	if edgeCount != 0 {
		t.Fatalf("CountEdges(after remove) = %d, want 0", edgeCount)
	}

	if err := store.DeleteNode(ctx, alice.ID); err != nil {
		t.Fatalf("DeleteNode() error = %v", err)
	}
	if _, ok, err := store.LookupNode(ctx, alice.ID); err != nil {
		t.Fatalf("LookupNode(after remove) error = %v", err)
	} else if ok {
		t.Fatal("expected removed node to be absent")
	}
}

func TestGraphStoreTraversalWrappersMatchGraphFunctions(t *testing.T) {
	ctx := context.Background()
	g := New()
	g.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "api"})
	g.AddNode(&Node{ID: "service:db", Kind: NodeKindService, Name: "db", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "calls:api:db", Source: "service:api", Target: "service:db", Kind: EdgeKindCalls})

	store := GraphStore(g)

	blast, err := store.BlastRadius(ctx, "service:api", 2)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	wantBlast := BlastRadius(g, "service:api", 2)
	if blast.TotalCount != wantBlast.TotalCount || blast.PrincipalID != wantBlast.PrincipalID {
		t.Fatalf("BlastRadius() = %#v, want %#v", blast, wantBlast)
	}

	reverse, err := store.ReverseAccess(ctx, "service:db", 2)
	if err != nil {
		t.Fatalf("ReverseAccess() error = %v", err)
	}
	wantReverse := ReverseAccess(g, "service:db", 2)
	if reverse.TotalCount != wantReverse.TotalCount || reverse.ResourceID != wantReverse.ResourceID {
		t.Fatalf("ReverseAccess() = %#v, want %#v", reverse, wantReverse)
	}

	access, err := store.EffectiveAccess(ctx, "service:api", "service:db", 2)
	if err != nil {
		t.Fatalf("EffectiveAccess() error = %v", err)
	}
	wantAccess := EffectiveAccess(g, "service:api", "service:db", 2)
	if access.Allowed != wantAccess.Allowed || len(access.AllowedBy) != len(wantAccess.AllowedBy) {
		t.Fatalf("EffectiveAccess() = %#v, want %#v", access, wantAccess)
	}

	cascade, err := store.CascadingBlastRadius(ctx, "service:api", 2)
	if err != nil {
		t.Fatalf("CascadingBlastRadius() error = %v", err)
	}
	wantCascade := CascadingBlastRadius(g, "service:api", 2)
	if cascade.MaxCascadeDepth != wantCascade.MaxCascadeDepth || cascade.SourceID != wantCascade.SourceID {
		t.Fatalf("CascadingBlastRadius() = %#v, want %#v", cascade, wantCascade)
	}

	subgraph, err := store.ExtractSubgraph(ctx, "service:api", ExtractSubgraphOptions{MaxDepth: 2})
	if err != nil {
		t.Fatalf("ExtractSubgraph() error = %v", err)
	}
	wantSubgraph := ExtractSubgraph(g, "service:api", ExtractSubgraphOptions{MaxDepth: 2})
	if subgraph.NodeCount() != wantSubgraph.NodeCount() || subgraph.EdgeCount() != wantSubgraph.EdgeCount() {
		t.Fatalf("ExtractSubgraph() = %d nodes/%d edges, want %d/%d", subgraph.NodeCount(), subgraph.EdgeCount(), wantSubgraph.NodeCount(), wantSubgraph.EdgeCount())
	}
}

func TestGraphStoreHonorsCanceledContext(t *testing.T) {
	g := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := g.UpsertNode(ctx, &Node{ID: "service:api", Kind: NodeKindService}); !errors.Is(err, context.Canceled) {
		t.Fatalf("UpsertNode() error = %v, want context.Canceled", err)
	}
	if _, _, err := g.LookupNode(ctx, "service:api"); !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupNode() error = %v, want context.Canceled", err)
	}
	if _, err := g.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot() error = %v, want context.Canceled", err)
	}
}
