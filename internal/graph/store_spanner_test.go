package graph

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

type fakeSpannerAdapter struct {
	store              GraphStore
	ensureCalls        int
	snapshotCalls      int
	lookupOutEdgeCalls map[string]int
	lookupInEdgeCalls  map[string]int
	nativeEdgeQueries  []string
}

func (f *fakeSpannerAdapter) UpsertNode(ctx context.Context, node *Node) error {
	return f.store.UpsertNode(ctx, node)
}

func (f *fakeSpannerAdapter) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	return f.store.UpsertNodesBatch(ctx, nodes)
}

func (f *fakeSpannerAdapter) UpsertEdge(ctx context.Context, edge *Edge) error {
	return f.store.UpsertEdge(ctx, edge)
}

func (f *fakeSpannerAdapter) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	return f.store.UpsertEdgesBatch(ctx, edges)
}

func (f *fakeSpannerAdapter) DeleteNode(ctx context.Context, id string) error {
	return f.store.DeleteNode(ctx, id)
}

func (f *fakeSpannerAdapter) DeleteEdge(ctx context.Context, id string) error {
	return f.store.DeleteEdge(ctx, id)
}

func (f *fakeSpannerAdapter) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	return f.store.LookupNode(ctx, id)
}

func (f *fakeSpannerAdapter) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	return f.store.LookupEdge(ctx, id)
}

func (f *fakeSpannerAdapter) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if f.lookupOutEdgeCalls == nil {
		f.lookupOutEdgeCalls = make(map[string]int)
	}
	f.lookupOutEdgeCalls[nodeID]++
	return f.store.LookupOutEdges(ctx, nodeID)
}

func (f *fakeSpannerAdapter) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if f.lookupInEdgeCalls == nil {
		f.lookupInEdgeCalls = make(map[string]int)
	}
	f.lookupInEdgeCalls[nodeID]++
	return f.store.LookupInEdges(ctx, nodeID)
}

func (f *fakeSpannerAdapter) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	return f.store.LookupNodesByKind(ctx, kinds...)
}

func (f *fakeSpannerAdapter) CountNodes(ctx context.Context) (int, error) {
	return f.store.CountNodes(ctx)
}

func (f *fakeSpannerAdapter) CountEdges(ctx context.Context) (int, error) {
	return f.store.CountEdges(ctx)
}

func (f *fakeSpannerAdapter) EnsureIndexes(ctx context.Context) error {
	f.ensureCalls++
	return f.store.EnsureIndexes(ctx)
}

func (f *fakeSpannerAdapter) Snapshot(ctx context.Context) (*Snapshot, error) {
	f.snapshotCalls++
	return f.store.Snapshot(ctx)
}

func (f *fakeSpannerAdapter) QueryTraversalEdges(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) ([]*Edge, error) {
	statement, err := spannerGraphTraversalEdgesStatement(rootID, direction, maxDepth)
	if err != nil {
		return nil, err
	}
	f.nativeEdgeQueries = append(f.nativeEdgeQueries, statement.SQL)

	snapshot, err := f.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	view := NewSnapshotGraphStore(snapshot)
	subgraph, err := view.ExtractSubgraph(ctx, rootID, ExtractSubgraphOptions{
		MaxDepth:  spannerNativeTraversalMaxHops(maxDepth),
		Direction: spannerTraversalDirectionToExtractSubgraph(direction),
	})
	if err != nil {
		return nil, err
	}

	edges := make([]*Edge, 0, subgraph.EdgeCount())
	for _, outgoing := range subgraph.GetAllEdges() {
		for _, edge := range outgoing {
			if edge != nil {
				edges = append(edges, edge)
			}
		}
	}
	return edges, nil
}

func spannerTraversalDirectionToExtractSubgraph(direction spannerTraversalDirection) ExtractSubgraphDirection {
	switch direction {
	case spannerTraversalDirectionOutgoing:
		return ExtractSubgraphDirectionOutgoing
	case spannerTraversalDirectionIncoming:
		return ExtractSubgraphDirectionIncoming
	default:
		return ExtractSubgraphDirectionBoth
	}
}

func TestSpannerGraphStoreSchemaStatements(t *testing.T) {
	statements, err := SpannerGraphStoreSchemaStatements()
	if err != nil {
		t.Fatalf("SpannerGraphStoreSchemaStatements() error = %v", err)
	}
	if len(statements) != 6 {
		t.Fatalf("expected 6 DDL statements, got %d", len(statements))
	}
	if !strings.Contains(statements[0], "CREATE TABLE graph_nodes") {
		t.Fatalf("expected node table DDL, got %q", statements[0])
	}
	if !strings.Contains(statements[1], "CREATE TABLE graph_edges") {
		t.Fatalf("expected edge table DDL, got %q", statements[1])
	}
	if !strings.Contains(statements[5], "CREATE OR REPLACE PROPERTY GRAPH cerebro_graph_store") {
		t.Fatalf("expected property graph DDL, got %q", statements[5])
	}
}

func TestSpannerGraphStoreDelegatesCRUDAndTraversal(t *testing.T) {
	adapter := &fakeSpannerAdapter{store: GraphStore(New())}
	store := NewSpannerGraphStore(adapter)
	ctx := context.Background()

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
	if adapter.ensureCalls == 0 {
		t.Fatal("expected EnsureIndexes() to hit the adapter")
	}

	if storedEdge, ok, err := store.LookupEdge(ctx, edge.ID); err != nil || !ok || storedEdge == nil || storedEdge.ID != edge.ID {
		t.Fatalf("LookupEdge() = (%#v, %v), err=%v", storedEdge, ok, err)
	}
	if nodeCount, err := store.CountNodes(ctx); err != nil || nodeCount != 2 {
		t.Fatalf("CountNodes() = (%d, %v), want (2, nil)", nodeCount, err)
	}
	if edgeCount, err := store.CountEdges(ctx); err != nil || edgeCount != 1 {
		t.Fatalf("CountEdges() = (%d, %v), want (1, nil)", edgeCount, err)
	}

	blast, err := store.BlastRadius(ctx, alice.ID, 2)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if blast.TotalCount != 1 {
		t.Fatalf("BlastRadius().TotalCount = %d, want 1", blast.TotalCount)
	}

	if err := store.DeleteEdge(ctx, edge.ID); err != nil {
		t.Fatalf("DeleteEdge() error = %v", err)
	}
	if _, ok, err := store.LookupEdge(ctx, edge.ID); err != nil || ok {
		t.Fatalf("LookupEdge(after delete) = (%v, %v), want absent; err=%v", ok, err, err)
	}
}

func TestSpannerGraphStoreTraversalsUseBoundedLookupGraphWithoutSnapshotMaterialization(t *testing.T) {
	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	db := contractStoreTestNode("service:db", NodeKindService, "DB")
	bucket := contractStoreTestNode("bucket:logs", NodeKindBucket, "logs")
	base.AddNodesBatch([]*Node{alice, api, db, bucket})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:db", api.ID, db.ID, EdgeKindCalls),
		contractStoreTestEdge("edge:db:bucket", db.ID, bucket.ID, EdgeKindCanWrite),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter)
	ctx := context.Background()

	blast, err := store.BlastRadius(ctx, alice.ID, 2)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	wantBlast := BlastRadius(base, alice.ID, 2)
	if blast.TotalCount != wantBlast.TotalCount {
		t.Fatalf("BlastRadius().TotalCount = %d, want %d", blast.TotalCount, wantBlast.TotalCount)
	}
	if !reflect.DeepEqual(sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes)) {
		t.Fatalf("BlastRadius() reachable nodes = %#v, want %#v", sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes))
	}

	reverse, err := store.ReverseAccess(ctx, bucket.ID, 2)
	if err != nil {
		t.Fatalf("ReverseAccess() error = %v", err)
	}
	wantReverse := ReverseAccess(base, bucket.ID, 2)
	if reverse.TotalCount != wantReverse.TotalCount {
		t.Fatalf("ReverseAccess().TotalCount = %d, want %d", reverse.TotalCount, wantReverse.TotalCount)
	}
	if !reflect.DeepEqual(sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy)) {
		t.Fatalf("ReverseAccess() accessors = %#v, want %#v", sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy))
	}

	access, err := store.EffectiveAccess(ctx, alice.ID, bucket.ID, 2)
	if err != nil {
		t.Fatalf("EffectiveAccess() error = %v", err)
	}
	wantAccess := EffectiveAccess(base, alice.ID, bucket.ID, 2)
	if access.Allowed != wantAccess.Allowed {
		t.Fatalf("EffectiveAccess().Allowed = %v, want %v", access.Allowed, wantAccess.Allowed)
	}
	if !reflect.DeepEqual(sortedEdgeIDs(access.AllowedBy), sortedEdgeIDs(wantAccess.AllowedBy)) {
		t.Fatalf("EffectiveAccess() allowed_by = %#v, want %#v", sortedEdgeIDs(access.AllowedBy), sortedEdgeIDs(wantAccess.AllowedBy))
	}

	subgraph, err := store.ExtractSubgraph(ctx, alice.ID, ExtractSubgraphOptions{MaxDepth: 2})
	if err != nil {
		t.Fatalf("ExtractSubgraph() error = %v", err)
	}
	wantSubgraph := ExtractSubgraph(base, alice.ID, ExtractSubgraphOptions{MaxDepth: 2})
	if !reflect.DeepEqual(sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes())) {
		t.Fatalf("ExtractSubgraph() nodes = %#v, want %#v", sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph)) {
		t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph))
	}

	if adapter.snapshotCalls != 0 {
		t.Fatalf("expected bounded traversals not to materialize a full snapshot, snapshotCalls=%d", adapter.snapshotCalls)
	}
}

func TestSpannerGraphStoreTraversalsMatchInMemoryAtZeroDepth(t *testing.T) {
	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	base.AddNodesBatch([]*Node{alice, api})
	base.AddEdge(contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead))

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter)
	ctx := context.Background()

	blast, err := store.BlastRadius(ctx, alice.ID, 0)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	wantBlast := BlastRadius(base, alice.ID, 0)
	if blast.TotalCount != wantBlast.TotalCount {
		t.Fatalf("BlastRadius().TotalCount = %d, want %d", blast.TotalCount, wantBlast.TotalCount)
	}
	if !reflect.DeepEqual(sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes)) {
		t.Fatalf("BlastRadius() reachable nodes = %#v, want %#v", sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes))
	}

	reverse, err := store.ReverseAccess(ctx, api.ID, 0)
	if err != nil {
		t.Fatalf("ReverseAccess() error = %v", err)
	}
	wantReverse := ReverseAccess(base, api.ID, 0)
	if reverse.TotalCount != wantReverse.TotalCount {
		t.Fatalf("ReverseAccess().TotalCount = %d, want %d", reverse.TotalCount, wantReverse.TotalCount)
	}
	if !reflect.DeepEqual(sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy)) {
		t.Fatalf("ReverseAccess() accessors = %#v, want %#v", sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy))
	}

	access, err := store.EffectiveAccess(ctx, alice.ID, api.ID, 0)
	if err != nil {
		t.Fatalf("EffectiveAccess() error = %v", err)
	}
	wantAccess := EffectiveAccess(base, alice.ID, api.ID, 0)
	if access.Allowed != wantAccess.Allowed {
		t.Fatalf("EffectiveAccess().Allowed = %v, want %v", access.Allowed, wantAccess.Allowed)
	}
	if !reflect.DeepEqual(sortedEdgeIDs(access.AllowedBy), sortedEdgeIDs(wantAccess.AllowedBy)) {
		t.Fatalf("EffectiveAccess() allowed_by = %#v, want %#v", sortedEdgeIDs(access.AllowedBy), sortedEdgeIDs(wantAccess.AllowedBy))
	}

	if adapter.snapshotCalls != 0 {
		t.Fatalf("expected zero-depth traversals not to materialize a full snapshot, snapshotCalls=%d", adapter.snapshotCalls)
	}
}

func TestSpannerGraphStoreCascadingBlastRadiusFallsBackToSnapshotMaterialization(t *testing.T) {
	base := New()
	base.AddNode(contractStoreTestNode("user:alice", NodeKindUser, "Alice"))
	base.AddNode(contractStoreTestNode("service:api", NodeKindService, "API"))
	base.AddEdge(contractStoreTestEdge("edge:alice:api", "user:alice", "service:api", EdgeKindCanRead))

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter)

	if _, err := store.CascadingBlastRadius(context.Background(), "user:alice", 2); err != nil {
		t.Fatalf("CascadingBlastRadius() error = %v", err)
	}
	if adapter.snapshotCalls == 0 {
		t.Fatal("expected CascadingBlastRadius() to use explicit snapshot fallback")
	}
}

func TestSpannerGraphStoreTraversalDoesNotReexpandVisitedNodes(t *testing.T) {
	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	base.AddNodesBatch([]*Node{alice, api})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:alice", api.ID, alice.ID, EdgeKindCanRead),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter)

	blast, err := store.BlastRadius(context.Background(), alice.ID, 3)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if blast.TotalCount != 1 {
		t.Fatalf("BlastRadius().TotalCount = %d, want 1", blast.TotalCount)
	}
	if got := adapter.lookupOutEdgeCalls[alice.ID]; got != 1 {
		t.Fatalf("LookupOutEdges(%q) calls = %d, want 1", alice.ID, got)
	}
	if got := adapter.lookupOutEdgeCalls[api.ID]; got != 1 {
		t.Fatalf("LookupOutEdges(%q) calls = %d, want 1", api.ID, got)
	}
}
