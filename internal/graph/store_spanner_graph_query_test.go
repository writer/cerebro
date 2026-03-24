package graph

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestSpannerGraphTraversalEdgesStatementUsesGraphTableTrailSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		direction      spannerTraversalDirection
		maxDepth       int
		wantPattern    string
		wantUnionCount int
	}{
		{
			name:           "outgoing",
			direction:      spannerTraversalDirectionOutgoing,
			maxDepth:       2,
			wantPattern:    "MATCH TRAIL (n0 {node_id: @root_id})-[e1]->(n1)-[e2]->(n2)-[e3]->(n3)",
			wantUnionCount: 5,
		},
		{
			name:           "incoming",
			direction:      spannerTraversalDirectionIncoming,
			maxDepth:       2,
			wantPattern:    "MATCH TRAIL (n0)-[e1]->(n1)-[e2]->(n2)-[e3]->(n3 {node_id: @root_id})",
			wantUnionCount: 5,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statement, err := spannerGraphTraversalEdgesStatement("service:root", tt.direction, tt.maxDepth)
			if err != nil {
				t.Fatalf("spannerGraphTraversalEdgesStatement() error = %v", err)
			}
			if got := statement.Params["root_id"]; got != "service:root" {
				t.Fatalf("statement root_id = %#v, want %q", got, "service:root")
			}
			if !strings.Contains(statement.SQL, "FROM GRAPH_TABLE(") {
				t.Fatalf("statement SQL %q does not use GRAPH_TABLE", statement.SQL)
			}
			if !strings.Contains(statement.SQL, spannerGraphStorePropertyGraphName) {
				t.Fatalf("statement SQL %q does not reference %q", statement.SQL, spannerGraphStorePropertyGraphName)
			}
			if !strings.Contains(statement.SQL, tt.wantPattern) {
				t.Fatalf("statement SQL %q does not contain %q", statement.SQL, tt.wantPattern)
			}
			if got := strings.Count(statement.SQL, "UNION DISTINCT"); got != tt.wantUnionCount {
				t.Fatalf("UNION DISTINCT count = %d, want %d", got, tt.wantUnionCount)
			}
		})
	}
}

func TestSpannerGraphStoreUsesNativeTraversalQueriesWhenEnabled(t *testing.T) {
	t.Parallel()

	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	db := contractStoreTestNode("service:db", NodeKindService, "DB")
	db.Risk = RiskCritical
	base.AddNodesBatch([]*Node{alice, api, db})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:db", api.ID, db.ID, EdgeKindCalls),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter, WithSpannerNativeTraversalQueries(true))
	ctx := context.Background()

	blast, err := store.BlastRadius(ctx, alice.ID, 2)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	wantBlast := BlastRadius(base, alice.ID, 2)
	if !reflect.DeepEqual(sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes)) {
		t.Fatalf("BlastRadius() reachable nodes = %#v, want %#v", sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes))
	}

	subgraph, err := store.ExtractSubgraph(ctx, alice.ID, ExtractSubgraphOptions{MaxDepth: 2})
	if err != nil {
		t.Fatalf("ExtractSubgraph() error = %v", err)
	}
	wantSubgraph := ExtractSubgraph(base, alice.ID, ExtractSubgraphOptions{MaxDepth: 2})
	if !reflect.DeepEqual(sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph)) {
		t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph))
	}

	if len(adapter.nativeEdgeQueries) == 0 {
		t.Fatal("expected native traversal path to issue graph queries")
	}
	if adapter.snapshotCalls != 0 {
		t.Fatalf("expected native traversal path not to materialize snapshots, snapshotCalls=%d", adapter.snapshotCalls)
	}
}

func TestSpannerGraphStoreFallsBackToLookupTraversalWhenNativeQueriesDisabled(t *testing.T) {
	t.Parallel()

	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	base.AddNodesBatch([]*Node{alice, api})
	base.AddEdge(contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead))

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter)

	if _, err := store.BlastRadius(context.Background(), alice.ID, 1); err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if len(adapter.nativeEdgeQueries) != 0 {
		t.Fatalf("expected native traversal queries to stay disabled, got %d", len(adapter.nativeEdgeQueries))
	}
	if got := adapter.lookupOutEdgeCalls[alice.ID]; got == 0 {
		t.Fatalf("expected lookup-based traversal expansion for %q, got %d calls", alice.ID, got)
	}
}

func TestSpannerGraphStoreNativeTraversalHandlesCyclesAndSelfReferences(t *testing.T) {
	t.Parallel()

	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	base.AddNodesBatch([]*Node{alice, api})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:alice", alice.ID, alice.ID, EdgeKindMemberOf),
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:alice", api.ID, alice.ID, EdgeKindCanWrite),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter, WithSpannerNativeTraversalQueries(true))
	ctx := context.Background()

	subgraph, err := store.ExtractSubgraph(ctx, alice.ID, ExtractSubgraphOptions{
		MaxDepth:  2,
		Direction: ExtractSubgraphDirectionOutgoing,
	})
	if err != nil {
		t.Fatalf("ExtractSubgraph() error = %v", err)
	}
	wantSubgraph := ExtractSubgraph(base, alice.ID, ExtractSubgraphOptions{
		MaxDepth:  2,
		Direction: ExtractSubgraphDirectionOutgoing,
	})
	if !reflect.DeepEqual(sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes())) {
		t.Fatalf("ExtractSubgraph() nodes = %#v, want %#v", sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph)) {
		t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph))
	}
	if len(adapter.nativeEdgeQueries) == 0 {
		t.Fatal("expected cycle/self-reference traversal to use native graph queries")
	}
}

func TestSpannerGraphStoreNativeTraversalFallsBackForBidirectionalMixedPaths(t *testing.T) {
	t.Parallel()

	base := New()
	root := contractStoreTestNode("service:root", NodeKindService, "Root")
	middle := contractStoreTestNode("service:middle", NodeKindService, "Middle")
	branch := contractStoreTestNode("service:branch", NodeKindService, "Branch")
	base.AddNodesBatch([]*Node{root, middle, branch})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:root:middle", root.ID, middle.ID, EdgeKindCalls),
		contractStoreTestEdge("edge:branch:middle", branch.ID, middle.ID, EdgeKindCalls),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(base)}
	store := NewSpannerGraphStore(adapter, WithSpannerNativeTraversalQueries(true))
	ctx := context.Background()

	subgraph, err := store.ExtractSubgraph(ctx, root.ID, ExtractSubgraphOptions{
		MaxDepth:  2,
		Direction: ExtractSubgraphDirectionBoth,
	})
	if err != nil {
		t.Fatalf("ExtractSubgraph() error = %v", err)
	}
	wantSubgraph := ExtractSubgraph(base, root.ID, ExtractSubgraphOptions{
		MaxDepth:  2,
		Direction: ExtractSubgraphDirectionBoth,
	})
	if !reflect.DeepEqual(sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes())) {
		t.Fatalf("ExtractSubgraph() nodes = %#v, want %#v", sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph)) {
		t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph))
	}
	if len(adapter.nativeEdgeQueries) != 0 {
		t.Fatalf("expected bidirectional traversal to fall back to lookup expansion, got %d native queries", len(adapter.nativeEdgeQueries))
	}
	if got := adapter.lookupInEdgeCalls[middle.ID]; got == 0 {
		t.Fatalf("expected lookup-based bidirectional traversal to expand incoming edges for %q, got %d calls", middle.ID, got)
	}
}
