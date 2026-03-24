package graph

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type graphStoreBackendFactory struct {
	name string
	new  func(t *testing.T) GraphStore
}

func TestGraphStoreBackendParityCRUDAndSnapshot(t *testing.T) {
	t.Parallel()

	for _, backend := range graphStoreBackendFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()
			runGraphStoreCRUDAndSnapshotContract(t, backend.new(t))
		})
	}
}

func TestGraphStoreBackendParityTraversal(t *testing.T) {
	t.Parallel()

	for _, backend := range graphStoreBackendFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()
			runGraphStoreTraversalContract(t, backend.new(t))
		})
	}
}

func TestGraphStoreBackendParitySpannerTraversalMatchesInMemoryReferenceWithoutSnapshotMaterialization(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reference := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "api")
	db := contractStoreTestNode("service:db", NodeKindService, "db")
	db.Risk = RiskCritical
	reference.AddNodesBatch([]*Node{alice, api, db})
	reference.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:db", api.ID, db.ID, EdgeKindCalls),
	})

	adapter := &fakeSpannerAdapter{store: GraphStore(New())}
	store := NewSpannerGraphStore(adapter, WithSpannerNativeTraversalQueries(true))
	snapshot := CreateSnapshot(reference)
	if err := store.UpsertNodesBatch(ctx, snapshot.Nodes); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}
	if err := store.UpsertEdgesBatch(ctx, snapshot.Edges); err != nil {
		t.Fatalf("UpsertEdgesBatch() error = %v", err)
	}

	blast, err := store.BlastRadius(ctx, alice.ID, 2)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	wantBlast := BlastRadius(reference, alice.ID, 2)
	if !reflect.DeepEqual(sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes)) {
		t.Fatalf("BlastRadius() reachable nodes = %#v, want %#v", sortedReachableNodeIDs(blast.ReachableNodes), sortedReachableNodeIDs(wantBlast.ReachableNodes))
	}

	reverse, err := store.ReverseAccess(ctx, db.ID, 2)
	if err != nil {
		t.Fatalf("ReverseAccess() error = %v", err)
	}
	wantReverse := ReverseAccess(reference, db.ID, 2)
	if !reflect.DeepEqual(sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy)) {
		t.Fatalf("ReverseAccess() accessors = %#v, want %#v", sortedAccessorNodeIDs(reverse.AccessibleBy), sortedAccessorNodeIDs(wantReverse.AccessibleBy))
	}

	access, err := store.EffectiveAccess(ctx, alice.ID, db.ID, 2)
	if err != nil {
		t.Fatalf("EffectiveAccess() error = %v", err)
	}
	wantAccess := EffectiveAccess(reference, alice.ID, db.ID, 2)
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
	wantSubgraph := ExtractSubgraph(reference, alice.ID, ExtractSubgraphOptions{MaxDepth: 2})
	if !reflect.DeepEqual(sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes())) {
		t.Fatalf("ExtractSubgraph() nodes = %#v, want %#v", sortedNodeIDs(subgraph.GetAllNodes()), sortedNodeIDs(wantSubgraph.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph)) {
		t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(subgraph), sortedGraphEdgeIDs(wantSubgraph))
	}

	if adapter.snapshotCalls != 0 {
		t.Fatalf("expected spanner traversal parity path not to materialize snapshots, snapshotCalls=%d", adapter.snapshotCalls)
	}
	if len(adapter.nativeEdgeQueries) == 0 {
		t.Fatal("expected spanner native traversal parity path to issue graph queries")
	}
}

func TestGraphStoreBackendParityCanceledContext(t *testing.T) {
	t.Parallel()

	for _, backend := range graphStoreBackendFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()
			runGraphStoreCanceledContextContract(t, backend.new(t))
		})
	}
}

func graphStoreBackendFactories() []graphStoreBackendFactory {
	return []graphStoreBackendFactory{
		{
			name: "memory",
			new: func(t *testing.T) GraphStore {
				t.Helper()
				return GraphStore(New())
			},
		},
		{
			name: "spanner",
			new: func(t *testing.T) GraphStore {
				t.Helper()
				return NewSpannerGraphStore(&fakeSpannerAdapter{store: GraphStore(New())})
			},
		},
		{
			name: "neptune",
			new: func(t *testing.T) GraphStore {
				t.Helper()
				return NewNeptuneGraphStore(newContractNeptuneExecutor(New()))
			},
		},
	}
}

func runGraphStoreCRUDAndSnapshotContract(t *testing.T, store GraphStore) {
	t.Helper()

	ctx := context.Background()
	alice := contractStoreTestNode("person:alice", NodeKindPerson, "Alice")
	db := contractStoreTestNode("db:payments", NodeKindDatabase, "payments")
	edge := contractStoreTestEdge("access:alice:payments", alice.ID, db.ID, EdgeKindCalls)

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
		t.Fatalf("LookupEdge(after delete) error = %v", err)
	} else if ok {
		t.Fatal("expected removed edge to be absent")
	}

	edgeCount, err = store.CountEdges(ctx)
	if err != nil {
		t.Fatalf("CountEdges(after delete) error = %v", err)
	}
	if edgeCount != 0 {
		t.Fatalf("CountEdges(after delete) = %d, want 0", edgeCount)
	}

	if err := store.DeleteNode(ctx, alice.ID); err != nil {
		t.Fatalf("DeleteNode() error = %v", err)
	}
	if _, ok, err := store.LookupNode(ctx, alice.ID); err != nil {
		t.Fatalf("LookupNode(after delete) error = %v", err)
	} else if ok {
		t.Fatal("expected removed node to be absent")
	}
}

func runGraphStoreTraversalContract(t *testing.T, store GraphStore) {
	t.Helper()

	ctx := context.Background()
	g := New()
	api := contractStoreTestNode("service:api", NodeKindService, "api")
	db := contractStoreTestNode("service:db", NodeKindService, "db")
	db.Risk = RiskCritical
	edge := contractStoreTestEdge("calls:api:db", api.ID, db.ID, EdgeKindCalls)
	g.AddNode(api)
	g.AddNode(db)
	g.AddEdge(edge)

	snapshot := CreateSnapshot(g)
	if err := store.UpsertNodesBatch(ctx, snapshot.Nodes); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}
	if err := store.UpsertEdgesBatch(ctx, snapshot.Edges); err != nil {
		t.Fatalf("UpsertEdgesBatch() error = %v", err)
	}

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

func runGraphStoreCanceledContextContract(t *testing.T, store GraphStore) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.UpsertNode(ctx, contractStoreTestNode("service:api", NodeKindService, "api")); err == nil {
		t.Fatal("expected canceled UpsertNode() to fail")
	}
	if _, _, err := store.LookupNode(ctx, "service:api"); err == nil {
		t.Fatal("expected canceled LookupNode() to fail")
	}
	if _, err := store.Snapshot(ctx); err == nil {
		t.Fatal("expected canceled Snapshot() to fail")
	}
}

func contractStoreTestNode(id string, kind NodeKind, name string) *Node {
	meta := contractStoreTestMetadata()
	properties := meta.PropertyMap()
	switch kind {
	case NodeKindService:
		properties["service_id"] = strings.TrimPrefix(id, "service:")
	}
	return &Node{
		ID:         id,
		Kind:       kind,
		Name:       name,
		Properties: properties,
	}
}

func contractStoreTestEdge(id, source, target string, kind EdgeKind) *Edge {
	meta := contractStoreTestMetadata()
	return &Edge{
		ID:         id,
		Source:     source,
		Target:     target,
		Kind:       kind,
		Properties: meta.PropertyMap(),
	}
}

func contractStoreTestMetadata() WriteMetadata {
	now := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	return NormalizeWriteMetadata(now, now, nil, "contract-test", "contract-test:event", 0.9, WriteMetadataDefaults{
		RecordedAt:      now.Add(2 * time.Minute),
		TransactionFrom: now.Add(2 * time.Minute),
	})
}

type contractNeptuneExecutor struct {
	graph *Graph
	calls []fakeNeptuneCall
}

func newContractNeptuneExecutor(graph *Graph) *contractNeptuneExecutor {
	return &contractNeptuneExecutor{graph: graph}
}

func (f *contractNeptuneExecutor) ExecuteOpenCypher(ctx context.Context, query string, params map[string]any) (any, error) {
	trimmed := strings.TrimSpace(query)
	f.calls = append(f.calls, fakeNeptuneCall{query: trimmed, params: params})

	switch trimmed {
	case strings.TrimSpace(neptuneUpsertNodeQuery):
		node, err := neptuneDecodeNode(params)
		if err != nil {
			return nil, err
		}
		if node != nil {
			f.graph.AddNode(node)
		}
		return []any{map[string]any{"id": node.ID}}, nil
	case strings.TrimSpace(neptuneUpsertNodesBatchQuery):
		for _, record := range contractNeptuneRowParams(params) {
			node, err := neptuneDecodeNode(record)
			if err != nil {
				return nil, err
			}
			if node != nil {
				f.graph.AddNode(node)
			}
		}
		return []any{map[string]any{"total": len(contractNeptuneRowParams(params))}}, nil
	case strings.TrimSpace(neptuneUpsertEdgeQuery):
		edge, err := neptuneDecodeEdge(params)
		if err != nil {
			return nil, err
		}
		if edge != nil {
			f.graph.AddEdge(edge)
		}
		return []any{map[string]any{"id": edge.ID}}, nil
	case strings.TrimSpace(neptuneUpsertEdgesBatchQuery):
		for _, record := range contractNeptuneRowParams(params) {
			edge, err := neptuneDecodeEdge(record)
			if err != nil {
				return nil, err
			}
			if edge != nil {
				f.graph.AddEdge(edge)
			}
		}
		return []any{map[string]any{"total": len(contractNeptuneRowParams(params))}}, nil
	case strings.TrimSpace(neptuneDeleteNodeQuery):
		id, _ := params["id"].(string)
		if err := GraphStore(f.graph).DeleteNode(ctx, strings.TrimSpace(id)); err != nil {
			return nil, err
		}
		return []any{map[string]any{"total": 1}}, nil
	case strings.TrimSpace(neptuneDeleteNodeEdgesQuery):
		return []any{map[string]any{"total": 0}}, nil
	case strings.TrimSpace(neptuneDeleteEdgeQuery):
		id, _ := params["id"].(string)
		if strings.TrimSpace(id) != "" {
			if err := GraphStore(f.graph).DeleteEdge(ctx, strings.TrimSpace(id)); err != nil {
				return nil, err
			}
		}
		return []any{map[string]any{"total": 1}}, nil
	case strings.TrimSpace(neptuneLookupNodeQuery):
		id, _ := params["id"].(string)
		if node, ok := f.graph.GetNode(strings.TrimSpace(id)); ok {
			return []any{map[string]any{"node": neptuneNodeRecordForTest(node)}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneLookupEdgeQuery):
		id, _ := params["id"].(string)
		if edge := contractLookupActiveEdge(f.graph, strings.TrimSpace(id)); edge != nil {
			return []any{map[string]any{"edge": neptuneEdgeRecordForTest(edge)}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneLookupOutEdgesQuery):
		nodeID, _ := params["node_id"].(string)
		return contractNeptuneEdgeRows(f.graph.GetOutEdges(strings.TrimSpace(nodeID))), nil
	case strings.TrimSpace(neptuneLookupInEdgesQuery):
		nodeID, _ := params["node_id"].(string)
		return contractNeptuneEdgeRows(f.graph.GetInEdges(strings.TrimSpace(nodeID))), nil
	case strings.TrimSpace(neptuneLookupNodesByKindQuery):
		return contractNeptuneLookupNodesByKindRows(f.graph, params["kinds"]), nil
	case strings.TrimSpace(neptuneCountNodesQuery):
		return []any{map[string]any{"total": f.graph.NodeCount()}}, nil
	case strings.TrimSpace(neptuneCountEdgesQuery):
		return []any{map[string]any{"total": f.graph.EdgeCount()}}, nil
	case strings.TrimSpace(neptuneSnapshotNodesQuery):
		return contractNeptuneNodeRows(f.graph.GetAllNodes()), nil
	case strings.TrimSpace(neptuneSnapshotEdgesQuery):
		return contractNeptuneEdgeRows(contractAllActiveEdges(f.graph)), nil
	}

	if strings.Contains(trimmed, "CREATE INDEX") {
		return []any{map[string]any{"total": 0}}, nil
	}
	if strings.Contains(trimmed, "UNWIND nodes(p) AS n") || strings.Contains(trimmed, "UNWIND relationships(p) AS r") {
		view, err := contractNeptuneSubgraphForQuery(f.graph, trimmed, params)
		if err != nil {
			return nil, err
		}
		if strings.Contains(trimmed, "UNWIND nodes(p) AS n") {
			return traversalNodeRows(view), nil
		}
		return traversalEdgeRows(view), nil
	}

	return nil, fmt.Errorf("unexpected contract neptune query: %s", trimmed)
}

func contractNeptuneRowParams(params map[string]any) []map[string]any {
	rows, _ := params["rows"].([]map[string]any)
	if rows != nil {
		return rows
	}
	rawRows, _ := params["rows"].([]any)
	out := make([]map[string]any, 0, len(rawRows))
	for _, raw := range rawRows {
		record, ok := raw.(map[string]any)
		if ok {
			out = append(out, record)
		}
	}
	return out
}

func contractLookupActiveEdge(g *Graph, id string) *Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edge := g.edgeByID[id]
	if !g.activeEdgeLocked(edge) {
		return nil
	}
	return edge
}

func contractAllActiveEdges(g *Graph) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := make([]*Edge, 0, len(g.edgeByID))
	for _, edge := range g.edgeByID {
		if g.activeEdgeLocked(edge) {
			edges = append(edges, edge)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})
	return edges
}

func contractNeptuneNodeRows(nodes []*Node) []any {
	sorted := append([]*Node(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	rows := make([]any, 0, len(sorted))
	for _, node := range sorted {
		rows = append(rows, map[string]any{"node": neptuneNodeRecordForTest(node)})
	}
	return rows
}

func contractNeptuneEdgeRows(edges []*Edge) []any {
	sorted := append([]*Edge(nil), edges...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	rows := make([]any, 0, len(sorted))
	for _, edge := range sorted {
		rows = append(rows, map[string]any{"edge": neptuneEdgeRecordForTest(edge)})
	}
	return rows
}

func contractNeptuneLookupNodesByKindRows(g *Graph, rawKinds any) []any {
	var kinds []NodeKind
	switch typed := rawKinds.(type) {
	case []string:
		for _, kind := range typed {
			kinds = append(kinds, NodeKind(kind))
		}
	case []any:
		for _, kind := range typed {
			text, _ := kind.(string)
			if strings.TrimSpace(text) != "" {
				kinds = append(kinds, NodeKind(text))
			}
		}
	}
	return contractNeptuneNodeRows(g.GetNodesByKind(kinds...))
}

func contractNeptuneSubgraphForQuery(g *Graph, query string, params map[string]any) (*Graph, error) {
	rootID, _ := params["root_id"].(string)
	if strings.TrimSpace(rootID) == "" {
		return New(), nil
	}
	maxDepth, err := traversalDepthFromQuery(query)
	if err != nil {
		return nil, err
	}
	direction, err := traversalDirectionFromQuery(query)
	if err != nil {
		return nil, err
	}
	return ExtractSubgraph(g, rootID, ExtractSubgraphOptions{
		MaxDepth:  maxDepth,
		Direction: direction,
	}), nil
}
