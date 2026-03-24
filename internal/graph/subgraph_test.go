package graph

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestExtractSubgraphIncludesBoundedNeighborhood(t *testing.T) {
	g := New()
	for _, node := range []*Node{
		{ID: "root", Kind: NodeKindRole},
		{ID: "out-1", Kind: NodeKindBucket},
		{ID: "out-2", Kind: NodeKindBucket},
		{ID: "in-1", Kind: NodeKindUser},
	} {
		g.AddNode(node)
	}
	g.AddEdge(&Edge{ID: "root-out-1", Source: "root", Target: "out-1", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "out-1-out-2", Source: "out-1", Target: "out-2", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "in-1-root", Source: "in-1", Target: "root", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{MaxDepth: 1})

	if got := sub.NodeCount(); got != 3 {
		t.Fatalf("NodeCount() = %d, want 3", got)
	}
	if got := sub.EdgeCount(); got != 2 {
		t.Fatalf("EdgeCount() = %d, want 2", got)
	}
	if _, ok := sub.GetNode("root"); !ok {
		t.Fatal("expected root node in subgraph")
	}
	if _, ok := sub.GetNode("out-1"); !ok {
		t.Fatal("expected outbound neighbor in subgraph")
	}
	if _, ok := sub.GetNode("in-1"); !ok {
		t.Fatal("expected inbound neighbor in subgraph")
	}
	if _, ok := sub.GetNode("out-2"); ok {
		t.Fatal("did not expect depth-2 node in subgraph")
	}
}

func TestExtractSubgraphDefaultsMaxDepthWhenUnset(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "root", Kind: NodeKindWorkload})
	g.AddNode(&Node{ID: "mid", Kind: NodeKindWorkload})
	g.AddNode(&Node{ID: "leaf", Kind: NodeKindWorkload})
	g.AddEdge(&Edge{ID: "root-mid", Source: "root", Target: "mid", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mid-leaf", Source: "mid", Target: "leaf", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{})

	if got := sub.NodeCount(); got != 3 {
		t.Fatalf("NodeCount() = %d, want 3", got)
	}
	if got := sub.EdgeCount(); got != 2 {
		t.Fatalf("EdgeCount() = %d, want 2", got)
	}
}

func TestExtractSubgraphHonorsDirection(t *testing.T) {
	g := New()
	for _, node := range []*Node{
		{ID: "root", Kind: NodeKindRole},
		{ID: "out", Kind: NodeKindBucket},
		{ID: "in", Kind: NodeKindUser},
	} {
		g.AddNode(node)
	}
	g.AddEdge(&Edge{ID: "root-out", Source: "root", Target: "out", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "in-root", Source: "in", Target: "root", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	outgoing := ExtractSubgraph(g, "root", ExtractSubgraphOptions{
		MaxDepth:  1,
		Direction: ExtractSubgraphDirectionOutgoing,
	})
	if _, ok := outgoing.GetNode("out"); !ok {
		t.Fatal("expected outgoing subgraph to include outbound neighbor")
	}
	if _, ok := outgoing.GetNode("in"); ok {
		t.Fatal("did not expect outgoing subgraph to include inbound neighbor")
	}

	incoming := ExtractSubgraph(g, "root", ExtractSubgraphOptions{
		MaxDepth:  1,
		Direction: ExtractSubgraphDirectionIncoming,
	})
	if _, ok := incoming.GetNode("in"); !ok {
		t.Fatal("expected incoming subgraph to include inbound neighbor")
	}
	if _, ok := incoming.GetNode("out"); ok {
		t.Fatal("did not expect incoming subgraph to include outbound neighbor")
	}
}

func TestExtractSubgraphHonorsMaxNodesAndEdgeFilter(t *testing.T) {
	g := New()
	for _, node := range []*Node{
		{ID: "root", Kind: NodeKindRole},
		{ID: "allow-1", Kind: NodeKindBucket},
		{ID: "allow-2", Kind: NodeKindBucket},
		{ID: "deny-1", Kind: NodeKindBucket},
	} {
		g.AddNode(node)
	}
	g.AddEdge(&Edge{ID: "allow-1", Source: "root", Target: "allow-1", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "deny-1", Source: "root", Target: "deny-1", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "allow-2", Source: "root", Target: "allow-2", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{
		MaxDepth: 1,
		MaxNodes: 2,
		EdgeFilter: func(edge *Edge) bool {
			return edge.Kind == EdgeKindCanRead
		},
	})

	if got := sub.NodeCount(); got != 2 {
		t.Fatalf("NodeCount() = %d, want 2", got)
	}
	if _, ok := sub.GetNode("deny-1"); ok {
		t.Fatal("did not expect filtered node in subgraph")
	}
	if _, ok := sub.GetNode("allow-2"); ok {
		t.Fatal("did not expect node beyond MaxNodes limit in subgraph")
	}
	if got := sub.EdgeCount(); got != 1 {
		t.Fatalf("EdgeCount() = %d, want 1", got)
	}
}

func TestExtractSubgraphIsDetachedFromParentMutations(t *testing.T) {
	g := New()
	root := &Node{
		ID:   "root",
		Kind: NodeKindRole,
		Properties: map[string]any{
			"nested": map[string]any{
				"key": "value",
			},
		},
	}
	child := &Node{ID: "child", Kind: NodeKindBucket}
	g.AddNode(root)
	g.AddNode(child)
	g.AddEdge(&Edge{
		ID:     "root-child",
		Source: "root",
		Target: "child",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"actions": []any{"read"},
		},
	})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{MaxDepth: 1})

	root.Properties["nested"].(map[string]any)["key"] = "changed"
	edge := g.GetOutEdges("root")[0]
	edge.Properties["actions"].([]any)[0] = "write"
	g.AddNode(&Node{ID: "late", Kind: NodeKindBucket})

	extractedRoot, ok := sub.GetNode("root")
	if !ok {
		t.Fatal("expected root in extracted subgraph")
	}
	if got := extractedRoot.Properties["nested"].(map[string]any)["key"]; got != "value" {
		t.Fatalf("nested property = %#v, want original value", got)
	}
	extractedEdge := sub.GetOutEdges("root")[0]
	if got := extractedEdge.Properties["actions"].([]any)[0]; got != "read" {
		t.Fatalf("edge action = %#v, want original value", got)
	}
	if _, ok := sub.GetNode("late"); ok {
		t.Fatal("did not expect later parent mutation to appear in extracted subgraph")
	}
}

func TestExtractSubgraphIncludesEdgesBetweenMaxDepthBoundaryNodes(t *testing.T) {
	g := New()
	for _, node := range []*Node{
		{ID: "root", Kind: NodeKindRole},
		{ID: "left", Kind: NodeKindBucket},
		{ID: "right", Kind: NodeKindBucket},
	} {
		g.AddNode(node)
	}
	g.AddEdge(&Edge{ID: "root-left", Source: "root", Target: "left", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "root-right", Source: "root", Target: "right", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "left-right", Source: "left", Target: "right", Kind: EdgeKindConnectsTo, Effect: EdgeEffectAllow})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{MaxDepth: 1, Direction: ExtractSubgraphDirectionOutgoing})

	if got := sub.EdgeCount(); got != 3 {
		t.Fatalf("EdgeCount() = %d, want 3", got)
	}
	foundBoundaryEdge := false
	for _, edge := range sub.GetOutEdges("left") {
		if edge != nil && edge.ID == "left-right" {
			foundBoundaryEdge = true
			break
		}
	}
	if !foundBoundaryEdge {
		t.Fatalf("expected max-depth boundary edge left-right in subgraph, got %#v", sub.GetOutEdges("left"))
	}
}

func TestExtractSubgraphHandlesCycles(t *testing.T) {
	g := New()
	for _, node := range []*Node{
		{ID: "root", Kind: NodeKindRole},
		{ID: "mid", Kind: NodeKindRole},
		{ID: "leaf", Kind: NodeKindRole},
	} {
		g.AddNode(node)
	}
	g.AddEdge(&Edge{ID: "root-mid", Source: "root", Target: "mid", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mid-leaf", Source: "mid", Target: "leaf", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "leaf-root", Source: "leaf", Target: "root", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{
		MaxDepth:  3,
		Direction: ExtractSubgraphDirectionOutgoing,
	})

	if got := sub.NodeCount(); got != 3 {
		t.Fatalf("NodeCount() = %d, want 3", got)
	}
	if got := sub.EdgeCount(); got != 3 {
		t.Fatalf("EdgeCount() = %d, want 3", got)
	}
}

func TestExtractSubgraphReleasesLockWhenEdgeFilterPanics(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "root", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "child", Kind: NodeKindBucket})
	g.AddEdge(&Edge{ID: "root-child", Source: "root", Target: "child", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected edge filter panic")
		}
		done := make(chan struct{})
		go func() {
			g.AddNode(&Node{ID: "late", Kind: NodeKindBucket})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("graph write blocked after ExtractSubgraph panic")
		}
	}()

	_ = ExtractSubgraph(g, "root", ExtractSubgraphOptions{
		MaxDepth: 1,
		EdgeFilter: func(*Edge) bool {
			panic("boom")
		},
	})
}

func TestExtractSubgraphMatchesSequentialReferenceOnWideNeighborhood(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "root", Kind: NodeKindRole})
	for i := 0; i < 96; i++ {
		childID := "child-" + strconv.Itoa(i)
		leafID := "leaf-" + strconv.Itoa(i)
		g.AddNode(&Node{ID: childID, Kind: NodeKindBucket})
		g.AddNode(&Node{ID: leafID, Kind: NodeKindBucket})
		g.AddEdge(&Edge{ID: "root-" + childID, Source: "root", Target: childID, Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
		g.AddEdge(&Edge{ID: childID + "-" + leafID, Source: childID, Target: leafID, Kind: EdgeKindConnectsTo, Effect: EdgeEffectAllow})
		if i > 0 {
			prevChildID := "child-" + strconv.Itoa(i-1)
			g.AddEdge(&Edge{ID: prevChildID + "-" + childID, Source: prevChildID, Target: childID, Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
		}
	}
	g.AddEdge(&Edge{ID: "leaf-95-root", Source: "leaf-95", Target: "root", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	opts := ExtractSubgraphOptions{
		MaxDepth:  2,
		MaxNodes:  40,
		Direction: ExtractSubgraphDirectionOutgoing,
	}

	got := ExtractSubgraph(g, "root", opts)
	want := extractSubgraphSequentialReference(g, "root", opts)

	if !reflect.DeepEqual(sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes())) {
		t.Fatalf("node IDs = %#v, want %#v", sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want)) {
		t.Fatalf("edge IDs = %#v, want %#v", sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want))
	}
}

func TestExtractSubgraphMatchesSequentialReferenceWithCyclesAndBoundaryEdges(t *testing.T) {
	g := New()
	for _, nodeID := range []string{"root", "left", "right", "mid-a", "mid-b", "cycle"} {
		g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole})
	}
	g.AddEdge(&Edge{ID: "root-left", Source: "root", Target: "left", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "root-right", Source: "root", Target: "right", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "left-right", Source: "left", Target: "right", Kind: EdgeKindConnectsTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "right-left", Source: "right", Target: "left", Kind: EdgeKindConnectsTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "left-mid-a", Source: "left", Target: "mid-a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "right-mid-b", Source: "right", Target: "mid-b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "mid-a-cycle", Source: "mid-a", Target: "cycle", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "cycle-root", Source: "cycle", Target: "root", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	opts := ExtractSubgraphOptions{
		MaxDepth:  2,
		Direction: ExtractSubgraphDirectionBoth,
	}

	got := ExtractSubgraph(g, "root", opts)
	want := extractSubgraphSequentialReference(g, "root", opts)

	if !reflect.DeepEqual(sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes())) {
		t.Fatalf("node IDs = %#v, want %#v", sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes()))
	}
	if !reflect.DeepEqual(sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want)) {
		t.Fatalf("edge IDs = %#v, want %#v", sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want))
	}
}

func extractSubgraphSequentialReference(g *Graph, rootID string, opts ExtractSubgraphOptions) *Graph {
	subgraph := New()
	if g == nil {
		return subgraph
	}

	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultExtractSubgraphMaxDepth
	}
	maxNodes := opts.MaxNodes
	if maxNodes <= 0 {
		maxNodes = int(^uint(0) >> 1)
	}

	nodesToCopy := make(map[string]*Node)
	edgesToCopy := make(map[*Edge]struct{})
	seen := newOrdinalVisitSet(nil)
	queue := make([]subgraphQueueItem, 0, 16)
	queueHead := 0

	g.mu.RLock()
	defer g.mu.RUnlock()
	root, ok := g.nodes[rootID]
	if !ok || root == nil || root.DeletedAt != nil {
		return subgraph
	}

	nodesToCopy[rootID] = root
	seen.markNode(rootID, root.ordinal)
	queue = append(queue, subgraphQueueItem{nodeID: rootID, depth: 0})

	visitEdges := func(current string, depth int, edges []*Edge, nextNodeID func(*Edge) string) {
		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}
			if opts.EdgeFilter != nil && !opts.EdgeFilter(edge) {
				continue
			}

			neighborID := nextNodeID(edge)
			neighbor, ok := g.nodes[neighborID]
			if !ok || neighbor == nil || neighbor.DeletedAt != nil {
				continue
			}

			if !seen.hasNode(neighborID, neighbor.ordinal) {
				if depth >= maxDepth || len(nodesToCopy) >= maxNodes {
					continue
				}
				seen.markNode(neighborID, neighbor.ordinal)
				nodesToCopy[neighborID] = neighbor
				queue = append(queue, subgraphQueueItem{nodeID: neighborID, depth: depth + 1})
			}

			if _, ok := nodesToCopy[neighborID]; ok {
				edgesToCopy[edge] = struct{}{}
			}
		}
	}

	for queueHead < len(queue) {
		item := queue[queueHead]
		queueHead++

		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionOutgoing {
			visitEdges(item.nodeID, item.depth, g.outEdges[item.nodeID], func(edge *Edge) string {
				return edge.Target
			})
		}
		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionIncoming {
			visitEdges(item.nodeID, item.depth, g.inEdges[item.nodeID], func(edge *Edge) string {
				return edge.Source
			})
		}
	}

	for _, node := range nodesToCopy {
		subgraph.AddNode(cloneNode(node))
	}
	for edge := range edgesToCopy {
		subgraph.AddEdge(cloneEdge(edge))
	}
	return subgraph
}
