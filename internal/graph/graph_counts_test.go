package graph

import "testing"

func TestGraphCountsMatchFullScanAcrossMutations(t *testing.T) {
	g := New()

	assertCountsMatchScan := func(step string) {
		t.Helper()
		wantNodes, wantEdges := fullScanGraphCounts(g)
		if got := g.NodeCount(); got != wantNodes {
			t.Fatalf("%s: NodeCount = %d, want %d", step, got, wantNodes)
		}
		if got := g.EdgeCount(); got != wantEdges {
			t.Fatalf("%s: EdgeCount = %d, want %d", step, got, wantEdges)
		}
	}

	assertCountsMatchScan("empty")

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "bucket:data", Kind: NodeKindBucket})
	assertCountsMatchScan("after add nodes")

	g.AddEdge(&Edge{ID: "e1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "role:admin", Target: "bucket:data", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "bucket:data", Target: "user:alice", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	assertCountsMatchScan("after add edges")

	g.SetNodeProperty("user:alice", "team", "platform")
	assertCountsMatchScan("after property mutation")

	if !g.RemoveEdge("user:alice", "role:admin", EdgeKindCanAssume) {
		t.Fatal("expected RemoveEdge to remove edge")
	}
	assertCountsMatchScan("after remove edge")

	if !g.RemoveNode("role:admin") {
		t.Fatal("expected RemoveNode to remove node")
	}
	assertCountsMatchScan("after remove node")

	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddEdge(&Edge{ID: "e4", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	assertCountsMatchScan("after revive node and edge")

	g.ClearEdges()
	assertCountsMatchScan("after clear edges")

	g.Clear()
	assertCountsMatchScan("after clear graph")
}

func TestGraphCountsMatchFullScanAfterSnapshotRestore(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "b", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "c", Kind: NodeKindBucket})
	g.AddEdge(&Edge{ID: "e1", Source: "a", Target: "b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "b", Target: "c", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	restored := RestoreFromSnapshot(CreateSnapshot(g))
	wantNodes, wantEdges := fullScanGraphCounts(restored)
	if got := restored.NodeCount(); got != wantNodes {
		t.Fatalf("restored NodeCount = %d, want %d", got, wantNodes)
	}
	if got := restored.EdgeCount(); got != wantEdges {
		t.Fatalf("restored EdgeCount = %d, want %d", got, wantEdges)
	}
}

func fullScanGraphCounts(g *Graph) (nodes int, edges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, node := range g.nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		nodes++
	}
	for _, edgeList := range g.outEdges {
		for _, edge := range edgeList {
			if g.activeEdgeLocked(edge) {
				edges++
			}
		}
	}
	return nodes, edges
}
