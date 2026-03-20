package graph

import "testing"

func TestGraphNodeOrdinalsRoundTripWithoutChangingStringAPI(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111111111111"})
	g.AddNode(&Node{ID: "bucket:data", Kind: NodeKindBucket, Account: "111111111111"})
	g.AddEdge(&Edge{
		ID:     "edge:alice-data",
		Source: "user:alice",
		Target: "bucket:data",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	aliceOrdinal, ok := g.LookupNodeOrdinal("user:alice")
	if !ok || aliceOrdinal == InvalidNodeOrdinal {
		t.Fatalf("LookupNodeOrdinal(user:alice) = (%d, %t), want non-zero,true", aliceOrdinal, ok)
	}
	dataOrdinal, ok := g.LookupNodeOrdinal("bucket:data")
	if !ok || dataOrdinal == InvalidNodeOrdinal {
		t.Fatalf("LookupNodeOrdinal(bucket:data) = (%d, %t), want non-zero,true", dataOrdinal, ok)
	}
	if resolved, ok := g.ResolveNodeOrdinal(aliceOrdinal); !ok || resolved != "user:alice" {
		t.Fatalf("ResolveNodeOrdinal(%d) = (%q, %t), want user:alice,true", aliceOrdinal, resolved, ok)
	}

	node, ok := g.GetNode("user:alice")
	if !ok {
		t.Fatal("expected GetNode(user:alice) to succeed")
	}
	if node.ordinal != aliceOrdinal {
		t.Fatalf("node.ordinal = %d, want %d", node.ordinal, aliceOrdinal)
	}

	edges := g.GetOutEdges("user:alice")
	if len(edges) != 1 {
		t.Fatalf("expected 1 outbound edge, got %d", len(edges))
	}
	if edges[0].Source != "user:alice" || edges[0].Target != "bucket:data" {
		t.Fatalf("string API changed: edge = %#v", edges[0])
	}
	if edges[0].sourceOrd != aliceOrdinal || edges[0].targetOrd != dataOrdinal {
		t.Fatalf("edge ordinals = (%d,%d), want (%d,%d)", edges[0].sourceOrd, edges[0].targetOrd, aliceOrdinal, dataOrdinal)
	}
}

func TestGraphNodeOrdinalIndexSurvivesSnapshotRestore(t *testing.T) {
	g := setupTestGraph()
	snapshot := CreateSnapshot(g)
	restored := RestoreFromSnapshot(snapshot)

	aliceOrdinal, ok := restored.LookupNodeOrdinal("user:alice")
	if !ok || aliceOrdinal == InvalidNodeOrdinal {
		t.Fatalf("restored LookupNodeOrdinal(user:alice) = (%d, %t), want non-zero,true", aliceOrdinal, ok)
	}
	if resolved, ok := restored.ResolveNodeOrdinal(aliceOrdinal); !ok || resolved != "user:alice" {
		t.Fatalf("restored ResolveNodeOrdinal(%d) = (%q, %t), want user:alice,true", aliceOrdinal, resolved, ok)
	}

	for _, edge := range restored.GetOutEdges("user:alice") {
		if edge.sourceOrd == InvalidNodeOrdinal || edge.targetOrd == InvalidNodeOrdinal {
			t.Fatalf("expected restored edge ordinals, got %#v", edge)
		}
	}
}

func TestGraphForkCopiesNodeIDIndexIndependently(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111111111111"})

	fork := g.Fork()
	fork.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser, Account: "111111111111"})

	if _, ok := g.LookupNodeOrdinal("user:bob"); ok {
		t.Fatal("expected original graph node ID index to stay unchanged after fork mutation")
	}
	if ordinal, ok := fork.LookupNodeOrdinal("user:bob"); !ok || ordinal == InvalidNodeOrdinal {
		t.Fatalf("expected fork to resolve user:bob ordinal, got (%d, %t)", ordinal, ok)
	}
}
