package graph

import (
	"fmt"
	"testing"
)

func TestRestoreFromSnapshotSkipsInvalidEntries(t *testing.T) {
	snapshot := &Snapshot{
		Nodes: []*Node{
			nil,
			{ID: "", Kind: NodeKindUser},
			{ID: "user:alice", Kind: NodeKindUser},
		},
		Edges: []*Edge{
			nil,
			{ID: "missing-source", Target: "user:alice", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
			{ID: "missing-target", Source: "user:alice", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
			{ID: "valid", Source: "user:alice", Target: "user:alice", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
		},
		Metadata: Metadata{NodeCount: 1, EdgeCount: 1},
	}

	restored := RestoreFromSnapshot(snapshot)

	if got := restored.NodeCount(); got != 1 {
		t.Fatalf("NodeCount = %d, want 1", got)
	}
	if got := restored.EdgeCount(); got != 1 {
		t.Fatalf("EdgeCount = %d, want 1", got)
	}
	if restored.Metadata().NodeCount != 1 || restored.Metadata().EdgeCount != 1 {
		t.Fatalf("metadata not preserved, got %#v", restored.Metadata())
	}
}

func BenchmarkRestoreFromSnapshot(b *testing.B) {
	snapshot := benchmarkGraphSnapshot(2000, 4000)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		restored := RestoreFromSnapshot(snapshot)
		if restored.NodeCount() != 2000 || restored.EdgeCount() != 4000 {
			b.Fatalf("unexpected restored counts: nodes=%d edges=%d", restored.NodeCount(), restored.EdgeCount())
		}
	}
}

func benchmarkGraphSnapshot(nodeCount, edgeCount int) *Snapshot {
	g := New()
	nodes := make([]*Node, 0, nodeCount)
	for i := 0; i < nodeCount; i++ {
		nodes = append(nodes, &Node{
			ID:   fmt.Sprintf("node:%d", i),
			Kind: NodeKindWorkload,
		})
	}
	g.AddNodesBatch(nodes)

	edges := make([]*Edge, 0, edgeCount)
	for i := 0; i < edgeCount; i++ {
		source := fmt.Sprintf("node:%d", i%nodeCount)
		target := fmt.Sprintf("node:%d", (i+1)%nodeCount)
		edges = append(edges, &Edge{
			ID:     fmt.Sprintf("edge:%d", i),
			Source: source,
			Target: target,
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
	}
	g.AddEdgesBatch(edges)
	return CreateSnapshot(g)
}
