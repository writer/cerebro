package graph

import (
	"fmt"
	"testing"
	"time"
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

func TestRestoreFromSnapshotDoesNotCountOrphanedEdgesAsActive(t *testing.T) {
	snapshot := &Snapshot{
		Nodes: []*Node{
			{ID: "user:alice", Kind: NodeKindUser},
		},
		Edges: []*Edge{
			{ID: "orphan-source", Source: "user:missing", Target: "user:alice", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
			{ID: "orphan-target", Source: "user:alice", Target: "user:ghost", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
			{ID: "valid", Source: "user:alice", Target: "user:alice", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
		},
		Metadata: Metadata{NodeCount: 1, EdgeCount: 1},
	}

	restored := RestoreFromSnapshot(snapshot)

	if got := restored.EdgeCount(); got != 1 {
		t.Fatalf("EdgeCount() = %d, want 1", got)
	}
	if got := restored.activeEdgeCount.Load(); got != 1 {
		t.Fatalf("activeEdgeCount = %d, want 1", got)
	}
	if edge := restored.edgeByID["orphan-source"]; edge == nil {
		t.Fatal("expected orphaned edge to be retained in full restore")
	}
}

func TestRestoreFromSnapshotDoesNotIndexOrphanedCrossAccountEdges(t *testing.T) {
	snapshot := &Snapshot{
		Nodes: []*Node{
			{ID: "user:alice", Kind: NodeKindUser},
		},
		Edges: []*Edge{
			{
				ID:     "orphan-cross-account",
				Source: "user:missing",
				Target: "user:alice",
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"cross_account": true,
				},
			},
		},
	}

	restored := RestoreFromSnapshot(snapshot)

	if got := restored.EdgeCount(); got != 0 {
		t.Fatalf("EdgeCount() = %d, want 0 for orphaned edge", got)
	}
	if got := len(restored.GetCrossAccountEdgesIndexed()); got != 0 {
		t.Fatalf("len(GetCrossAccountEdgesIndexed()) = %d, want 0", got)
	}
	if edge := restored.edgeByID["orphan-cross-account"]; edge == nil {
		t.Fatal("expected orphaned cross-account edge tombstone to remain restorable")
	}
}

func TestGraphViewFromSnapshotPreservesPropertyHistory(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "service:payments",
		Kind:       NodeKindService,
		Properties: map[string]any{"status": "healthy"},
	})

	now = base.Add(2 * time.Hour)
	g.SetNodeProperty("service:payments", "status", "degraded")

	snapshot := CreateSnapshot(g)

	now = base.Add(8 * 24 * time.Hour)
	view := GraphViewFromSnapshot(snapshot)
	node, ok := view.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected restored active node")
	}

	history := node.PropertyHistory["status"]
	if len(history) != 2 {
		t.Fatalf("expected property history to be preserved, got %#v", history)
	}
	if got := history[0].Value; got != "healthy" {
		t.Fatalf("history[0].Value = %#v, want healthy", got)
	}
	if got := history[1].Value; got != "degraded" {
		t.Fatalf("history[1].Value = %#v, want degraded", got)
	}

	record, ok := GetEntityRecordAtTime(view, "service:payments", base.Add(30*time.Minute), now)
	if !ok {
		t.Fatal("expected point-in-time entity reconstruction")
	}
	if got := record.Entity.Properties["status"]; got != "healthy" {
		t.Fatalf("historical status = %#v, want healthy", got)
	}
}

func TestRestoreFromSnapshotPreservesDeletedState(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
	})
	g.AddNode(&Node{
		ID:   "database:payments",
		Kind: NodeKindDatabase,
	})
	g.AddEdge(&Edge{
		ID:     "service:payments->database:payments:depends_on",
		Source: "service:payments",
		Target: "database:payments",
		Kind:   EdgeKindDependsOn,
		Effect: EdgeEffectAllow,
	})
	g.RemoveEdge("service:payments", "database:payments", EdgeKindDependsOn)
	g.RemoveNode("service:payments")

	restored := RestoreFromSnapshot(CreateSnapshot(g))

	if _, ok := restored.GetNode("service:payments"); ok {
		t.Fatal("expected deleted node to stay excluded from active reads")
	}
	deletedNode, ok := restored.GetNodeIncludingDeleted("service:payments")
	if !ok || deletedNode == nil || deletedNode.DeletedAt == nil {
		t.Fatalf("expected deleted node tombstone after restore, got %#v", deletedNode)
	}

	deletedEdge := restored.edgeByID["service:payments->database:payments:depends_on"]
	if deletedEdge == nil || deletedEdge.DeletedAt == nil {
		t.Fatalf("expected deleted edge tombstone after restore, got %#v", deletedEdge)
	}
	if restored.EdgeCount() != 0 {
		t.Fatalf("EdgeCount() = %d, want 0", restored.EdgeCount())
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
