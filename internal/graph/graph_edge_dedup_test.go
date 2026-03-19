package graph

import (
	"strconv"
	"testing"
)

func TestGraphAddEdgeReusesExistingID(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{
		ID:         "edge-1",
		Source:     "node:a",
		Target:     "node:b",
		Kind:       EdgeKindTargets,
		Effect:     EdgeEffectAllow,
		Properties: map[string]any{"state": "first"},
	})

	first := g.GetOutEdges("node:a")[0]
	if first.CreatedAt.IsZero() {
		t.Fatal("expected first edge to receive created_at")
	}

	g.AddEdge(&Edge{
		ID:         "edge-1",
		Source:     "node:a",
		Target:     "node:b",
		Kind:       EdgeKindTargets,
		Effect:     EdgeEffectDeny,
		Priority:   100,
		Properties: map[string]any{"state": "updated"},
	})

	out := g.GetOutEdges("node:a")
	if len(out) != 1 {
		t.Fatalf("expected one active edge after same-ID update, got %d", len(out))
	}
	if got := len(g.outEdges["node:a"]); got != 1 {
		t.Fatalf("expected one stored out-edge after same-ID update, got %d", got)
	}
	if got := len(g.inEdges["node:b"]); got != 1 {
		t.Fatalf("expected one stored in-edge after same-ID update, got %d", got)
	}
	if out[0].Effect != EdgeEffectDeny {
		t.Fatalf("expected updated effect %q, got %q", EdgeEffectDeny, out[0].Effect)
	}
	if out[0].Priority != 100 {
		t.Fatalf("expected updated priority 100, got %d", out[0].Priority)
	}
	if got := out[0].Properties["state"]; got != "updated" {
		t.Fatalf("expected updated properties, got %#v", out[0].Properties)
	}
	if out[0].Version != 2 {
		t.Fatalf("expected version 2 after same-ID update, got %d", out[0].Version)
	}
	if !out[0].CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("expected created_at to be preserved, got %s want %s", out[0].CreatedAt, first.CreatedAt)
	}
}

func TestGraphAddEdgeAllowsDistinctIDsForSameTuple(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{
		ID:     "allow-edge",
		Source: "node:a",
		Target: "node:b",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:       "deny-edge",
		Source:   "node:a",
		Target:   "node:b",
		Kind:     EdgeKindCanRead,
		Effect:   EdgeEffectDeny,
		Priority: 100,
	})

	out := g.GetOutEdges("node:a")
	if len(out) != 2 {
		t.Fatalf("expected distinct IDs on same tuple to coexist, got %d edges", len(out))
	}
}

func TestGraphAddEdgeRevivesDeletedEdgeWithoutAppendingDuplicate(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "node:a",
		Target: "node:b",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	})
	if !g.RemoveEdge("node:a", "node:b", EdgeKindTargets) {
		t.Fatal("expected initial edge removal to succeed")
	}

	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "node:a",
		Target: "node:b",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	})

	out := g.GetOutEdges("node:a")
	if len(out) != 1 {
		t.Fatalf("expected revived edge to be active once, got %d", len(out))
	}
	if got := len(g.outEdges["node:a"]); got != 1 {
		t.Fatalf("expected one stored out-edge after revive, got %d", got)
	}
	if got := len(g.inEdges["node:b"]); got != 1 {
		t.Fatalf("expected one stored in-edge after revive, got %d", got)
	}
	if out[0].DeletedAt != nil {
		t.Fatalf("expected revived edge to be active, got deleted_at=%v", out[0].DeletedAt)
	}
}

func TestGraphAddEdgeRelinksAdjacencyWhenSameIDMoves(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "node:a",
		Target: "node:b",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	})

	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "node:c",
		Target: "node:d",
		Kind:   EdgeKindBasedOn,
		Effect: EdgeEffectAllow,
	})

	if got := len(g.GetOutEdges("node:a")); got != 0 {
		t.Fatalf("expected moved edge to leave old source empty, got %d", got)
	}
	if got := len(g.GetInEdges("node:b")); got != 0 {
		t.Fatalf("expected moved edge to leave old target empty, got %d", got)
	}

	out := g.GetOutEdges("node:c")
	if len(out) != 1 {
		t.Fatalf("expected moved edge on new source, got %d", len(out))
	}
	if out[0].Target != "node:d" || out[0].Kind != EdgeKindBasedOn {
		t.Fatalf("expected moved edge to point at node:d with based_on kind, got %+v", out[0])
	}
	if got := len(g.outEdges["node:c"]); got != 1 {
		t.Fatalf("expected one stored out-edge on new source, got %d", got)
	}
	if got := len(g.inEdges["node:d"]); got != 1 {
		t.Fatalf("expected one stored in-edge on new target, got %d", got)
	}
}

func TestGraphCompactDeletedEdgesEvictsDeletedEdgeIDs(t *testing.T) {
	g := New()

	for i := 0; i < 32; i++ {
		id := "edge-" + strconv.Itoa(i)
		target := "node:" + strconv.Itoa(i)
		g.AddEdge(&Edge{
			ID:     id,
			Source: "node:source",
			Target: target,
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
		if !g.RemoveEdge("node:source", target, EdgeKindTargets) {
			t.Fatalf("expected remove to succeed for %s", id)
		}
	}

	if got := len(g.edgeByID); got != 32 {
		t.Fatalf("expected deleted edges to remain indexed before compaction, got %d", got)
	}

	g.CompactDeletedEdges()

	if got := len(g.edgeByID); got != 0 {
		t.Fatalf("expected compacted deleted edge IDs to be evicted, got %d", got)
	}
}
