package graph

import (
	"testing"
	"time"
)

func TestGraphTemporalAddNodeDefaults(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	now := time.Date(2026, 3, 8, 10, 0, 0, 0, time.UTC)
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{ID: "node-1", Kind: NodeKindUser})

	node, ok := g.GetNode("node-1")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if node.CreatedAt.IsZero() || node.UpdatedAt.IsZero() {
		t.Fatalf("expected temporal fields to be initialized, got created=%v updated=%v", node.CreatedAt, node.UpdatedAt)
	}
	if !node.CreatedAt.Equal(now) || !node.UpdatedAt.Equal(now) {
		t.Fatalf("expected created/updated to equal %v, got created=%v updated=%v", now, node.CreatedAt, node.UpdatedAt)
	}
	if node.Version != 1 {
		t.Fatalf("expected initial version 1, got %d", node.Version)
	}
	if node.DeletedAt != nil {
		t.Fatalf("expected node to be active")
	}
}

func TestGraphTemporalAddNodeUpdateTracksHistory(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	t0 := time.Date(2026, 3, 8, 10, 0, 0, 0, time.UTC)
	calls := 0
	temporalNowUTC = func() time.Time {
		calls++
		return t0.Add(time.Duration(calls) * time.Minute)
	}

	g := New()
	g.AddNode(&Node{ID: "node-1", Kind: NodeKindUser, Properties: map[string]any{"team": "red"}})
	first, _ := g.GetNode("node-1")
	firstCreated := first.CreatedAt

	g.AddNode(&Node{ID: "node-1", Kind: NodeKindUser, Properties: map[string]any{"team": "blue"}})
	node, ok := g.GetNode("node-1")
	if !ok {
		t.Fatal("expected updated node")
	}
	if node.Version != 2 {
		t.Fatalf("expected version 2, got %d", node.Version)
	}
	if !node.CreatedAt.Equal(firstCreated) {
		t.Fatalf("expected created_at to stay stable, first=%v now=%v", firstCreated, node.CreatedAt)
	}
	if node.PreviousProperties["team"] != "red" {
		t.Fatalf("expected previous_properties to contain old value, got %#v", node.PreviousProperties)
	}
	if node.Properties["team"] != "blue" {
		t.Fatalf("expected latest property value, got %#v", node.Properties)
	}
}

func TestGraphTemporalSetNodePropertyTracksPreviousAndVersion(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	t0 := time.Date(2026, 3, 8, 10, 0, 0, 0, time.UTC)
	calls := 0
	temporalNowUTC = func() time.Time {
		calls++
		return t0.Add(time.Duration(calls) * time.Minute)
	}

	g := New()
	g.AddNode(&Node{ID: "node-1", Kind: NodeKindUser, Properties: map[string]any{"department": "security"}})
	if !g.SetNodeProperty("node-1", "department", "platform") {
		t.Fatal("expected SetNodeProperty to succeed")
	}

	node, _ := g.GetNode("node-1")
	if node.Version != 2 {
		t.Fatalf("expected version 2, got %d", node.Version)
	}
	if node.PreviousProperties["department"] != "security" {
		t.Fatalf("expected previous properties to keep old value, got %#v", node.PreviousProperties)
	}
	if node.Properties["department"] != "platform" {
		t.Fatalf("expected new property value, got %#v", node.Properties)
	}
}

func TestGraphTemporalRemoveNodeSoftDelete(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	t0 := time.Date(2026, 3, 8, 10, 0, 0, 0, time.UTC)
	calls := 0
	temporalNowUTC = func() time.Time {
		calls++
		return t0.Add(time.Duration(calls) * time.Minute)
	}

	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddEdge(&Edge{ID: "e1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	if !g.RemoveNode("role:admin") {
		t.Fatal("expected RemoveNode to succeed")
	}
	if _, ok := g.GetNode("role:admin"); ok {
		t.Fatal("expected deleted node to be hidden from GetNode")
	}
	deleted, ok := g.GetNodeIncludingDeleted("role:admin")
	if !ok || deleted.DeletedAt == nil {
		t.Fatalf("expected soft-deleted node to remain retrievable with DeletedAt")
	}
	if len(g.GetAllNodes()) != 1 {
		t.Fatalf("expected only active nodes in GetAllNodes, got %d", len(g.GetAllNodes()))
	}
	if len(g.GetAllNodesIncludingDeleted()) != 2 {
		t.Fatalf("expected deleted nodes to be included in GetAllNodesIncludingDeleted")
	}
	if len(g.GetOutEdges("user:alice")) != 0 {
		t.Fatalf("expected edges to soft-deleted node to be hidden")
	}
}

func TestGraphTemporalRemoveEdgeSoftDelete(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()
	temporalNowUTC = func() time.Time { return time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC) }

	g := New()
	g.AddNode(&Node{ID: "a", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "b", Kind: NodeKindRole})
	g.AddEdge(&Edge{ID: "e1", Source: "a", Target: "b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "a", Target: "b", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	if !g.RemoveEdge("a", "b", EdgeKindCanAssume) {
		t.Fatal("expected RemoveEdge to report removal")
	}
	out := g.GetOutEdges("a")
	if len(out) != 1 || out[0].Kind != EdgeKindCanRead {
		t.Fatalf("expected only undeleted can_read edge to remain visible, got %#v", out)
	}
	if g.outEdges["a"][0].DeletedAt == nil {
		t.Fatalf("expected first edge to be soft-deleted internally")
	}
}

func TestGraphTemporalBuildIndexSkipsDeleted(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111", Provider: "aws", Risk: RiskHigh})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222", Provider: "aws", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "x", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow, Properties: map[string]any{"cross_account": true}})

	if !g.RemoveNode("role:admin") {
		t.Fatal("expected RemoveNode to succeed")
	}
	g.BuildIndex()

	if got := len(g.GetNodesByKindIndexed(NodeKindRole)); got != 0 {
		t.Fatalf("expected deleted role to be excluded from index, got %d", got)
	}
	if got := len(g.GetCrossAccountEdgesIndexed()); got != 0 {
		t.Fatalf("expected deleted edges to be excluded from cross-account index, got %d", got)
	}
}

func TestGraphTemporalNodesAliases(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "node-a", Kind: NodeKindUser})
	if len(g.Nodes()) != 1 {
		t.Fatalf("expected Nodes() to return active nodes")
	}
	if !g.RemoveNode("node-a") {
		t.Fatal("expected RemoveNode to succeed")
	}
	if len(g.Nodes()) != 0 {
		t.Fatalf("expected Nodes() to hide deleted nodes")
	}
	if len(g.NodesIncludingDeleted()) != 1 {
		t.Fatalf("expected NodesIncludingDeleted() to include soft-deleted nodes")
	}
}
