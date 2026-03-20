package graph

import (
	"testing"
	"time"
)

func TestGraphChangeSubscriptionFiltersNodeAndEdgeChanges(t *testing.T) {
	g := New()
	sub := g.SubscribeChanges(GraphChangeFilter{
		NodeKinds: []NodeKind{NodeKindUser},
		EdgeKinds: []EdgeKind{EdgeKindCanAssume},
	}, 1)
	defer sub.Close()

	g.AddNode(&Node{ID: "bucket:logs", Kind: NodeKindBucket, Name: "logs"})
	assertNoGraphChange(t, sub.Changes(), 50*time.Millisecond)

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	change := assertGraphChange(t, sub.Changes(), time.Second)
	if change.Type != GraphChangeNodeUpserted {
		t.Fatalf("expected node upsert change, got %s", change.Type)
	}
	if change.NodeID != "user:alice" {
		t.Fatalf("expected user node change, got %q", change.NodeID)
	}

	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin"})
	g.AddEdge(&Edge{Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume})
	change = assertGraphChange(t, sub.Changes(), time.Second)
	if change.Type != GraphChangeEdgeUpserted {
		t.Fatalf("expected edge upsert change, got %s", change.Type)
	}
	if change.EdgeKind != EdgeKindCanAssume {
		t.Fatalf("expected can_assume edge change, got %s", change.EdgeKind)
	}
}

func TestRemoveNodeEmitsEdgeRemovalChanges(t *testing.T) {
	g := New()
	sub := g.SubscribeChanges(GraphChangeFilter{
		EdgeKinds: []EdgeKind{EdgeKindCanAssume},
	}, 4)
	defer sub.Close()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin"})
	g.AddEdge(&Edge{Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume})
	change := assertGraphChange(t, sub.Changes(), time.Second)
	if change.Type != GraphChangeEdgeUpserted {
		t.Fatalf("expected edge upsert change, got %s", change.Type)
	}

	if !g.RemoveNode("user:alice") {
		t.Fatal("expected node removal to succeed")
	}

	change = assertGraphChange(t, sub.Changes(), time.Second)
	if change.Type != GraphChangeEdgeRemoved {
		t.Fatalf("expected edge removal change, got %s", change.Type)
	}
	if change.EdgeKind != EdgeKindCanAssume {
		t.Fatalf("expected can_assume edge removal, got %s", change.EdgeKind)
	}
}

func assertGraphChange(t *testing.T, ch <-chan GraphChange, timeout time.Duration) GraphChange {
	t.Helper()
	select {
	case change := <-ch:
		return change
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for graph change after %s", timeout)
		return GraphChange{}
	}
}

func assertNoGraphChange(t *testing.T, ch <-chan GraphChange, timeout time.Duration) {
	t.Helper()
	select {
	case change := <-ch:
		t.Fatalf("unexpected graph change: %+v", change)
	case <-time.After(timeout):
	}
}
