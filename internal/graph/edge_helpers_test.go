package graph

import "testing"

func TestAddEdgeIfMissingAddsEdgeOnce(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "source", Kind: NodeKindWorkload})
	g.AddNode(&Node{ID: "target", Kind: NodeKindObservation})

	edge := &Edge{
		ID:     "source->target:targets",
		Source: "source",
		Target: "target",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	}

	if !AddEdgeIfMissing(g, edge) {
		t.Fatal("expected first AddEdgeIfMissing to add edge")
	}
	if AddEdgeIfMissing(g, edge) {
		t.Fatal("expected duplicate AddEdgeIfMissing to return false")
	}
	if got := len(g.GetOutEdges("source")); got != 1 {
		t.Fatalf("len(outEdges) = %d, want 1", got)
	}
}

func TestAddEdgeIfMissingRequiresEndpoints(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "source", Kind: NodeKindWorkload})

	if AddEdgeIfMissing(g, &Edge{
		ID:     "source->missing:targets",
		Source: "source",
		Target: "missing",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	}) {
		t.Fatal("expected AddEdgeIfMissing to reject missing target")
	}
	if got := len(g.GetOutEdges("source")); got != 0 {
		t.Fatalf("len(outEdges) = %d, want 0", got)
	}
}

func TestMergeEdgePropertiesUpdatesActiveEdgeByID(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "source", Kind: NodeKindWorkload})
	g.AddNode(&Node{ID: "target", Kind: NodeKindObservation})
	g.AddEdge(&Edge{
		ID:         "source->target:targets",
		Source:     "source",
		Target:     "target",
		Kind:       EdgeKindTargets,
		Effect:     EdgeEffectAllow,
		Properties: map[string]any{"existing": "value"},
	})

	if !MergeEdgeProperties(g, "source->target:targets", map[string]any{
		"response_execution_id": "exec-1",
		"response_action_type":  "block_ip",
	}) {
		t.Fatal("expected MergeEdgeProperties to update the edge")
	}

	edges := g.GetOutEdges("source")
	if len(edges) != 1 {
		t.Fatalf("len(outEdges) = %d, want 1", len(edges))
	}
	if got := edges[0].Properties["existing"]; got != "value" {
		t.Fatalf("existing property = %#v, want value", got)
	}
	if got := edges[0].Properties["response_execution_id"]; got != "exec-1" {
		t.Fatalf("response_execution_id = %#v, want exec-1", got)
	}
	if got := edges[0].Properties["response_action_type"]; got != "block_ip" {
		t.Fatalf("response_action_type = %#v, want block_ip", got)
	}
}
