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
