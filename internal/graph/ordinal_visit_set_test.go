package graph

import "testing"

func TestOrdinalVisitSetTracksInvalidOrdinalsByNodeID(t *testing.T) {
	visited := newOrdinalVisitSet(nil)

	if visited.hasNode("role:a", InvalidNodeOrdinal) {
		t.Fatal("expected role:a to be unvisited")
	}
	if !visited.markNode("role:a", InvalidNodeOrdinal) {
		t.Fatal("expected first mark for role:a to succeed")
	}
	if !visited.hasNode("role:a", InvalidNodeOrdinal) {
		t.Fatal("expected role:a to be marked visited")
	}
	if visited.markNode("role:a", InvalidNodeOrdinal) {
		t.Fatal("expected second mark for role:a to report already visited")
	}
	if visited.hasNode("role:b", InvalidNodeOrdinal) {
		t.Fatal("expected role:b to remain unvisited")
	}
	if !visited.markNode("role:b", InvalidNodeOrdinal) {
		t.Fatal("expected first mark for role:b to succeed")
	}
	if !visited.hasNode("role:b", InvalidNodeOrdinal) {
		t.Fatal("expected role:b to be marked visited")
	}
}

func TestOrdinalVisitSetSeparatesGraphAndLocalOrdinals(t *testing.T) {
	visited := newOrdinalVisitSet(nil)

	if !visited.markNode("role:graph", NodeOrdinal(1)) {
		t.Fatal("expected first graph-ordinal mark to succeed")
	}
	if visited.hasNode("role:local", InvalidNodeOrdinal) {
		t.Fatal("expected local node to remain unvisited after graph-ordinal mark")
	}
	if !visited.markNode("role:local", InvalidNodeOrdinal) {
		t.Fatal("expected first local mark to succeed")
	}
	if visited.hasNode("role:other", NodeOrdinal(2)) {
		t.Fatal("expected unrelated graph ordinal to remain unvisited after local mark")
	}
	if !visited.markNode("role:other", NodeOrdinal(2)) {
		t.Fatal("expected first mark for second graph ordinal to succeed")
	}
	if visited.markNode("role:local", InvalidNodeOrdinal) {
		t.Fatal("expected second local mark to report already visited")
	}
}

func TestOrdinalVisitSetCloneCopiesLocalNodeIDsIndependently(t *testing.T) {
	visited := newOrdinalVisitSet(nil)
	if !visited.markNode("role:a", InvalidNodeOrdinal) {
		t.Fatal("expected first local mark to succeed")
	}

	cloned := visited.clone()

	if !visited.markNode("role:original-only", InvalidNodeOrdinal) {
		t.Fatal("expected original clone branch to track new local node")
	}
	if cloned.hasNode("role:original-only", InvalidNodeOrdinal) {
		t.Fatal("expected cloned visit set to remain independent from original")
	}

	if !cloned.markNode("role:clone-only", InvalidNodeOrdinal) {
		t.Fatal("expected cloned visit set to track its own local node")
	}
	if visited.hasNode("role:clone-only", InvalidNodeOrdinal) {
		t.Fatal("expected original visit set to remain independent from clone")
	}
}
