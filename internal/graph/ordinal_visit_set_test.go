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
