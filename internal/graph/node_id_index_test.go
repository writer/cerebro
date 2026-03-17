package graph

import "testing"

func TestNodeIDIndexInternRoundTrip(t *testing.T) {
	idx := NewNodeIDIndex()

	ordinal := idx.Intern("deployment:prod/api")
	if ordinal == InvalidNodeOrdinal {
		t.Fatal("expected non-zero ordinal")
	}

	id, ok := idx.Resolve(ordinal)
	if !ok {
		t.Fatal("expected Resolve to succeed")
	}
	if id != "deployment:prod/api" {
		t.Fatalf("Resolve(%d) = %q, want deployment:prod/api", ordinal, id)
	}
}

func TestNodeIDIndexInternDeduplicatesExistingIDs(t *testing.T) {
	idx := NewNodeIDIndex()

	first := idx.Intern("deployment:prod/api")
	second := idx.Intern("deployment:prod/api")
	if first != second {
		t.Fatalf("Intern returned %d and %d for the same ID", first, second)
	}
	if got := idx.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

func TestNodeIDIndexLookupRejectsBlankAndUnknownIDs(t *testing.T) {
	idx := NewNodeIDIndex()
	idx.Intern("deployment:prod/api")

	if ordinal, ok := idx.Lookup(""); ok || ordinal != InvalidNodeOrdinal {
		t.Fatalf("Lookup(empty) = (%d, %t), want invalid,false", ordinal, ok)
	}
	if ordinal, ok := idx.Lookup("deployment:prod/unknown"); ok || ordinal != InvalidNodeOrdinal {
		t.Fatalf("Lookup(unknown) = (%d, %t), want invalid,false", ordinal, ok)
	}
	if id, ok := idx.Resolve(999); ok || id != "" {
		t.Fatalf("Resolve(999) = (%q, %t), want empty,false", id, ok)
	}
}

func TestNodeIDIndexPreservesExactWhitespaceIDs(t *testing.T) {
	idx := NewNodeIDIndex()

	trimmed := idx.Intern("deployment:prod/api")
	spaced := idx.Intern(" deployment:prod/api ")
	blank := idx.Intern(" ")

	if trimmed == spaced {
		t.Fatalf("expected spaced ID to receive a distinct ordinal, got %d", spaced)
	}
	if blank == InvalidNodeOrdinal {
		t.Fatal("expected exact whitespace ID to remain internable")
	}
	if got, ok := idx.Lookup(" deployment:prod/api "); !ok || got != spaced {
		t.Fatalf("Lookup(spaced) = (%d, %t), want %d,true", got, ok, spaced)
	}
	if got, ok := idx.Resolve(blank); !ok || got != " " {
		t.Fatalf("Resolve(blank) = (%q, %t), want %q,true", got, ok, " ")
	}
}

func TestNodeIDIndexBitmapMatchesInternedCardinality(t *testing.T) {
	idx := NewNodeIDIndex()
	ordinals := []NodeOrdinal{
		idx.Intern("deployment:prod/api"),
		idx.Intern("deployment:prod/worker"),
		idx.Intern("deployment:prod/db"),
	}

	visited := idx.NewBitmap()
	if got, want := len(visited), idx.Len()+1; got != want {
		t.Fatalf("len(NewBitmap()) = %d, want %d", got, want)
	}

	for _, ordinal := range ordinals {
		visited[ordinal] = true
	}
	for _, ordinal := range ordinals {
		if !visited[ordinal] {
			t.Fatalf("visited[%d] = false, want true", ordinal)
		}
	}
}
