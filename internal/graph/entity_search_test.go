package graph

import "testing"

func TestSearchAndSuggestEntities(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:       "arn:aws:s3:::audit-logs",
		Kind:     NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Region:   "us-east-1",
	})
	g.AddNode(&Node{
		ID:       "person:alice@example.com",
		Kind:     NodeKindPerson,
		Name:     "Alice Example",
		Provider: "workspace",
	})
	g.BuildIndex()

	results := SearchEntities(g, EntitySearchOptions{Query: "s3 bucket", Limit: 5})
	if results.Count < 1 {
		t.Fatalf("expected search results, got %#v", results)
	}
	if results.Results[0].Entity.ID != "arn:aws:s3:::audit-logs" {
		t.Fatalf("expected bucket search hit, got %#v", results.Results[0].Entity.ID)
	}

	suggestions := SuggestEntities(g, EntitySuggestOptions{Prefix: "ali", Limit: 5})
	if suggestions.Count < 1 {
		t.Fatalf("expected suggestions, got %#v", suggestions)
	}
	if suggestions.Suggestions[0].EntityID != "person:alice@example.com" {
		t.Fatalf("expected alice suggestion, got %#v", suggestions.Suggestions[0])
	}
}

func TestEntitySearchTrigrams_UsesRunes(t *testing.T) {
	got := entitySearchTrigrams("über")
	want := []string{"übe", "ber"}
	if len(got) != len(want) {
		t.Fatalf("trigram count = %d, want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trigram[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSuggestEntities_UsesRunePrefixes(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "document:uber-ops",
		Kind: NodeKindDocument,
		Name: "Über Ops",
	})
	g.BuildIndex()

	suggestions := SuggestEntities(g, EntitySuggestOptions{Prefix: "üb", Limit: 5})
	if suggestions.Count != 1 {
		t.Fatalf("expected one unicode suggestion, got %#v", suggestions)
	}
	if suggestions.Suggestions[0].EntityID != "document:uber-ops" {
		t.Fatalf("expected unicode suggestion hit, got %#v", suggestions.Suggestions[0])
	}
}

func TestSearchEntities_UsesRuneLengthForShortQueries(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "document:uber-ops",
		Kind: NodeKindDocument,
		Name: "Über Ops",
	})
	g.BuildIndex()

	results := SearchEntities(g, EntitySearchOptions{Query: "üb", Limit: 5})
	if results.Count != 1 {
		t.Fatalf("expected one unicode search result, got %#v", results)
	}
	if results.Results[0].Entity.ID != "document:uber-ops" {
		t.Fatalf("expected unicode search hit, got %#v", results.Results[0].Entity.ID)
	}
}
