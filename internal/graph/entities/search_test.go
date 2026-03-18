package entities

import (
	"testing"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestSearchAndSuggestEntities(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::audit-logs",
		Kind:     graph.NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Region:   "us-east-1",
	})
	g.AddNode(&graph.Node{
		ID:       "person:alice@example.com",
		Kind:     graph.NodeKindPerson,
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

func TestSuggestEntitiesUsesRunePrefixes(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "document:uber-ops",
		Kind: graph.NodeKindDocument,
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

func TestSearchEntitiesUsesRuneLengthForShortQueries(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "document:uber-ops",
		Kind: graph.NodeKindDocument,
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
