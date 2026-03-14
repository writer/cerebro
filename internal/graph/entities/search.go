package entities

import graph "github.com/evalops/cerebro/internal/graph"

type (
	EntitySearchOptions     = graph.EntitySearchOptions
	EntitySearchResult      = graph.EntitySearchResult
	EntitySearchCollection  = graph.EntitySearchCollection
	EntitySuggestOptions    = graph.EntitySuggestOptions
	EntitySuggestCollection = graph.EntitySuggestCollection
	EntitySuggestion        = graph.EntitySuggestion
)

func SearchEntities(g *graph.Graph, opts EntitySearchOptions) EntitySearchCollection {
	return graph.SearchEntities(g, opts)
}

func SuggestEntities(g *graph.Graph, opts EntitySuggestOptions) EntitySuggestCollection {
	return graph.SuggestEntities(g, opts)
}
