package entities

import (
	"time"

	graph "github.com/evalops/cerebro/internal/graph"
)

type (
	EntityQueryOptions            = graph.EntityQueryOptions
	EntityQueryFilters            = graph.EntityQueryFilters
	EntityTemporalMetadata        = graph.EntityTemporalMetadata
	EntityLinkSummary             = graph.EntityLinkSummary
	EntityRelationshipSummary     = graph.EntityRelationshipSummary
	EntityClaimPredicateSummary   = graph.EntityClaimPredicateSummary
	EntityKnowledgeSupportSummary = graph.EntityKnowledgeSupportSummary
	EntityRecord                  = graph.EntityRecord
	EntityCollectionSummary       = graph.EntityCollectionSummary
	EntityCollection              = graph.EntityCollection
	EntityCanonicalRef            = graph.EntityCanonicalRef
	EntityExternalRef             = graph.EntityExternalRef
	EntityAliasRecord             = graph.EntityAliasRecord
	EntityFacetFieldDefinition    = graph.EntityFacetFieldDefinition
	EntityFacetDefinition         = graph.EntityFacetDefinition
	EntityFacetRecord             = graph.EntityFacetRecord
	EntityPostureClaimRecord      = graph.EntityPostureClaimRecord
	EntityPostureSummary          = graph.EntityPostureSummary
	EntitySubresourceRecord       = graph.EntitySubresourceRecord
	EntitySearchOptions           = graph.EntitySearchOptions
	EntitySearchResult            = graph.EntitySearchResult
	EntitySearchCollection        = graph.EntitySearchCollection
	EntitySuggestOptions          = graph.EntitySuggestOptions
	EntitySuggestCollection       = graph.EntitySuggestCollection
	EntitySuggestion              = graph.EntitySuggestion
)

func QueryEntities(g *graph.Graph, opts EntityQueryOptions) EntityCollection {
	return graph.QueryEntities(g, opts)
}

func GetEntityRecord(g *graph.Graph, id string, validAt, recordedAt time.Time) (EntityRecord, bool) {
	return graph.GetEntityRecord(g, id, validAt, recordedAt)
}

func SearchEntities(g *graph.Graph, opts EntitySearchOptions) EntitySearchCollection {
	return graph.SearchEntities(g, opts)
}

func SuggestEntities(g *graph.Graph, opts EntitySuggestOptions) EntitySuggestCollection {
	return graph.SuggestEntities(g, opts)
}
