package entities

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
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
)

func QueryEntities(g *graph.Graph, opts EntityQueryOptions) EntityCollection {
	return graph.QueryEntities(g, opts)
}

func GetEntityRecord(g *graph.Graph, id string, validAt, recordedAt time.Time) (EntityRecord, bool) {
	return graph.GetEntityRecord(g, id, validAt, recordedAt)
}
