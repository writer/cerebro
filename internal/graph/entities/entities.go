package entities

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

type (
	EntityQueryOptions             = graph.EntityQueryOptions
	EntityQueryFilters             = graph.EntityQueryFilters
	EntityTemporalMetadata         = graph.EntityTemporalMetadata
	EntityLinkSummary              = graph.EntityLinkSummary
	EntityRelationshipSummary      = graph.EntityRelationshipSummary
	EntityClaimPredicateSummary    = graph.EntityClaimPredicateSummary
	EntityKnowledgeSupportSummary  = graph.EntityKnowledgeSupportSummary
	EntityRecord                   = graph.EntityRecord
	EntityCollectionSummary        = graph.EntityCollectionSummary
	EntityCollection               = graph.EntityCollection
	EntityCanonicalRef             = graph.EntityCanonicalRef
	EntityExternalRef              = graph.EntityExternalRef
	EntityAliasRecord              = graph.EntityAliasRecord
	EntityFacetFieldDefinition     = graph.EntityFacetFieldDefinition
	EntityFacetDefinition          = graph.EntityFacetDefinition
	EntityFacetRecord              = graph.EntityFacetRecord
	EntityPostureClaimRecord       = graph.EntityPostureClaimRecord
	EntityPostureSummary           = graph.EntityPostureSummary
	EntitySubresourceRecord        = graph.EntitySubresourceRecord
	EntitySearchOptions            = graph.EntitySearchOptions
	EntitySearchResult             = graph.EntitySearchResult
	EntitySearchCollection         = graph.EntitySearchCollection
	EntitySuggestOptions           = graph.EntitySuggestOptions
	EntitySuggestCollection        = graph.EntitySuggestCollection
	EntitySuggestion               = graph.EntitySuggestion
	EntityTimeReconstruction       = graph.EntityTimeReconstruction
	EntityTimeRecord               = graph.EntityTimeRecord
	EntityPropertyDiff             = graph.EntityPropertyDiff
	EntityTimeDiffRecord           = graph.EntityTimeDiffRecord
	EntityFacetContractCatalog     = graph.EntityFacetContractCatalog
	EntityFacetCompatibilityReport = graph.EntityFacetCompatibilityReport
)

func QueryEntities(g *graph.Graph, opts EntityQueryOptions) EntityCollection {
	return graph.QueryEntities(g, opts)
}

func GetEntityRecord(g *graph.Graph, id string, validAt, recordedAt time.Time) (EntityRecord, bool) {
	return graph.GetEntityRecord(g, id, validAt, recordedAt)
}

func GetEntityRecordAtTime(g *graph.Graph, id string, asOf, recordedAt time.Time) (EntityTimeRecord, bool) {
	return graph.GetEntityRecordAtTime(g, id, asOf, recordedAt)
}

func GetEntityTimeDiff(g *graph.Graph, id string, from, to, recordedAt time.Time) (EntityTimeDiffRecord, bool) {
	return graph.GetEntityTimeDiff(g, id, from, to, recordedAt)
}

func SearchEntities(g *graph.Graph, opts EntitySearchOptions) EntitySearchCollection {
	return graph.SearchEntities(g, opts)
}

func SuggestEntities(g *graph.Graph, opts EntitySuggestOptions) EntitySuggestCollection {
	return graph.SuggestEntities(g, opts)
}

func BuildEntityFacetContractCatalog(now time.Time) EntityFacetContractCatalog {
	return graph.BuildEntityFacetContractCatalog(now)
}

func GetEntityFacetDefinition(id string) (EntityFacetDefinition, bool) {
	return graph.GetEntityFacetDefinition(id)
}

func DefaultEntityFacetDefinitions() []EntityFacetDefinition {
	return graph.DefaultEntityFacetDefinitions()
}

func EntityFacetAppliesToNode(def EntityFacetDefinition, kind graph.NodeKind) bool {
	return graph.EntityFacetAppliesToNode(def, kind)
}

func CompareEntityFacetContractCatalogs(baseline, current EntityFacetContractCatalog, now time.Time) EntityFacetCompatibilityReport {
	return graph.CompareEntityFacetContractCatalogs(baseline, current, now)
}
