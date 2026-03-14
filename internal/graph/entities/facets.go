package entities

import graph "github.com/evalops/cerebro/internal/graph"

type (
	EntityFacetFieldDefinition = graph.EntityFacetFieldDefinition
	EntityFacetDefinition      = graph.EntityFacetDefinition
	EntityFacetRecord          = graph.EntityFacetRecord
	EntityPostureClaimRecord   = graph.EntityPostureClaimRecord
	EntityPostureSummary       = graph.EntityPostureSummary
)

func GetEntityFacetDefinition(id string) (EntityFacetDefinition, bool) {
	return graph.GetEntityFacetDefinition(id)
}

func DefaultEntityFacetDefinitions() []EntityFacetDefinition {
	return graph.ListEntityFacetDefinitions()
}

func EntityFacetAppliesToNode(def EntityFacetDefinition, kind graph.NodeKind) bool {
	if len(def.ApplicableKinds) == 0 {
		return true
	}
	for _, candidate := range def.ApplicableKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}
