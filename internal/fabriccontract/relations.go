package fabriccontract

import (
	"sort"
	"strings"
)

const (
	RelationSelf               = "self"
	RelationActedOn            = "acted_on"
	RelationAffectedBy         = "affected_by"
	RelationAffects            = "affects"
	RelationAssignedTo         = "assigned_to"
	RelationAssociatedWith     = "associated_with"
	RelationAttachedTo         = "attached_to"
	RelationAuthored           = "authored"
	RelationBelongsTo          = "belongs_to"
	RelationCanAdmin           = "can_admin"
	RelationCanAssume          = "can_assume"
	RelationCanImpersonate     = "can_impersonate"
	RelationCanPerform         = "can_perform"
	RelationCanReach           = "can_reach"
	RelationCNAMETo            = "cname_to"
	RelationConfersCapability  = "confers_capability"
	RelationContains           = "contains"
	RelationDependsOn          = "depends_on"
	RelationGrantsEntitlement  = "grants_entitlement"
	RelationHasClassification  = "has_classification"
	RelationHasContext         = "has_context"
	RelationHasDNSRecord       = "has_dns_record"
	RelationHasEvidence        = "has_evidence"
	RelationHasFinding         = "has_finding"
	RelationHasIdentifier      = "has_identifier"
	RelationMemberOf           = "member_of"
	RelationObservedOn         = "observed_on"
	RelationOwnedBy            = "owned_by"
	RelationRepresents         = "represents"
	RelationRepresentsIdentity = "represents_identity"
	RelationResolvesTo         = "resolves_to"
	RelationRunsAs             = "runs_as"
	RelationSameActor          = "same_actor"
	RelationSupports           = "supports"
	RelationTaggedAs           = "tagged_as"
	RelationTargeted           = "targeted"
)

// RelationClass distinguishes current structural links from durable historical
// citations. Historical links must be backed by a canonical record rather than
// inferred from the graph projection.
type RelationClass string

const (
	RelationClassStructural RelationClass = "structural"
	RelationClassHistorical RelationClass = "historical"
	RelationClassCitation   RelationClass = "citation"
)

// RelationDefinition records the stable semantics for one relation. Empty
// endpoint-kind lists mean the legacy graph relation is not yet constrained by
// the resource-reference layer.
type RelationDefinition struct {
	Name          string
	Inverse       string
	Class         RelationClass
	SourceKinds   []string
	TargetKinds   []string
	DefaultExpand bool
}

var relationDefinitions = buildRelationDefinitions()

func buildRelationDefinitions() map[string]RelationDefinition {
	names := []string{
		RelationSelf,
		RelationActedOn,
		RelationAffectedBy,
		RelationAffects,
		RelationAssignedTo,
		RelationAssociatedWith,
		RelationAttachedTo,
		RelationAuthored,
		RelationBelongsTo,
		RelationCanAdmin,
		RelationCanAssume,
		RelationCanImpersonate,
		RelationCanPerform,
		RelationCanReach,
		RelationCNAMETo,
		RelationConfersCapability,
		RelationContains,
		RelationDependsOn,
		RelationGrantsEntitlement,
		RelationHasClassification,
		RelationHasContext,
		RelationHasDNSRecord,
		RelationHasEvidence,
		RelationHasFinding,
		RelationHasIdentifier,
		RelationMemberOf,
		RelationObservedOn,
		RelationOwnedBy,
		RelationRepresents,
		RelationRepresentsIdentity,
		RelationResolvesTo,
		RelationRunsAs,
		RelationSameActor,
		RelationSupports,
		RelationTaggedAs,
		RelationTargeted,
	}
	definitions := make(map[string]RelationDefinition, len(names))
	for _, name := range names {
		definitions[name] = RelationDefinition{Name: name, Class: RelationClassStructural}
	}
	definitions[RelationSelf] = RelationDefinition{
		Name:          RelationSelf,
		Class:         RelationClassStructural,
		SourceKinds:   []string{"finding"},
		TargetKinds:   []string{"finding"},
		DefaultExpand: true,
	}
	definitions[RelationHasContext] = RelationDefinition{
		Name:          RelationHasContext,
		Class:         RelationClassStructural,
		SourceKinds:   []string{"finding"},
		TargetKinds:   []string{"finding_investigation"},
		DefaultExpand: true,
	}
	definitions[RelationHasEvidence] = RelationDefinition{
		Name:          RelationHasEvidence,
		Class:         RelationClassStructural,
		SourceKinds:   []string{"finding"},
		TargetKinds:   []string{"finding_evidence_collection"},
		DefaultExpand: true,
	}
	definitions[RelationObservedOn] = RelationDefinition{
		Name:          RelationObservedOn,
		Class:         RelationClassStructural,
		SourceKinds:   []string{"finding"},
		TargetKinds:   []string{"source_runtime"},
		DefaultExpand: true,
	}
	definitions[RelationAffects] = RelationDefinition{
		Name:          RelationAffects,
		Class:         RelationClassStructural,
		SourceKinds:   []string{"finding"},
		TargetKinds:   []string{"graph_entity"},
		DefaultExpand: false,
	}
	return definitions
}

func IsRelation(value string) bool {
	_, ok := relationDefinitions[strings.TrimSpace(value)]
	return ok
}

func Relations() []string {
	relations := make([]string, 0, len(relationDefinitions))
	for relation := range relationDefinitions {
		relations = append(relations, relation)
	}
	sort.Strings(relations)
	return relations
}

// LookupRelation returns a copy of the registered relation definition.
func LookupRelation(value string) (RelationDefinition, bool) {
	definition, ok := relationDefinitions[strings.TrimSpace(value)]
	if !ok {
		return RelationDefinition{}, false
	}
	definition.SourceKinds = append([]string(nil), definition.SourceKinds...)
	definition.TargetKinds = append([]string(nil), definition.TargetKinds...)
	return definition, true
}

// RelationDefinitions returns the registry in stable name order.
func RelationDefinitions() []RelationDefinition {
	names := Relations()
	definitions := make([]RelationDefinition, 0, len(names))
	for _, name := range names {
		definition, _ := LookupRelation(name)
		definitions = append(definitions, definition)
	}
	return definitions
}
