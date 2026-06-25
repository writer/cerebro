package fabriccontract

import (
	"sort"
	"strings"
)

const (
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

var relationSet = map[string]struct{}{
	RelationActedOn:            {},
	RelationAffectedBy:         {},
	RelationAffects:            {},
	RelationAssignedTo:         {},
	RelationAssociatedWith:     {},
	RelationAttachedTo:         {},
	RelationAuthored:           {},
	RelationBelongsTo:          {},
	RelationCanAdmin:           {},
	RelationCanAssume:          {},
	RelationCanImpersonate:     {},
	RelationCanPerform:         {},
	RelationCanReach:           {},
	RelationCNAMETo:            {},
	RelationConfersCapability:  {},
	RelationContains:           {},
	RelationDependsOn:          {},
	RelationGrantsEntitlement:  {},
	RelationHasClassification:  {},
	RelationHasDNSRecord:       {},
	RelationHasEvidence:        {},
	RelationHasFinding:         {},
	RelationHasIdentifier:      {},
	RelationMemberOf:           {},
	RelationObservedOn:         {},
	RelationOwnedBy:            {},
	RelationRepresents:         {},
	RelationRepresentsIdentity: {},
	RelationResolvesTo:         {},
	RelationRunsAs:             {},
	RelationSameActor:          {},
	RelationSupports:           {},
	RelationTaggedAs:           {},
	RelationTargeted:           {},
}

func IsRelation(value string) bool {
	_, ok := relationSet[strings.TrimSpace(value)]
	return ok
}

func Relations() []string {
	relations := make([]string, 0, len(relationSet))
	for relation := range relationSet {
		relations = append(relations, relation)
	}
	sort.Strings(relations)
	return relations
}
