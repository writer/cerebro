package fabriccontract

import (
	"sort"
	"strings"
)

const (
	RelationActedOn            = "acted_on"
	RelationAffectedBy         = "affected_by"
	RelationAffects            = "affects"
	RelationAnnotatedWith      = "annotated_with"
	RelationApprovedBy         = "approved_by"
	RelationApproves           = "approves"
	RelationAssignedTo         = "assigned_to"
	RelationAssociatedWith     = "associated_with"
	RelationAttachedTo         = "attached_to"
	RelationAuthored           = "authored"
	RelationBasedOn            = "based_on"
	RelationBelongsTo          = "belongs_to"
	RelationCanAdmin           = "can_admin"
	RelationCanAssume          = "can_assume"
	RelationCanImpersonate     = "can_impersonate"
	RelationCanPerform         = "can_perform"
	RelationCanReach           = "can_reach"
	RelationCitedBy            = "cited_by"
	RelationCites              = "cites"
	RelationClosed             = "closed"
	RelationClosedBy           = "closed_by"
	RelationCNAMETo            = "cname_to"
	RelationConfersCapability  = "confers_capability"
	RelationContains           = "contains"
	RelationDependsOn          = "depends_on"
	RelationEvaluates          = "evaluates"
	RelationEvidenceFor        = "evidence_for"
	RelationExecutedAs         = "executed_as"
	RelationExecutedBy         = "executed_by"
	RelationExecutionOf        = "execution_of"
	RelationFindingOn          = "finding_on"
	RelationGrantsEntitlement  = "grants_entitlement"
	RelationHasCandidate       = "has_candidate"
	RelationHasClassification  = "has_classification"
	RelationHasContext         = "has_context"
	RelationHasDNSRecord       = "has_dns_record"
	RelationHasEvidence        = "has_evidence"
	RelationHasFinding         = "has_finding"
	RelationHasIdentifier      = "has_identifier"
	RelationMappedToControl    = "mapped_to_control"
	RelationMemberOf           = "member_of"
	RelationObserved           = "observed"
	RelationObservedOn         = "observed_on"
	RelationOwnedBy            = "owned_by"
	RelationPlannedIn          = "planned_in"
	RelationProduced           = "produced"
	RelationProducedByRun      = "produced_by_run"
	RelationProposedAs         = "proposed_as"
	RelationProposedFor        = "proposed_for"
	RelationProviderRecord     = "provider_record"
	RelationRecurredAs         = "recurred_as"
	RelationRecurrenceOf       = "recurrence_of"
	RelationRepresents         = "represents"
	RelationRepresentsIdentity = "represents_identity"
	RelationResolvesTo         = "resolves_to"
	RelationRunsAs             = "runs_as"
	RelationSameActor          = "same_actor"
	RelationSelf               = "self"
	RelationSupersededBy       = "superseded_by"
	RelationSupersedes         = "supersedes"
	RelationSupports           = "supports"
	RelationTaggedAs           = "tagged_as"
	RelationTargeted           = "targeted"
	RelationTargets            = "targets"
	RelationTestedBy           = "tested_by"
	RelationTrackedBy          = "tracked_by"
	RelationTracks             = "tracks"
	RelationVerifiedBy         = "verified_by"
	RelationVerifies           = "verifies"
)

// RelationClass identifies the durability and authority rules for a relation.
type RelationClass string

const (
	RelationClassStructural         RelationClass = "structural"
	RelationClassProjectedContext   RelationClass = "projected_context"
	RelationClassHistoricalCitation RelationClass = "historical_citation"
	RelationClassWorkflowTransition RelationClass = "workflow_transition"
	RelationClassExternalLocator    RelationClass = "external_locator"
	RelationClassDerivedAnalytic    RelationClass = "derived_analytic"
)

// RelationDirection states the default direction presented by a resolver.
type RelationDirection string

const (
	RelationDirectionOutgoing      RelationDirection = "outgoing"
	RelationDirectionIncoming      RelationDirection = "incoming"
	RelationDirectionBidirectional RelationDirection = "bidirectional"
)

// RelationDefinition records traversal and provenance rules for one relation.
// Empty kind lists mean any registered resource kind; callers still authorize
// both endpoints independently.
type RelationDefinition struct {
	Name             string
	Inverse          string
	SourceKinds      []ResourceKind
	TargetKinds      []ResourceKind
	Class            RelationClass
	DefaultDirection RelationDirection
	SafeToTraverse   bool
	RequiresEvidence bool
	RequiresValidity bool
	IncludeByDefault bool
}

var relationRegistry = buildRelationRegistry()

func buildRelationRegistry() map[string]RelationDefinition {
	registry := make(map[string]RelationDefinition)
	projected := []string{
		RelationActedOn, RelationAffectedBy, RelationAffects, RelationAssignedTo,
		RelationAssociatedWith, RelationAttachedTo, RelationAuthored, RelationBelongsTo,
		RelationCanAdmin, RelationCanAssume, RelationCanImpersonate, RelationCanPerform,
		RelationCanReach, RelationCNAMETo, RelationConfersCapability, RelationContains,
		RelationDependsOn, RelationGrantsEntitlement, RelationHasClassification,
		RelationHasContext, RelationHasDNSRecord, RelationHasIdentifier, RelationMemberOf,
		RelationOwnedBy, RelationRepresents, RelationRepresentsIdentity, RelationResolvesTo,
		RelationRunsAs, RelationSameActor, RelationSupports, RelationTaggedAs, RelationTargeted,
	}
	for _, name := range projected {
		registry[name] = RelationDefinition{
			Name: name, SourceKinds: []ResourceKind{ResourceKindGraphEntity}, TargetKinds: []ResourceKind{ResourceKindGraphEntity},
			Class: RelationClassProjectedContext, DefaultDirection: RelationDirectionOutgoing, RequiresEvidence: true,
		}
	}

	// The finding read adds typed navigation without replacing the existing graph
	// projection meanings for these relations.
	registry[RelationHasContext] = RelationDefinition{
		Name: RelationHasContext, SourceKinds: []ResourceKind{ResourceKindGraphEntity, ResourceKindFinding}, TargetKinds: []ResourceKind{ResourceKindGraphEntity, ResourceKindFindingInvestigation},
		Class: RelationClassProjectedContext, DefaultDirection: RelationDirectionOutgoing, RequiresEvidence: true,
	}
	registry[RelationAffects] = RelationDefinition{
		Name: RelationAffects, SourceKinds: []ResourceKind{ResourceKindGraphEntity, ResourceKindFinding}, TargetKinds: []ResourceKind{ResourceKindGraphEntity},
		Class: RelationClassProjectedContext, DefaultDirection: RelationDirectionOutgoing, RequiresEvidence: true,
	}

	addRelationPair(registry, RelationHasEvidence, RelationEvidenceFor, RelationClassStructural, []ResourceKind{ResourceKindFinding, ResourceKindControl, ResourceKindEvidencePacket, ResourceKindAuditPacket, ResourceKindDecisionPacket, ResourceKindGraphEntity}, []ResourceKind{ResourceKindFindingEvidence, ResourceKindFindingEvidenceCollection, ResourceKindSourceEvent, ResourceKindEvidencePacket, ResourceKindGraphEntity}, true, true, false)
	addRelationPair(registry, RelationHasFinding, RelationFindingOn, RelationClassStructural, []ResourceKind{ResourceKindGraphEntity, ResourceKindControl, ResourceKindSourceRuntime}, []ResourceKind{ResourceKindFinding, ResourceKindGraphEntity}, true, true, false)
	addRelationPair(registry, RelationObservedOn, RelationObserved, RelationClassStructural, []ResourceKind{ResourceKindFinding, ResourceKindFindingEvidence, ResourceKindSourceEvent, ResourceKindGraphEntity}, []ResourceKind{ResourceKindSourceRuntime, ResourceKindGraphEntity}, true, true, false)
	addRelationPair(registry, RelationProducedByRun, RelationProduced, RelationClassStructural, nil, []ResourceKind{ResourceKindEvaluationRun, ResourceKindReportRun, ResourceKindJob, ResourceKindQuestionnaireRun}, true, true, false)
	addRelationPair(registry, RelationMappedToControl, RelationTestedBy, RelationClassStructural, []ResourceKind{ResourceKindFinding, ResourceKindRule}, []ResourceKind{ResourceKindControl}, true, false, false)
	addRelationPair(registry, RelationPlannedIn, RelationHasCandidate, RelationClassStructural, []ResourceKind{ResourceKindFinding}, []ResourceKind{ResourceKindDecisionPacket}, true, false, false)
	addRelationPair(registry, RelationProposedAs, RelationProposedFor, RelationClassWorkflowTransition, []ResourceKind{ResourceKindFinding, ResourceKindDecisionPacket}, []ResourceKind{ResourceKindActionProposal}, false, true, true)
	addRelationPair(registry, RelationApprovedBy, RelationApproves, RelationClassWorkflowTransition, []ResourceKind{ResourceKindActionProposal}, []ResourceKind{ResourceKindApprovalReceipt}, false, true, true)
	addRelationPair(registry, RelationExecutedAs, RelationExecutionOf, RelationClassWorkflowTransition, []ResourceKind{ResourceKindActionProposal}, []ResourceKind{ResourceKindActionExecution}, false, true, true)
	addRelationPair(registry, RelationVerifiedBy, RelationVerifies, RelationClassWorkflowTransition, []ResourceKind{ResourceKindActionExecution}, []ResourceKind{ResourceKindVerification}, false, true, true)
	addRelationPair(registry, RelationClosedBy, RelationClosed, RelationClassWorkflowTransition, []ResourceKind{ResourceKindFinding}, []ResourceKind{ResourceKindVerification, ResourceKindWorkflowOutcome}, false, true, true)
	addRelationPair(registry, RelationRecurredAs, RelationRecurrenceOf, RelationClassDerivedAnalytic, []ResourceKind{ResourceKindFindingEpisode}, []ResourceKind{ResourceKindFindingEpisode}, false, true, true)
	addRelationPair(registry, RelationSupersedes, RelationSupersededBy, RelationClassHistoricalCitation, nil, nil, false, true, true)
	addRelationPair(registry, RelationCites, RelationCitedBy, RelationClassHistoricalCitation, []ResourceKind{ResourceKindAuditPacket, ResourceKindDecisionPacket, ResourceKindEvidencePacket, ResourceKindReportRun}, nil, false, true, true)
	addRelationPair(registry, RelationTrackedBy, RelationTracks, RelationClassExternalLocator, nil, []ResourceKind{ResourceKindExternalWork, ResourceKindGraphEntity}, false, true, false)

	registry[RelationSelf] = RelationDefinition{Name: RelationSelf, Inverse: RelationSelf, Class: RelationClassStructural, DefaultDirection: RelationDirectionBidirectional, SafeToTraverse: true, IncludeByDefault: true}
	registry[RelationProviderRecord] = RelationDefinition{Name: RelationProviderRecord, Class: RelationClassExternalLocator, DefaultDirection: RelationDirectionOutgoing, RequiresEvidence: true}
	registry[RelationTargets] = workflowRelation(RelationTargets)
	registry[RelationBasedOn] = workflowRelation(RelationBasedOn)
	registry[RelationExecutedBy] = workflowRelation(RelationExecutedBy)
	registry[RelationEvaluates] = workflowRelation(RelationEvaluates)
	registry[RelationAnnotatedWith] = workflowRelation(RelationAnnotatedWith)
	return registry
}

func workflowRelation(name string) RelationDefinition {
	return RelationDefinition{
		Name: name, SourceKinds: []ResourceKind{ResourceKindGraphEntity}, TargetKinds: []ResourceKind{ResourceKindGraphEntity},
		Class: RelationClassWorkflowTransition, DefaultDirection: RelationDirectionOutgoing, RequiresEvidence: true, RequiresValidity: true,
	}
}

func addRelationPair(registry map[string]RelationDefinition, forward string, inverse string, class RelationClass, sources []ResourceKind, targets []ResourceKind, safe bool, evidence bool, validity bool) {
	registry[forward] = RelationDefinition{
		Name: forward, Inverse: inverse, SourceKinds: append([]ResourceKind(nil), sources...), TargetKinds: append([]ResourceKind(nil), targets...),
		Class: class, DefaultDirection: RelationDirectionOutgoing, SafeToTraverse: safe, RequiresEvidence: evidence, RequiresValidity: validity,
	}
	registry[inverse] = RelationDefinition{
		Name: inverse, Inverse: forward, SourceKinds: append([]ResourceKind(nil), targets...), TargetKinds: append([]ResourceKind(nil), sources...),
		Class: class, DefaultDirection: RelationDirectionIncoming, SafeToTraverse: safe, RequiresEvidence: evidence, RequiresValidity: validity,
	}
}

// IsRelation reports whether value names a registered relation.
func IsRelation(value string) bool {
	_, ok := relationRegistry[strings.TrimSpace(value)]
	return ok
}

// RelationDefinitionFor returns a copy of the registered definition.
func RelationDefinitionFor(value string) (RelationDefinition, bool) {
	definition, ok := relationRegistry[strings.TrimSpace(value)]
	if !ok {
		return RelationDefinition{}, false
	}
	definition.SourceKinds = append([]ResourceKind(nil), definition.SourceKinds...)
	definition.TargetKinds = append([]ResourceKind(nil), definition.TargetKinds...)
	return definition, true
}

// RelationDefinitions returns stable, independently mutable registry snapshots.
func RelationDefinitions() []RelationDefinition {
	definitions := make([]RelationDefinition, 0, len(relationRegistry))
	for name := range relationRegistry {
		definition, _ := RelationDefinitionFor(name)
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Name < definitions[j].Name })
	return definitions
}

// Relations returns relation names in stable order.
func Relations() []string {
	definitions := RelationDefinitions()
	relations := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		relations = append(relations, definition.Name)
	}
	return relations
}

// Allows reports whether this definition accepts the source and target kinds.
func (definition RelationDefinition) Allows(source ResourceKind, target ResourceKind) bool {
	return relationAllowsKind(definition.SourceKinds, source) && relationAllowsKind(definition.TargetKinds, target)
}

func relationAllowsKind(allowed []ResourceKind, value ResourceKind) bool {
	if _, ok := ResourceKindDefinitionFor(string(value)); !ok {
		return false
	}
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}
