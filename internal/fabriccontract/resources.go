package fabriccontract

import (
	"sort"
	"strings"
)

// ResourceKind identifies one canonical resource family in the reference fabric.
type ResourceKind string

const (
	ResourceKindFinding             ResourceKind = "finding"
	ResourceKindFindingEvidence     ResourceKind = "finding_evidence"
	ResourceKindEvaluationRun       ResourceKind = "evaluation_run"
	ResourceKindSourceEvent         ResourceKind = "source_event"
	ResourceKindSourceRuntime       ResourceKind = "source_runtime"
	ResourceKindGraphEntity         ResourceKind = "graph_entity"
	ResourceKindGraphFact           ResourceKind = "graph_fact"
	ResourceKindGraphPath           ResourceKind = "graph_path"
	ResourceKindRule                ResourceKind = "rule"
	ResourceKindControl             ResourceKind = "control"
	ResourceKindEvidencePacket      ResourceKind = "evidence_packet"
	ResourceKindAuditPacket         ResourceKind = "audit_packet"
	ResourceKindDecisionPacket      ResourceKind = "decision_packet"
	ResourceKindReportRun           ResourceKind = "report_run"
	ResourceKindJob                 ResourceKind = "job"
	ResourceKindAgentTask           ResourceKind = "agent_task"
	ResourceKindAskQuery            ResourceKind = "ask_query"
	ResourceKindDashboardLens       ResourceKind = "dashboard_lens"
	ResourceKindQuestionnaireRun    ResourceKind = "questionnaire_run"
	ResourceKindExternalWork        ResourceKind = "external_work"
	ResourceKindActionProposal      ResourceKind = "action_proposal"
	ResourceKindApprovalReceipt     ResourceKind = "approval_receipt"
	ResourceKindActionExecution     ResourceKind = "action_execution"
	ResourceKindVerification        ResourceKind = "verification"
	ResourceKindWorkflowOutcome     ResourceKind = "workflow_outcome"
	ResourceKindFindingEpisode      ResourceKind = "finding_episode"
	ResourceKindRemediationCampaign ResourceKind = "remediation_campaign"
)

// ResourceOwner identifies the domain that owns a resource's canonical record.
// Resolvers may project or enrich these records, but they must not replace the owner.
type ResourceOwner string

const (
	ResourceOwnerFindings           ResourceOwner = "findings"
	ResourceOwnerFindingEvaluations ResourceOwner = "finding_evaluations"
	ResourceOwnerSourceRuntime      ResourceOwner = "source_runtime"
	ResourceOwnerGraphProjection    ResourceOwner = "graph_projection"
	ResourceOwnerRuleCatalog        ResourceOwner = "rule_catalog"
	ResourceOwnerControlCatalog     ResourceOwner = "control_catalog"
	ResourceOwnerEvidencePackets    ResourceOwner = "evidence_packets"
	ResourceOwnerReports            ResourceOwner = "reports"
	ResourceOwnerJobs               ResourceOwner = "jobs"
	ResourceOwnerAgentPlatform      ResourceOwner = "agent_platform"
	ResourceOwnerAsk                ResourceOwner = "ask"
	ResourceOwnerDashboards         ResourceOwner = "dashboards"
	ResourceOwnerQuestionnaires     ResourceOwner = "questionnaires"
	ResourceOwnerExternalWork       ResourceOwner = "external_work"
	ResourceOwnerActionWorkflow     ResourceOwner = "action_workflow"
	ResourceOwnerFindingOutcomes    ResourceOwner = "finding_outcomes"
)

// ResourceIdentifierKind states which canonical identifier a resource kind uses.
type ResourceIdentifierKind string

const (
	ResourceIdentifierID  ResourceIdentifierKind = "id"
	ResourceIdentifierURN ResourceIdentifierKind = "urn"
)

// ResourceKindDefinition binds a public kind to its canonical owner and identifier.
type ResourceKindDefinition struct {
	Kind       ResourceKind
	Owner      ResourceOwner
	Identifier ResourceIdentifierKind
}

var resourceKindRegistry = map[ResourceKind]ResourceKindDefinition{
	ResourceKindFinding:             resourceKindDefinition(ResourceKindFinding, ResourceOwnerFindings, ResourceIdentifierID),
	ResourceKindFindingEvidence:     resourceKindDefinition(ResourceKindFindingEvidence, ResourceOwnerFindings, ResourceIdentifierID),
	ResourceKindEvaluationRun:       resourceKindDefinition(ResourceKindEvaluationRun, ResourceOwnerFindingEvaluations, ResourceIdentifierID),
	ResourceKindSourceEvent:         resourceKindDefinition(ResourceKindSourceEvent, ResourceOwnerSourceRuntime, ResourceIdentifierID),
	ResourceKindSourceRuntime:       resourceKindDefinition(ResourceKindSourceRuntime, ResourceOwnerSourceRuntime, ResourceIdentifierID),
	ResourceKindGraphEntity:         resourceKindDefinition(ResourceKindGraphEntity, ResourceOwnerGraphProjection, ResourceIdentifierURN),
	ResourceKindGraphFact:           resourceKindDefinition(ResourceKindGraphFact, ResourceOwnerGraphProjection, ResourceIdentifierID),
	ResourceKindGraphPath:           resourceKindDefinition(ResourceKindGraphPath, ResourceOwnerGraphProjection, ResourceIdentifierID),
	ResourceKindRule:                resourceKindDefinition(ResourceKindRule, ResourceOwnerRuleCatalog, ResourceIdentifierID),
	ResourceKindControl:             resourceKindDefinition(ResourceKindControl, ResourceOwnerControlCatalog, ResourceIdentifierID),
	ResourceKindEvidencePacket:      resourceKindDefinition(ResourceKindEvidencePacket, ResourceOwnerEvidencePackets, ResourceIdentifierID),
	ResourceKindAuditPacket:         resourceKindDefinition(ResourceKindAuditPacket, ResourceOwnerEvidencePackets, ResourceIdentifierID),
	ResourceKindDecisionPacket:      resourceKindDefinition(ResourceKindDecisionPacket, ResourceOwnerEvidencePackets, ResourceIdentifierID),
	ResourceKindReportRun:           resourceKindDefinition(ResourceKindReportRun, ResourceOwnerReports, ResourceIdentifierID),
	ResourceKindJob:                 resourceKindDefinition(ResourceKindJob, ResourceOwnerJobs, ResourceIdentifierID),
	ResourceKindAgentTask:           resourceKindDefinition(ResourceKindAgentTask, ResourceOwnerAgentPlatform, ResourceIdentifierID),
	ResourceKindAskQuery:            resourceKindDefinition(ResourceKindAskQuery, ResourceOwnerAsk, ResourceIdentifierID),
	ResourceKindDashboardLens:       resourceKindDefinition(ResourceKindDashboardLens, ResourceOwnerDashboards, ResourceIdentifierID),
	ResourceKindQuestionnaireRun:    resourceKindDefinition(ResourceKindQuestionnaireRun, ResourceOwnerQuestionnaires, ResourceIdentifierID),
	ResourceKindExternalWork:        resourceKindDefinition(ResourceKindExternalWork, ResourceOwnerExternalWork, ResourceIdentifierID),
	ResourceKindActionProposal:      resourceKindDefinition(ResourceKindActionProposal, ResourceOwnerActionWorkflow, ResourceIdentifierID),
	ResourceKindApprovalReceipt:     resourceKindDefinition(ResourceKindApprovalReceipt, ResourceOwnerActionWorkflow, ResourceIdentifierID),
	ResourceKindActionExecution:     resourceKindDefinition(ResourceKindActionExecution, ResourceOwnerActionWorkflow, ResourceIdentifierID),
	ResourceKindVerification:        resourceKindDefinition(ResourceKindVerification, ResourceOwnerActionWorkflow, ResourceIdentifierID),
	ResourceKindWorkflowOutcome:     resourceKindDefinition(ResourceKindWorkflowOutcome, ResourceOwnerActionWorkflow, ResourceIdentifierID),
	ResourceKindFindingEpisode:      resourceKindDefinition(ResourceKindFindingEpisode, ResourceOwnerFindingOutcomes, ResourceIdentifierID),
	ResourceKindRemediationCampaign: resourceKindDefinition(ResourceKindRemediationCampaign, ResourceOwnerFindingOutcomes, ResourceIdentifierID),
}

func resourceKindDefinition(kind ResourceKind, owner ResourceOwner, identifier ResourceIdentifierKind) ResourceKindDefinition {
	return ResourceKindDefinition{Kind: kind, Owner: owner, Identifier: identifier}
}

// ResourceKindDefinitionFor returns the canonical definition for value.
func ResourceKindDefinitionFor(value string) (ResourceKindDefinition, bool) {
	kind := ResourceKind(strings.TrimSpace(value))
	definition, ok := resourceKindRegistry[kind]
	return definition, ok
}

// IsResourceKind reports whether value names a registered resource kind.
func IsResourceKind(value string) bool {
	_, ok := ResourceKindDefinitionFor(value)
	return ok
}

// ResourceKindDefinitions returns a stable snapshot sorted by kind.
func ResourceKindDefinitions() []ResourceKindDefinition {
	definitions := make([]ResourceKindDefinition, 0, len(resourceKindRegistry))
	for _, definition := range resourceKindRegistry {
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].Kind < definitions[j].Kind
	})
	return definitions
}

// ResourceKinds returns the registered kind names in stable order.
func ResourceKinds() []ResourceKind {
	definitions := ResourceKindDefinitions()
	kinds := make([]ResourceKind, 0, len(definitions))
	for _, definition := range definitions {
		kinds = append(kinds, definition.Kind)
	}
	return kinds
}
