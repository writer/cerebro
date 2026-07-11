package workflowevents

import (
	"encoding/json"
	"fmt"
	"strings"

	eventregistry "github.com/WriterInternal/event-registry/clients/go"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	EventKindComplianceProgramRecorded             = "workflow.v1.compliance.program_recorded"
	EventKindComplianceProgramScopeRecorded        = "workflow.v1.compliance.program_scope_recorded"
	EventKindComplianceImplementationRecorded      = "workflow.v1.compliance.control_implementation_recorded"
	EventKindComplianceEvidenceVersionRecorded     = "workflow.v1.compliance.evidence_artifact_version_recorded"
	EventKindComplianceEvidenceClaimRecorded       = "workflow.v1.compliance.evidence_claim_recorded"
	EventKindComplianceEvidenceClaimReviewed       = "workflow.v1.compliance.evidence_claim_reviewed"
	EventKindComplianceEvidenceClaimInvalidated    = "workflow.v1.compliance.evidence_claim_invalidated"
	EventKindCompliancePlanRevisionRecorded        = "workflow.v1.compliance.assessment_plan_revision_recorded"
	EventKindCompliancePlanPublished               = "workflow.v1.compliance.assessment_plan_published"
	EventKindComplianceAssessmentRequested         = "workflow.v1.compliance.assessment_requested"
	EventKindComplianceAssessmentJobBound          = "workflow.v1.compliance.assessment_job_bound"
	EventKindComplianceInputManifestRecorded       = "workflow.v1.compliance.assessment_input_manifest_recorded"
	EventKindComplianceResultChunkRecorded         = "workflow.v1.compliance.assessment_result_chunk_recorded"
	EventKindComplianceAssessmentCompleted         = "workflow.v1.compliance.assessment_completed"
	EventKindComplianceAssessmentCancelled         = "workflow.v1.compliance.assessment_cancelled"
	EventKindComplianceActivityRecorded            = "workflow.v1.compliance.assessment_activity_recorded"
	EventKindCompliancePopulationRecorded          = "workflow.v1.compliance.assessment_population_recorded"
	EventKindComplianceSampleRecorded              = "workflow.v1.compliance.assessment_sample_recorded"
	EventKindComplianceReviewRecorded              = "workflow.v1.compliance.assessment_review_recorded"
	EventKindComplianceRiskDecisionRecorded        = "workflow.v1.compliance.risk_decision_recorded"
	EventKindComplianceExceptionUpdated            = "workflow.v1.compliance.exception_updated"
	EventKindComplianceWorkItemUpdated             = "workflow.v1.compliance.work_item_updated"
	EventKindComplianceRemediationMilestoneUpdated = "workflow.v1.compliance.remediation_milestone_updated"
	EventKindComplianceAuditEngagementRecorded     = "workflow.v1.compliance.audit_engagement_recorded"
	EventKindComplianceAuditRequestUpdated         = "workflow.v1.compliance.audit_request_updated"
	EventKindComplianceAuditSubmissionRecorded     = "workflow.v1.compliance.audit_submission_recorded"
	EventKindComplianceAuditPackageRecorded        = "workflow.v1.compliance.audit_package_recorded"
	EventKindComplianceAuditDeliveryRecorded       = "workflow.v1.compliance.audit_delivery_recorded"
	EventKindComplianceExchangeStaged              = "workflow.v1.compliance.exchange_staged"
	EventKindComplianceExchangeCommitted           = "workflow.v1.compliance.exchange_committed"
	EventKindComplianceMonitorUpdated              = "workflow.v1.compliance.monitor_updated"
	EventKindComplianceMonitorTriggered            = "workflow.v1.compliance.monitor_triggered"

	SchemaComplianceAggregate = "urn:cerebro:events/workflow.compliance.aggregate/v1"
	maxCompliancePayloadBytes = 512 * 1024
)

// ComplianceAggregateRecorded is the shared append-first envelope for bounded,
// canonical compliance revisions and transitions. PayloadJSON contains no raw
// evidence bytes and is validated by the owning domain before append.
type ComplianceAggregateRecorded struct {
	Kind             string `json:"kind"`
	TenantID         string `json:"tenant_id"`
	AggregateType    string `json:"aggregate_type"`
	AggregateID      string `json:"aggregate_id"`
	RevisionID       string `json:"revision_id,omitempty"`
	AggregateVersion int64  `json:"aggregate_version"`
	Operation        string `json:"operation"`
	ContentDigest    string `json:"content_digest,omitempty"`
	PayloadJSON      string `json:"payload_json,omitempty"`
	ActorID          string `json:"actor_id,omitempty"`
	RecordedAt       string `json:"recorded_at"`
}

func NewComplianceAggregateEvent(payload ComplianceAggregateRecorded) (*cerebrov1.EventEnvelope, error) {
	payload.Kind = strings.TrimSpace(payload.Kind)
	if !strings.HasPrefix(payload.Kind, eventregistry.WorkflowV1CompliancePrefix) || !KindRegistered(payload.Kind) {
		return nil, fmt.Errorf("compliance event kind %q is not registered", payload.Kind)
	}
	if strings.TrimSpace(payload.AggregateType) == "" || strings.TrimSpace(payload.AggregateID) == "" {
		return nil, fmt.Errorf("compliance event aggregate type and id are required")
	}
	if payload.AggregateVersion < 1 {
		return nil, fmt.Errorf("compliance event aggregate version must be positive")
	}
	if strings.TrimSpace(payload.Operation) == "" {
		return nil, fmt.Errorf("compliance event operation is required")
	}
	if len(payload.PayloadJSON) > maxCompliancePayloadBytes {
		return nil, fmt.Errorf("compliance event payload exceeds %d bytes", maxCompliancePayloadBytes)
	}
	if strings.TrimSpace(payload.PayloadJSON) != "" && !json.Valid([]byte(payload.PayloadJSON)) {
		return nil, fmt.Errorf("compliance event payload_json is invalid")
	}
	contract := eventregistry.ComplianceAggregateV1{
		Kind: payload.Kind, TenantID: payload.TenantID, AggregateType: payload.AggregateType,
		AggregateID: payload.AggregateID, RevisionID: payload.RevisionID,
		AggregateVersion: payload.AggregateVersion, Operation: payload.Operation,
		ContentDigest: payload.ContentDigest, PayloadJSON: payload.PayloadJSON,
		ActorID: payload.ActorID, RecordedAt: payload.RecordedAt,
	}
	primaryID := payload.AggregateID + "|" + fmt.Sprintf("%d", payload.AggregateVersion) + "|" + payload.Operation
	return newEvent(contract, SchemaComplianceAggregate, payload.TenantID, "compliance", primaryID, payload.RecordedAt, map[string]string{
		EventAttributeWorkflowKind: "compliance_aggregate",
		"aggregate_type":           payload.AggregateType,
		"aggregate_id":             payload.AggregateID,
		"revision_id":              payload.RevisionID,
	})
}

func DecodeComplianceAggregate(event *cerebrov1.EventEnvelope) (*ComplianceAggregateRecorded, error) {
	payload := &ComplianceAggregateRecorded{Kind: strings.TrimSpace(event.GetKind())}
	if !strings.HasPrefix(payload.Kind, eventregistry.WorkflowV1CompliancePrefix) || !KindRegistered(payload.Kind) {
		return nil, fmt.Errorf("workflow event kind = %q is not a registered compliance kind", payload.Kind)
	}
	if err := decodePayload(event, payload.Kind, payload); err != nil {
		return nil, err
	}
	payload.Kind = strings.TrimSpace(event.GetKind())
	return payload, nil
}

func registeredComplianceKinds() []string {
	return []string{
		EventKindComplianceProgramRecorded, EventKindComplianceProgramScopeRecorded,
		EventKindComplianceImplementationRecorded, EventKindComplianceEvidenceVersionRecorded,
		EventKindComplianceEvidenceClaimRecorded, EventKindComplianceEvidenceClaimReviewed,
		EventKindComplianceEvidenceClaimInvalidated, EventKindCompliancePlanRevisionRecorded,
		EventKindCompliancePlanPublished, EventKindComplianceAssessmentRequested,
		EventKindComplianceAssessmentJobBound, EventKindComplianceInputManifestRecorded,
		EventKindComplianceResultChunkRecorded, EventKindComplianceAssessmentCompleted,
		EventKindComplianceAssessmentCancelled, EventKindComplianceActivityRecorded,
		EventKindCompliancePopulationRecorded, EventKindComplianceSampleRecorded,
		EventKindComplianceReviewRecorded, EventKindComplianceRiskDecisionRecorded,
		EventKindComplianceExceptionUpdated, EventKindComplianceWorkItemUpdated,
		EventKindComplianceRemediationMilestoneUpdated, EventKindComplianceAuditEngagementRecorded,
		EventKindComplianceAuditRequestUpdated, EventKindComplianceAuditSubmissionRecorded,
		EventKindComplianceAuditPackageRecorded, EventKindComplianceAuditDeliveryRecorded,
		EventKindComplianceExchangeStaged, EventKindComplianceExchangeCommitted,
		EventKindComplianceMonitorUpdated, EventKindComplianceMonitorTriggered,
	}
}
