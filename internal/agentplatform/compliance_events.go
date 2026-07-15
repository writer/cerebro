package agentplatform

import "time"

const (
	EventTypeComplianceAssuranceDecisionRecorded  = "compliance.assurance_decision.recorded"
	EventTypeComplianceAssessmentSnapshotRecorded = "compliance.assessment_snapshot.recorded"
	EventTypeComplianceWorkItemUpdated            = "compliance.work_item.updated"
	EventTypeComplianceWorkItemVerified           = "compliance.work_item.verified"
)

// ComplianceEventMetadata is the stable tenant-scoped envelope shared by
// public compliance events. Payloads carry identities and digests, not raw
// evidence or source records.
type ComplianceEventMetadata struct {
	EventID    string    `json:"event_id"`
	TenantID   string    `json:"tenant_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

type AssuranceDecisionRecordedEvent struct {
	ComplianceEventMetadata
	DecisionID        string `json:"decision_id"`
	AssessmentRunID   string `json:"assessment_run_id"`
	ObjectiveResultID string `json:"objective_result_id"`
	Qualified         bool   `json:"qualified"`
	DecisionDigest    string `json:"decision_digest"`
	RecordDigest      string `json:"record_digest"`
}

type AssessmentSnapshotRecordedEvent struct {
	ComplianceEventMetadata
	SnapshotID        string `json:"snapshot_id"`
	AssessmentRunID   string `json:"assessment_run_id"`
	ResultSetDigest   string `json:"result_set_digest"`
	DecisionSetDigest string `json:"decision_set_digest"`
	EvidenceSetDigest string `json:"evidence_set_digest"`
}

type ComplianceWorkItemUpdatedEvent struct {
	ComplianceEventMetadata
	WorkItemID      string `json:"work_item_id"`
	State           string `json:"state"`
	Version         uint64 `json:"version"`
	OccurrenceCount uint64 `json:"occurrence_count"`
}

type ComplianceWorkItemVerifiedEvent struct {
	ComplianceEventMetadata
	WorkItemID          string `json:"work_item_id"`
	AssuranceDecisionID string `json:"assurance_decision_id"`
	AssessmentRunID     string `json:"assessment_run_id"`
	ObjectiveResultID   string `json:"objective_result_id"`
	DecisionDigest      string `json:"decision_digest"`
}
