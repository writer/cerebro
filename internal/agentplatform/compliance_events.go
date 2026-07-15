package agentplatform

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	EventTypeComplianceAssuranceDecisionRecorded  = "compliance.assurance_decision.recorded"
	EventTypeComplianceAssessmentSnapshotRecorded = "compliance.assessment_snapshot.recorded"
	EventTypeComplianceWorkItemUpdated            = "compliance.work_item.updated"
	EventTypeComplianceWorkItemVerified           = "compliance.work_item.verified"
)

var ErrUnsupportedComplianceEvent = errors.New("unsupported public compliance event")

type TypedComplianceEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

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

// BuildTypedComplianceEvent projects canonical append-log events into the
// public event contract. It copies identifiers, states, and digests only.
func BuildTypedComplianceEvent(event *cerebrov1.EventEnvelope) (TypedComplianceEvent, error) {
	aggregate, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return TypedComplianceEvent{}, err
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, aggregate.RecordedAt)
	if err != nil {
		return TypedComplianceEvent{}, fmt.Errorf("public compliance event recorded_at: %w", err)
	}
	metadata := ComplianceEventMetadata{EventID: strings.TrimSpace(event.GetId()), TenantID: strings.TrimSpace(aggregate.TenantID), OccurredAt: recordedAt.UTC()}
	if metadata.EventID == "" || metadata.TenantID == "" {
		return TypedComplianceEvent{}, fmt.Errorf("public compliance event identity is incomplete")
	}
	switch aggregate.Kind {
	case workflowevents.EventKindComplianceAssuranceDecisionRecorded:
		var decision complianceassessment.AssuranceDecision
		if err := json.Unmarshal([]byte(aggregate.PayloadJSON), &decision); err != nil {
			return TypedComplianceEvent{}, fmt.Errorf("decode assurance decision event: %w", err)
		}
		return TypedComplianceEvent{Type: EventTypeComplianceAssuranceDecisionRecorded, Payload: AssuranceDecisionRecordedEvent{
			ComplianceEventMetadata: metadata, DecisionID: decision.ID, AssessmentRunID: decision.RunID,
			ObjectiveResultID: decision.ResultID, Qualified: decision.Decision.Qualified,
			DecisionDigest: decision.Decision.DecisionDigest, RecordDigest: decision.RecordDigest,
		}}, nil
	case workflowevents.EventKindComplianceAssessmentSnapshotRecorded:
		var snapshot complianceassessment.AssessmentSnapshot
		if err := json.Unmarshal([]byte(aggregate.PayloadJSON), &snapshot); err != nil {
			return TypedComplianceEvent{}, fmt.Errorf("decode assessment snapshot event: %w", err)
		}
		return TypedComplianceEvent{Type: EventTypeComplianceAssessmentSnapshotRecorded, Payload: AssessmentSnapshotRecordedEvent{
			ComplianceEventMetadata: metadata, SnapshotID: snapshot.ID, AssessmentRunID: snapshot.RunID,
			ResultSetDigest: snapshot.ResultSetHash, DecisionSetDigest: snapshot.DecisionSetDigest, EvidenceSetDigest: snapshot.EvidenceSetDigest,
		}}, nil
	case workflowevents.EventKindComplianceWorkItemUpdated:
		var payload struct {
			Item complianceassessment.WorkItem `json:"item"`
		}
		if err := json.Unmarshal([]byte(aggregate.PayloadJSON), &payload); err != nil {
			return TypedComplianceEvent{}, fmt.Errorf("decode compliance work event: %w", err)
		}
		if aggregate.Operation == string(complianceassessment.WorkActionVerifyAssurance) && payload.Item.Verification != nil {
			verification := payload.Item.Verification
			return TypedComplianceEvent{Type: EventTypeComplianceWorkItemVerified, Payload: ComplianceWorkItemVerifiedEvent{
				ComplianceEventMetadata: metadata, WorkItemID: payload.Item.ID,
				AssuranceDecisionID: verification.AssuranceDecisionID, AssessmentRunID: verification.AssessmentRunID,
				ObjectiveResultID: verification.ObjectiveResultID, DecisionDigest: verification.DecisionDigest,
			}}, nil
		}
		return TypedComplianceEvent{Type: EventTypeComplianceWorkItemUpdated, Payload: ComplianceWorkItemUpdatedEvent{
			ComplianceEventMetadata: metadata, WorkItemID: payload.Item.ID, State: string(payload.Item.State),
			Version: payload.Item.Version, OccurrenceCount: uint64(len(payload.Item.Occurrences)),
		}}, nil
	default:
		return TypedComplianceEvent{}, fmt.Errorf("%w: %s", ErrUnsupportedComplianceEvent, aggregate.Kind)
	}
}
