package agentplatform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestComplianceEventPayloadsCarryReferencesWithoutRawEvidence(t *testing.T) {
	payload, err := json.Marshal(AssuranceDecisionRecordedEvent{
		ComplianceEventMetadata: ComplianceEventMetadata{EventID: "event-1", TenantID: "tenant-1"},
		DecisionID:              "decision-1", AssessmentRunID: "run-1", ObjectiveResultID: "result-1",
		Qualified: true, DecisionDigest: "decision-digest", RecordDigest: "record-digest",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, required := range []string{"event_id", "tenant_id", "decision_id", "assessment_run_id", "objective_result_id", "qualified", "decision_digest", "record_digest", "occurred_at"} {
		if _, ok := fields[required]; !ok {
			t.Fatalf("typed payload missing %q: %s", required, payload)
		}
	}
	for _, forbidden := range []string{"evidence", "evidence_records", "source_records", "credentials"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("typed payload exposes %q: %s", forbidden, payload)
		}
	}
}

func TestBuildTypedComplianceEventProjectsCanonicalEvents(t *testing.T) {
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	decision := complianceassessment.AssuranceDecision{
		ID: "decision-1", TenantID: "tenant-1", RunID: "run-1", ResultID: "result-1", RecordDigest: "record-digest",
		Decision:      complianceassessment.QualifiedDecision{Qualified: true, DecisionDigest: "decision-digest"},
		InputSnapshot: complianceassessment.QualificationInput{EvidenceProofs: []complianceassessment.EvidenceProof{{EvidenceID: "private-evidence-ref"}}},
	}
	typed, err := BuildTypedComplianceEvent(testComplianceEnvelope(t, workflowevents.EventKindComplianceAssuranceDecisionRecorded, "assurance_decision_recorded", now, decision))
	if err != nil {
		t.Fatalf("BuildTypedComplianceEvent(decision) error = %v", err)
	}
	projected := typed.Payload.(AssuranceDecisionRecordedEvent)
	if typed.Type != EventTypeComplianceAssuranceDecisionRecorded || projected.DecisionID != decision.ID || projected.DecisionDigest != decision.Decision.DecisionDigest {
		t.Fatalf("typed decision event = %+v", typed)
	}
	encoded, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || jsonContainsString(encoded, "private-evidence-ref") {
		t.Fatalf("typed event leaked evidence proof: %s", encoded)
	}

	work := complianceassessment.WorkItem{
		ID: "work-1", State: complianceassessment.WorkResolved, Version: 4,
		Occurrences: []complianceassessment.WorkOccurrence{{AssessmentRunID: "run-1"}},
		Verification: &complianceassessment.WorkVerification{
			AssuranceDecisionID: "decision-1", AssessmentRunID: "run-2", ObjectiveResultID: "result-2", DecisionDigest: "decision-digest-2",
		},
	}
	typed, err = BuildTypedComplianceEvent(testComplianceEnvelope(t, workflowevents.EventKindComplianceWorkItemUpdated, string(complianceassessment.WorkActionVerifyAssurance), now, map[string]any{"item": work}))
	if err != nil {
		t.Fatalf("BuildTypedComplianceEvent(work verification) error = %v", err)
	}
	verified := typed.Payload.(ComplianceWorkItemVerifiedEvent)
	if typed.Type != EventTypeComplianceWorkItemVerified || verified.WorkItemID != work.ID || verified.AssuranceDecisionID != "decision-1" {
		t.Fatalf("typed verified work event = %+v", typed)
	}

	work.Verification = nil
	typed, err = BuildTypedComplianceEvent(testComplianceEnvelope(t, workflowevents.EventKindComplianceWorkItemUpdated, "failed_result_recorded", now, map[string]any{"item": work}))
	if err != nil {
		t.Fatalf("BuildTypedComplianceEvent(work update) error = %v", err)
	}
	updated := typed.Payload.(ComplianceWorkItemUpdatedEvent)
	if typed.Type != EventTypeComplianceWorkItemUpdated || updated.OccurrenceCount != 1 || updated.Version != work.Version {
		t.Fatalf("typed work update event = %+v", typed)
	}
}

func testComplianceEnvelope(t *testing.T, kind, operation string, at time.Time, payload any) *cerebrov1.EventEnvelope {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: "tenant-1", AggregateType: "test", AggregateID: "aggregate-1", AggregateVersion: 1,
		Operation: operation, PayloadJSON: string(body), RecordedAt: at.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func jsonContainsString(body []byte, value string) bool {
	return strings.Contains(string(body), value)
}
