package agentplatform

import (
	"encoding/json"
	"testing"
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
