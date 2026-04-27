package workflowevents

import (
	"testing"
	"time"
)

func TestNewDecisionRecordedEventIsStableAndDecodable(t *testing.T) {
	payload := DecisionRecorded{
		TenantID:      "writer",
		DecisionID:    "urn:cerebro:writer:decision:decision-1",
		DecisionType:  "finding-triage",
		Status:        "approved",
		TargetIDs:     []string{"urn:cerebro:writer:resource:target-1"},
		SourceSystem:  "findings",
		SourceEventID: "finding-1",
		ObservedAt:    "2026-04-27T12:00:00Z",
		ValidFrom:     "2026-04-27T12:00:00Z",
	}
	first, err := NewDecisionRecordedEvent(payload)
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	second, err := NewDecisionRecordedEvent(payload)
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent(second) error = %v", err)
	}
	if first.GetId() != second.GetId() {
		t.Fatalf("event id = %q, want stable %q", first.GetId(), second.GetId())
	}
	if got := first.GetKind(); got != EventKindKnowledgeDecisionRecorded {
		t.Fatalf("event kind = %q, want %q", got, EventKindKnowledgeDecisionRecorded)
	}
	if got := first.GetAttributes()[EventAttributeDecisionID]; got != payload.DecisionID {
		t.Fatalf("decision_id attribute = %q, want %q", got, payload.DecisionID)
	}
	decoded, err := DecodeDecisionRecorded(first)
	if err != nil {
		t.Fatalf("DecodeDecisionRecorded() error = %v", err)
	}
	if got := decoded.DecisionID; got != payload.DecisionID {
		t.Fatalf("decoded decision id = %q, want %q", got, payload.DecisionID)
	}
}

func TestCanonicalWorkflowIDUsesProvidedURN(t *testing.T) {
	urn := "urn:cerebro:writer:decision:decision-1"
	if got := CanonicalWorkflowID("writer", "decision", urn, "decision", nil, time.Time{}); got != urn {
		t.Fatalf("CanonicalWorkflowID() = %q, want %q", got, urn)
	}
}
