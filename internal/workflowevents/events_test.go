package workflowevents

import (
	"bytes"
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
	if !IsSharedEnvelopeEvent(first) {
		t.Fatalf("workflow event payload is not marked as shared Avro envelope: %#v", first.GetAttributes())
	}
	if bytes.HasPrefix(bytes.TrimSpace(first.GetPayload()), []byte("{")) {
		t.Fatal("workflow event payload is JSON, want shared Avro envelope")
	}
	if got := first.GetAttributes()["event_type"]; got != EventKindKnowledgeDecisionRecorded {
		t.Fatalf("event_type attribute = %q, want %q", got, EventKindKnowledgeDecisionRecorded)
	}
	decoded, err := DecodeDecisionRecorded(first)
	if err != nil {
		t.Fatalf("DecodeDecisionRecorded() error = %v", err)
	}
	if got := decoded.DecisionID; got != payload.DecisionID {
		t.Fatalf("decoded decision id = %q, want %q", got, payload.DecisionID)
	}
}

func TestNewDecisionRecordedEventEncodesNestedMetadata(t *testing.T) {
	payload := DecisionRecorded{
		TenantID:     "writer",
		DecisionID:   "urn:cerebro:writer:decision:decision-1",
		DecisionType: "finding-triage",
		Status:       "approved",
		TargetIDs:    []string{"urn:cerebro:writer:resource:target-1"},
		SourceSystem: "findings",
		ObservedAt:   "2026-04-27T12:00:00Z",
		ValidFrom:    "2026-04-27T12:00:00Z",
		Metadata: map[string]any{
			"context": map[string]any{
				"nested": true,
				"owners": []any{"sec", "eng"},
			},
		},
	}
	event, err := NewDecisionRecordedEvent(payload)
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	decoded, err := DecodeDecisionRecorded(event)
	if err != nil {
		t.Fatalf("DecodeDecisionRecorded() error = %v", err)
	}
	if got := decoded.Metadata["context"]; got != `{"nested":true,"owners":["sec","eng"]}` {
		t.Fatalf("decoded nested metadata = %#v", got)
	}
}

func TestCanonicalWorkflowIDUsesProvidedURN(t *testing.T) {
	urn := "urn:cerebro:writer:decision:decision-1"
	if got := CanonicalWorkflowID("writer", "decision", urn, "decision", nil, time.Time{}); got != urn {
		t.Fatalf("CanonicalWorkflowID() = %q, want %q", got, urn)
	}
}
