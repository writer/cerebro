package eventregistry

import (
	"strings"
	"testing"
	"time"
)

func TestEncoderEncodeGeneratesEventID(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.EventID == "" {
		t.Fatal("Encode() should generate an EventID when not provided")
	}
	if len(encoded.EventID) != 36 {
		t.Fatalf("generated EventID length = %d, want 36 (UUID format)", len(encoded.EventID))
	}
}

func TestEncoderEncodeUsesProvidedEventID(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{EventID: "custom-id-123"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.EventID != "custom-id-123" {
		t.Fatalf("EventID = %q, want %q", encoded.EventID, "custom-id-123")
	}
}

func TestEncoderEncodeUsesProvidedEmittedAt(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	ts := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	encoded, err := Encoder{}.Encode(event, EncodeOptions{EmittedAt: ts})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.EmittedAtMS != ts.UnixMilli() {
		t.Fatalf("EmittedAtMS = %d, want %d", encoded.EmittedAtMS, ts.UnixMilli())
	}
}

func TestEncoderEncodeSetsSubjectAndVersion(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{EventID: "eid"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.Subject != WorkflowV1KnowledgeDecisionRecorded {
		t.Fatalf("Subject = %q, want %q", encoded.Subject, WorkflowV1KnowledgeDecisionRecorded)
	}
	if encoded.Version != 1 {
		t.Fatalf("Version = %d, want 1", encoded.Version)
	}
}

func TestEncoderEncodeSetsAttributes(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{EventID: "eid"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.Attributes["event_type"] != WorkflowV1KnowledgeDecisionRecorded {
		t.Fatalf("Attributes[event_type] = %q, want %q", encoded.Attributes["event_type"], WorkflowV1KnowledgeDecisionRecorded)
	}
	if encoded.Attributes["event_id"] != "eid" {
		t.Fatalf("Attributes[event_id] = %q, want %q", encoded.Attributes["event_id"], "eid")
	}
	if encoded.Attributes["envelope_version"] != "1" {
		t.Fatalf("Attributes[envelope_version] = %q, want %q", encoded.Attributes["envelope_version"], "1")
	}
	if encoded.Attributes["schema_fingerprint"] != workflowV1DecisionFingerprint {
		t.Fatalf("Attributes[schema_fingerprint] = %q, want %q", encoded.Attributes["schema_fingerprint"], workflowV1DecisionFingerprint)
	}
}

func TestEncoderEncodeCustomAttributesDoNotOverrideReserved(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "accept",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{
		EventID:    "eid",
		Attributes: map[string]string{"event_type": "attacker", "custom": "value"},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.Attributes["event_type"] != WorkflowV1KnowledgeDecisionRecorded {
		t.Fatalf("reserved attribute was overridden: event_type = %q", encoded.Attributes["event_type"])
	}
	if encoded.Attributes["custom"] != "value" {
		t.Fatalf("custom attribute missing: Attributes[custom] = %q", encoded.Attributes["custom"])
	}
}

func TestEncoderEncodeProducesNonEmptyEnvelope(t *testing.T) {
	event := ActionRecordedV1{
		TenantID:     "tenant-1",
		ActionID:     "action-1",
		ActionType:   "suspend",
		Status:       "executed",
		Title:        "Suspend user",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	encoded, err := Encoder{}.Encode(event, EncodeOptions{EventID: "eid"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if len(encoded.EnvelopeBytes) == 0 {
		t.Fatal("EnvelopeBytes should not be empty")
	}
}

func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Fatalf("nilIfEmpty(\"\") = %v, want nil", got)
	}
	if got := nilIfEmpty("x"); got == nil || *got != "x" {
		t.Fatalf("nilIfEmpty(\"x\") = %v, want ptr to \"x\"", got)
	}
}

func TestUuidV4Format(t *testing.T) {
	id, err := uuidV4()
	if err != nil {
		t.Fatalf("uuidV4() error = %v", err)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("uuid parts = %d, want 5", len(parts))
	}
	// Version nibble should be 4
	if parts[2][0] != '4' {
		t.Fatalf("uuid version = %c, want '4'", parts[2][0])
	}
}

func TestUuidV4Uniqueness(t *testing.T) {
	id1, _ := uuidV4()
	id2, _ := uuidV4()
	if id1 == id2 {
		t.Fatalf("two uuidV4 calls returned same value: %q", id1)
	}
}
