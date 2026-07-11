package workflowevents

import (
	"strings"
	"testing"
)

func TestComplianceAggregateRoundTrip(t *testing.T) {
	t.Parallel()
	payload := ComplianceAggregateRecorded{
		Kind: EventKindComplianceProgramRecorded, TenantID: "tenant-a",
		AggregateType: "program", AggregateID: "program-1", RevisionID: "revision-1",
		AggregateVersion: 2, Operation: "recorded",
		ContentDigest: "sha256:abc", PayloadJSON: `{"id":"program-1"}`,
		ActorID: "actor-1", RecordedAt: "2026-07-11T08:00:00.123Z",
	}
	event, err := NewComplianceAggregateEvent(payload)
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent() error = %v", err)
	}
	decoded, err := DecodeComplianceAggregate(event)
	if err != nil {
		t.Fatalf("DecodeComplianceAggregate() error = %v", err)
	}
	if decoded.Kind != payload.Kind || decoded.TenantID != payload.TenantID || decoded.AggregateID != payload.AggregateID || decoded.AggregateVersion != payload.AggregateVersion || decoded.PayloadJSON != payload.PayloadJSON {
		t.Fatalf("round trip = %#v, want %#v", decoded, payload)
	}
	if event.GetAttributes()["aggregate_id"] != payload.AggregateID {
		t.Fatalf("aggregate_id attribute = %q", event.GetAttributes()["aggregate_id"])
	}
}

func TestComplianceAggregateKindsRegistered(t *testing.T) {
	t.Parallel()
	for _, kind := range registeredComplianceKinds() {
		if !KindRegistered(kind) {
			t.Fatalf("kind %q is not registered", kind)
		}
		if got := SchemaForKind(kind); got != SchemaComplianceAggregate {
			t.Fatalf("schema for %q = %q", kind, got)
		}
	}
}

func TestComplianceExchangeRequestAndCommitRemainDistinctFacts(t *testing.T) {
	t.Parallel()
	if EventKindComplianceExchangeCommitRequested == EventKindComplianceExchangeCommitted {
		t.Fatal("exchange commit request and completed commit share an event kind")
	}
	for _, kind := range []string{EventKindComplianceExchangeCommitRequested, EventKindComplianceExchangeCommitted} {
		if !KindRegistered(kind) {
			t.Fatalf("kind %q is not registered", kind)
		}
	}
}

func TestComplianceAggregateRejectsUnsafePayload(t *testing.T) {
	t.Parallel()
	base := ComplianceAggregateRecorded{
		Kind: EventKindComplianceProgramRecorded, TenantID: "tenant-a",
		AggregateType: "program", AggregateID: "program-1", AggregateVersion: 1,
		Operation: "recorded", RecordedAt: "2026-07-11T08:00:00Z",
	}
	invalid := base
	invalid.PayloadJSON = "{"
	if _, err := NewComplianceAggregateEvent(invalid); err == nil {
		t.Fatal("invalid JSON payload unexpectedly accepted")
	}
	large := base
	large.PayloadJSON = `"` + strings.Repeat("x", maxCompliancePayloadBytes) + `"`
	if _, err := NewComplianceAggregateEvent(large); err == nil {
		t.Fatal("oversized payload unexpectedly accepted")
	}
	unknown := base
	unknown.Kind = "workflow.v1.compliance.unknown"
	if _, err := NewComplianceAggregateEvent(unknown); err == nil {
		t.Fatal("unregistered kind unexpectedly accepted")
	}
}
