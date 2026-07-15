package eventregistry

import "testing"

func TestComplianceAggregateV1EncodesSharedSchema(t *testing.T) {
	t.Parallel()
	event := ComplianceAggregateV1{
		Kind: WorkflowV1CompliancePrefix + "program_recorded", TenantID: "tenant-a",
		AggregateType: "program", AggregateID: "program-1", RevisionID: "revision-1",
		AggregateVersion: 1, Operation: "recorded", ContentDigest: "sha256:abc",
		PayloadJSON: `{"id":"program-1"}`, ActorID: "actor-1", RecordedAt: "2026-07-11T08:00:00Z",
	}
	encoded, err := (Encoder{}).Encode(event, EncodeOptions{EventID: "event-1"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded.Subject != event.Kind || len(encoded.EnvelopeBytes) == 0 {
		t.Fatalf("encoded = %#v", encoded)
	}
}
