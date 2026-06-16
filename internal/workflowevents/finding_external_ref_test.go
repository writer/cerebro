package workflowevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestEventKindFindingExternalRefLinkedRegistered(t *testing.T) {
	const want = "workflow.v1.finding.external_ref_linked"
	if got := EventKindFindingExternalRefLinked; got != want {
		t.Fatalf("EventKindFindingExternalRefLinked = %q, want %q", got, want)
	}
	if got := SchemaFindingExternalRefLinked; got != "urn:cerebro:events/workflow.finding.external_ref_linked/v1" {
		t.Fatalf("SchemaFindingExternalRefLinked = %q, want external ref schema", got)
	}
	if !KindRegistered(EventKindFindingExternalRefLinked) {
		t.Fatalf("KindRegistered(%q) = false, want true", EventKindFindingExternalRefLinked)
	}
	if got := SchemaForKind(EventKindFindingExternalRefLinked); got != SchemaFindingExternalRefLinked {
		t.Fatalf("SchemaForKind(%q) = %q, want %q", EventKindFindingExternalRefLinked, got, SchemaFindingExternalRefLinked)
	}
}

func TestFindingExternalRefLinked_RoundTrip(t *testing.T) {
	payload := newCanonicalFindingExternalRefLinked()
	event, err := NewFindingExternalRefLinkedEvent(payload)
	if err != nil {
		t.Fatalf("NewFindingExternalRefLinkedEvent() error = %v", err)
	}
	if got := event.GetKind(); got != EventKindFindingExternalRefLinked {
		t.Fatalf("event kind = %q, want %q", got, EventKindFindingExternalRefLinked)
	}
	if got := event.GetSchemaRef(); got != SchemaFindingExternalRefLinked {
		t.Fatalf("event schema = %q, want %q", got, SchemaFindingExternalRefLinked)
	}
	if got := event.GetAttributes()[EventAttributeFindingID]; got != payload.Finding.FindingID {
		t.Fatalf("finding_id attribute = %q, want %q", got, payload.Finding.FindingID)
	}
	decoded, err := DecodeFindingExternalRefLinked(event)
	if err != nil {
		t.Fatalf("DecodeFindingExternalRefLinked() error = %v", err)
	}
	if !reflect.DeepEqual(*decoded, payload) {
		t.Fatalf("decoded payload mismatch:\n got=%+v\nwant=%+v", *decoded, payload)
	}
}

func TestNewFindingExternalRefLinkedEvent_UsesSharedEnvelope(t *testing.T) {
	payload := newCanonicalFindingExternalRefLinked()
	event, err := NewFindingExternalRefLinkedEvent(payload)
	if err != nil {
		t.Fatalf("NewFindingExternalRefLinkedEvent() error = %v", err)
	}
	if !IsSharedEnvelopeEvent(event) {
		t.Fatalf("workflow event payload is not marked as shared Avro envelope: %#v", event.GetAttributes())
	}
	if bytes.HasPrefix(bytes.TrimSpace(event.GetPayload()), []byte("{")) {
		t.Fatal("workflow event payload is JSON, want shared Avro envelope")
	}
	shared, err := DecodeSharedEnvelopeEvent(event.GetPayload(), event.GetAttributes())
	if err != nil {
		t.Fatalf("DecodeSharedEnvelopeEvent() error = %v", err)
	}
	if got := shared.GetSchemaRef(); got != SchemaFindingExternalRefLinked {
		t.Fatalf("shared schema ref = %q, want %q", got, SchemaFindingExternalRefLinked)
	}
	decoded, err := DecodeFindingExternalRefLinked(shared)
	if err != nil {
		t.Fatalf("DecodeFindingExternalRefLinked(shared) error = %v", err)
	}
	if !reflect.DeepEqual(*decoded, payload) {
		t.Fatalf("decoded payload mismatch:\n got=%+v\nwant=%+v", *decoded, payload)
	}
}

func TestFindingExternalRefLinked_RequiredFields(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*FindingExternalRefLinked)
		wantError error
	}{
		{"missing_finding_id", func(p *FindingExternalRefLinked) { p.Finding.FindingID = "" }, ErrFindingExternalRefFindingIDRequired},
		{"missing_system", func(p *FindingExternalRefLinked) { p.System = "" }, ErrFindingExternalRefSystemRequired},
		{"missing_kind", func(p *FindingExternalRefLinked) { p.Kind = "" }, ErrFindingExternalRefKindRequired},
		{"missing_external_id", func(p *FindingExternalRefLinked) { p.ExternalID = "" }, ErrFindingExternalRefExternalIDRequired},
		{"missing_linked_at", func(p *FindingExternalRefLinked) { p.LinkedAt = "" }, ErrFindingExternalRefLinkedAtRequired},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload := newCanonicalFindingExternalRefLinked()
			tc.mutate(&payload)
			envelope := envelopeForFindingExternalRefLinked(t, payload)
			_, err := DecodeFindingExternalRefLinked(envelope)
			if err == nil {
				t.Fatalf("DecodeFindingExternalRefLinked() expected error %v, got nil", tc.wantError)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("DecodeFindingExternalRefLinked() error = %v, want errors.Is(%v)", err, tc.wantError)
			}
		})
	}
}

func newCanonicalFindingExternalRefLinked() FindingExternalRefLinked {
	return FindingExternalRefLinked{
		Finding: FindingSnapshot{
			TenantID:     "writer",
			SourceSystem: "writer-panopticon-case",
			FindingID:    "finding-1",
			RuleID:       "panopticon-curated-case",
			Status:       "open",
		},
		System:               "panopticon",
		Kind:                 "case",
		ExternalID:           "case-123",
		URL:                  "https://panopticon.example/cases/123",
		ExternalStatus:       "investigating",
		ExternalStatusReason: "risky chrome extension",
		LifecycleOwner:       "external_owned",
		LinkedAt:             "2026-06-16T12:00:00Z",
	}
}

func envelopeForFindingExternalRefLinked(t *testing.T, payload FindingExternalRefLinked) *cerebrov1.EventEnvelope {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	tenant := payload.Finding.TenantID
	if tenant == "" {
		tenant = "writer"
	}
	source := payload.Finding.SourceSystem
	if source == "" {
		source = "findings"
	}
	return &cerebrov1.EventEnvelope{
		Id:         "urn:cerebro:writer:workflow_event:test:external-ref",
		TenantId:   tenant,
		SourceId:   source,
		Kind:       EventKindFindingExternalRefLinked,
		OccurredAt: timestamppb.Now(),
		SchemaRef:  SchemaFindingExternalRefLinked,
		Payload:    body,
		Attributes: map[string]string{
			EventAttributeTenantID:     tenant,
			EventAttributeSourceSystem: source,
			EventAttributeFindingID:    payload.Finding.FindingID,
		},
	}
}
