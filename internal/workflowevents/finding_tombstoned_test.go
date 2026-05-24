package workflowevents

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestEventKindFindingTombstonedRegistered(t *testing.T) {
	const want = "workflow.v1.finding.tombstoned"
	if got := EventKindFindingTombstoned; got != want {
		t.Fatalf("EventKindFindingTombstoned = %q, want %q", got, want)
	}
	if got := SchemaFindingTombstoned; got != "urn:cerebro:events/workflow.finding.tombstoned/v1" {
		t.Fatalf("SchemaFindingTombstoned = %q, want %q", got, "urn:cerebro:events/workflow.finding.tombstoned/v1")
	}
	if !KindRegistered(EventKindFindingTombstoned) {
		t.Fatalf("KindRegistered(%q) = false, want true", EventKindFindingTombstoned)
	}
	if got := SchemaForKind(EventKindFindingTombstoned); got != SchemaFindingTombstoned {
		t.Fatalf("SchemaForKind(%q) = %q, want %q", EventKindFindingTombstoned, got, SchemaFindingTombstoned)
	}
}

func TestFindingTombstoned_RoundTrip(t *testing.T) {
	payload := newCanonicalFindingTombstoned()
	event, err := NewFindingTombstonedEvent(payload)
	if err != nil {
		t.Fatalf("NewFindingTombstonedEvent() error = %v", err)
	}
	if got := event.GetKind(); got != EventKindFindingTombstoned {
		t.Fatalf("event kind = %q, want %q", got, EventKindFindingTombstoned)
	}
	if got := event.GetSchemaRef(); got != SchemaFindingTombstoned {
		t.Fatalf("event schema = %q, want %q", got, SchemaFindingTombstoned)
	}
	if got := event.GetAttributes()[EventAttributeFindingID]; got != payload.Finding.FindingID {
		t.Fatalf("finding_id attribute = %q, want %q", got, payload.Finding.FindingID)
	}
	decoded, err := DecodeFindingTombstoned(event)
	if err != nil {
		t.Fatalf("DecodeFindingTombstoned() error = %v", err)
	}
	if !reflect.DeepEqual(*decoded, payload) {
		t.Fatalf("decoded payload mismatch:\n got=%+v\nwant=%+v", *decoded, payload)
	}
}

func TestFindingTombstoned_RequiredFields(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*FindingTombstoned)
		wantError error
	}{
		{"missing_finding_id", func(p *FindingTombstoned) { p.Finding.FindingID = "" }, ErrFindingTombstonedFindingIDRequired},
		{"missing_run_id", func(p *FindingTombstoned) { p.RunID = "" }, ErrFindingTombstonedRunIDRequired},
		{"missing_prior_status", func(p *FindingTombstoned) { p.PriorStatus = "" }, ErrFindingTombstonedPriorStatusRequired},
		{"missing_actor", func(p *FindingTombstoned) { p.Actor = "" }, ErrFindingTombstonedActorRequired},
		{"missing_reason", func(p *FindingTombstoned) { p.Reason = "" }, ErrFindingTombstonedReasonRequired},
		{"missing_tombstoned_at", func(p *FindingTombstoned) { p.TombstonedAt = "" }, ErrFindingTombstonedTimestampRequired},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload := newCanonicalFindingTombstoned()
			tc.mutate(&payload)
			envelope := envelopeForFindingTombstoned(t, payload)
			_, err := DecodeFindingTombstoned(envelope)
			if err == nil {
				t.Fatalf("DecodeFindingTombstoned() expected error %v, got nil", tc.wantError)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("DecodeFindingTombstoned() error = %v, want errors.Is(%v)", err, tc.wantError)
			}
		})
	}

	t.Run("all_fields_decode_clean", func(t *testing.T) {
		payload := newCanonicalFindingTombstoned()
		envelope := envelopeForFindingTombstoned(t, payload)
		decoded, err := DecodeFindingTombstoned(envelope)
		if err != nil {
			t.Fatalf("DecodeFindingTombstoned() error = %v", err)
		}
		if !reflect.DeepEqual(*decoded, payload) {
			t.Fatalf("decoded payload mismatch:\n got=%+v\nwant=%+v", *decoded, payload)
		}
	})
}

func newCanonicalFindingTombstoned() FindingTombstoned {
	return FindingTombstoned{
		Finding: FindingSnapshot{
			TenantID:     "writer",
			SourceSystem: "findings",
			FindingID:    "urn:cerebro:writer:finding:f-1",
			RuleID:       "rule-1",
			Status:       "resolved",
			Fingerprint:  "fp-1",
		},
		PriorStatus:  "open",
		Reason:       "bulk closeout: pre-conversion backlog",
		Actor:        "operator@writer.com",
		RunID:        "run-2026-04-27-001",
		TombstonedAt: "2026-04-27T12:00:00Z",
	}
}

func envelopeForFindingTombstoned(t *testing.T, payload FindingTombstoned) *cerebrov1.EventEnvelope {
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
		Id:         "urn:cerebro:writer:workflow_event:test:tombstoned",
		TenantId:   tenant,
		SourceId:   source,
		Kind:       EventKindFindingTombstoned,
		OccurredAt: timestamppb.Now(),
		SchemaRef:  SchemaFindingTombstoned,
		Payload:    body,
		Attributes: map[string]string{
			EventAttributeTenantID:     tenant,
			EventAttributeSourceSystem: source,
			EventAttributeFindingID:    payload.Finding.FindingID,
		},
	}
}
