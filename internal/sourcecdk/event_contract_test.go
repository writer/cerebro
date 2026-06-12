package sourcecdk

import (
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateEventEnvelopeAcceptsNormalizedEvent(t *testing.T) {
	event := normalizedTestEvent()
	if err := ValidateEventEnvelope(event); err != nil {
		t.Fatalf("ValidateEventEnvelope() error = %v", err)
	}
}

func TestValidateEventEnvelopeRejectsMissingRequiredFields(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*cerebrov1.EventEnvelope)
	}{
		{name: "id", mutate: func(event *cerebrov1.EventEnvelope) { event.Id = "" }},
		{name: "tenant", mutate: func(event *cerebrov1.EventEnvelope) { event.TenantId = "" }},
		{name: "source", mutate: func(event *cerebrov1.EventEnvelope) { event.SourceId = "" }},
		{name: "kind", mutate: func(event *cerebrov1.EventEnvelope) { event.Kind = "" }},
		{name: "occurred_at", mutate: func(event *cerebrov1.EventEnvelope) { event.OccurredAt = nil }},
		{name: "schema_ref", mutate: func(event *cerebrov1.EventEnvelope) { event.SchemaRef = "" }},
		{name: "payload", mutate: func(event *cerebrov1.EventEnvelope) { event.Payload = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := normalizedTestEvent()
			tt.mutate(event)
			if err := ValidateEventEnvelope(event); !errors.Is(err, ErrInvalidEventEnvelope) {
				t.Fatalf("ValidateEventEnvelope() error = %v, want ErrInvalidEventEnvelope", err)
			}
		})
	}
}

func TestValidateEventEnvelopeRejectsInvalidJSONPayload(t *testing.T) {
	event := normalizedTestEvent()
	event.Payload = []byte(`{"unterminated":`)
	if err := ValidateEventEnvelope(event); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("ValidateEventEnvelope() error = %v, want ErrInvalidEventEnvelope", err)
	}
}

func TestValidateEventEnvelopeRejectsPantherStyleKindShape(t *testing.T) {
	event := normalizedTestEvent()
	event.Kind = "GitHub.Audit"
	if err := ValidateEventEnvelope(event); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("ValidateEventEnvelope() error = %v, want ErrInvalidEventEnvelope", err)
	}
}

func TestValidateEventEnvelopeWithContractsRequiresAttributesAndPayloadFields(t *testing.T) {
	event := normalizedTestEvent()
	event.Payload = []byte(`{"action":"protected_branch.destroy","org":"example"}`)
	event.Attributes["org"] = "example"
	contracts := []EventContract{{
		Kind:                  "github.audit",
		SchemaRef:             "github/audit/v1",
		RequiredAttributes:    []string{"org"},
		RequiredPayloadFields: []string{"action", "org"},
	}}
	if err := ValidateEventEnvelopeWithContracts(event, contracts); err != nil {
		t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v", err)
	}
	delete(event.Attributes, "org")
	if err := ValidateEventEnvelopeWithContracts(event, contracts); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v, want ErrInvalidEventEnvelope", err)
	}
}

func TestValidateEventEnvelopeWithContractsRejectsUnmatchedKind(t *testing.T) {
	event := normalizedTestEvent()
	event.Kind = "github.pull_request"
	event.SchemaRef = "github/pull_request/v1"
	contracts := []EventContract{{
		Kind:               "github.audit",
		SchemaRef:          "github/audit/v1",
		RequiredAttributes: []string{"org"},
	}}
	if err := ValidateEventEnvelopeWithContracts(event, contracts); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v, want ErrInvalidEventEnvelope", err)
	}
}

func TestValidateEventContractsRejectsDuplicateKinds(t *testing.T) {
	_, err := ValidateEventContracts([]EventContract{
		{Kind: "github.audit", SchemaRef: "github/audit/v1", RequiredAttributes: []string{"org"}},
		{Kind: "github.audit", SchemaRef: "github/audit/v1", RequiredAttributes: []string{"action"}},
	})
	if err == nil {
		t.Fatal("ValidateEventContracts() error = nil, want duplicate kind error")
	}
}

func FuzzValidateEventEnvelopeWithContracts(f *testing.F) {
	f.Add("github.audit", "github/audit/v1", []byte(`{"action":"protected_branch.destroy","org":"example"}`), "org", "example", "action")
	f.Add("GitHub.Audit", "github/audit/v1", []byte(`{"action":"x"}`), "org", "example", "action")
	f.Add("github.audit", "github/audit/v1", []byte(`[]`), "org", "example", "action")
	f.Add("github.audit", "github/audit/v1", []byte(`{"action":""}`), "org", "", "action")
	f.Fuzz(func(t *testing.T, kind string, schemaRef string, payload []byte, attrKey string, attrValue string, requiredPayloadField string) {
		if len(payload) > 4096 || len(kind) > 128 || len(schemaRef) > 128 || len(attrKey) > 128 || len(requiredPayloadField) > 128 {
			t.Skip()
		}
		event := normalizedTestEvent()
		event.Kind = kind
		event.SchemaRef = schemaRef
		event.Payload = payload
		event.Attributes = map[string]string{}
		if attrKey != "" {
			event.Attributes[attrKey] = attrValue
		}
		contracts := []EventContract{{
			Kind:                  "github.audit",
			SchemaRef:             "github/audit/v1",
			RequiredAttributes:    []string{"org"},
			RequiredPayloadFields: []string{requiredPayloadField},
		}}
		err := ValidateEventEnvelopeWithContracts(event, contracts)
		if err == nil {
			if kind != "github.audit" || schemaRef != "github/audit/v1" {
				t.Fatalf("accepted event with mismatched contract kind/schema: kind=%q schema=%q", kind, schemaRef)
			}
			if attrValue == "" && attrKey == "org" {
				t.Fatalf("accepted event with empty required attribute")
			}
			return
		}
		if !errors.Is(err, ErrInvalidEventEnvelope) {
			if _, normalizeErr := NormalizeEventContract(contracts[0]); normalizeErr == nil {
				t.Fatalf("error = %v, want ErrInvalidEventEnvelope", err)
			}
		}
	})
}

func normalizedTestEvent() *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "github-audit-1",
		TenantId:   "example",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "github/audit/v1",
		Payload:    []byte(`{"action":"protected_branch.destroy"}`),
		Attributes: map[string]string{
			AttributeActorUser: "security-admin@example.com",
			AttributeEventType: "protected_branch.destroy",
		},
	}
}
