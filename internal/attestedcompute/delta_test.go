package attestedcompute

import (
	"encoding/json"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectEventAcceptsBlindedGraphDelta(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tokenizer, err := NewTokenizer(key)
	if err != nil {
		t.Fatalf("NewTokenizer() error = %v", err)
	}
	userToken := tokenizer.Token("identity.email", "alice@example.com")
	resourceToken := tokenizer.Token("aws.arn", "arn:aws:s3:::sensitive-bucket")
	payload := GraphDelta{
		Attestation: Attestation{
			Format:      "aws-nitro-enclave-poc",
			Measurement: strings.Repeat("a", 96),
			KeyID:       "collector-key",
		},
		Entities: []Entity{
			{
				URN:        TokenURN("tenant-a", "okta.user", userToken),
				EntityType: "okta.user",
				Label:      userToken,
				Attributes: map[string]string{
					"is_admin":     "true",
					"mfa_enrolled": "false",
					"user_urn":     TokenURN("tenant-a", "okta.user", userToken),
				},
			},
			{
				URN:        TokenURN("tenant-a", "aws.s3_bucket", resourceToken),
				EntityType: "aws.s3_bucket",
				Label:      resourceToken,
				Attributes: map[string]string{
					"classification_level": "restricted",
					"resource_urn":         TokenURN("tenant-a", "aws.s3_bucket", resourceToken),
				},
			},
			{
				URN:        "urn:cerebro:tenant-a:data.classification:restricted",
				EntityType: "data.classification",
				Label:      "restricted",
			},
		},
		Links: []Link{
			{FromURN: TokenURN("tenant-a", "okta.user", userToken), ToURN: TokenURN("tenant-a", "aws.s3_bucket", resourceToken), Relation: "can_admin"},
			{FromURN: TokenURN("tenant-a", "aws.s3_bucket", resourceToken), ToURN: "urn:cerebro:tenant-a:data.classification:restricted", Relation: "has_classification"},
		},
	}
	event := eventWithPayload(t, payload)
	entities, links, err := ProjectEvent(event)
	if err != nil {
		t.Fatalf("ProjectEvent() error = %v", err)
	}
	if len(entities) != 3 || len(links) != 2 {
		t.Fatalf("ProjectEvent() produced %d entities/%d links, want 3/2", len(entities), len(links))
	}
	if got := entities[0].Attributes["attested_compute_measurement"]; got == "" {
		t.Fatalf("attestation measurement not stamped on entity")
	}
	if got := links[0].Attributes["attested_compute_key_id"]; got != "collector-key" {
		t.Fatalf("link attestation key = %q, want collector-key", got)
	}
}

func TestProjectEventRejectsRawSensitiveLabel(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: "aws-nitro-enclave-poc", Measurement: strings.Repeat("a", 96)},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:attested:okta.user:tok_abc",
			EntityType: "okta.user",
			Label:      "alice@example.com",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want raw label rejection")
	}
}

func TestProjectEventRejectsRawSensitiveAttribute(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: "aws-nitro-enclave-poc", Measurement: strings.Repeat("a", 96)},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:attested:okta.user:tok_abc",
			EntityType: "okta.user",
			Label:      "tok_abc",
			Attributes: map[string]string{
				"email": "alice@example.com",
			},
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want raw attribute rejection")
	}
}

func TestProjectEventRejectsCrossTenantURN(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: "aws-nitro-enclave-poc", Measurement: strings.Repeat("a", 96)},
		Entities: []Entity{{
			URN:        "urn:cerebro:other:attested:okta.user:tok_abc",
			EntityType: "okta.user",
			Label:      "tok_abc",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want cross-tenant rejection")
	}
}

func eventWithPayload(t *testing.T, delta GraphDelta) *cerebrov1.EventEnvelope {
	t.Helper()
	body, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	return &cerebrov1.EventEnvelope{
		Id:       "evt-1",
		TenantId: "tenant-a",
		SourceId: "attested_compute",
		Kind:     EventKindGraphDelta,
		Payload:  body,
	}
}
