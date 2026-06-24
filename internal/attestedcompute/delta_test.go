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
			Format:      AttestationFormatAWSNitroEnclavePOC,
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
	if got := entities[0].Attributes["attested_compute_verification_status"]; got != "unverified_poc" {
		t.Fatalf("attestation verification status = %q, want unverified_poc", got)
	}
	for _, key := range []string{"attested_compute_claimed_format", "attested_compute_claimed_measurement", "attested_compute_claimed_key_id", "attested_compute_claimed_image_digest"} {
		if got := entities[0].Attributes[key]; got != "" {
			t.Fatalf("%s = %q, want empty for unverified attestation", key, got)
		}
	}
}

func TestProjectEventRejectsRawSensitiveLabel(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
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

func TestProjectEventRejectsCaseInsensitiveSensitiveEntityBypass(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:okta.user:alice@example.com",
			EntityType: "OKTA.USER",
			Label:      "alice@example.com",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want case-insensitive sensitive entity rejection")
	}
}

func TestProjectEventRejectsSensitiveURNWithBenignDeclaredType(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:okta.user:alice@example.com",
			EntityType: "data.classification",
			Label:      "restricted",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want sensitive URN rejection")
	}
}

func TestProjectEventRejectsRawSensitiveAttribute(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
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

func TestSensitiveAttributeKeyOnlyMatchesIPAsToken(t *testing.T) {
	for _, key := range []string{"ip", "source_ip", "ip_address", "public-ip", "network.ip", "ipv4_address", "source_ipv6", "ipv4.src"} {
		if !sensitiveAttributeKey(key) {
			t.Fatalf("sensitiveAttributeKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"description", "ownership", "ship_date"} {
		if sensitiveAttributeKey(key) {
			t.Fatalf("sensitiveAttributeKey(%q) = true, want false", key)
		}
	}
}

func TestSensitiveAttributeKeyDoesNotAllowSafePrefixPIIBypass(t *testing.T) {
	for _, key := range []string{"risk_email", "control_user_name", "classification_arn", "posture_principal"} {
		if !sensitiveAttributeKey(key) {
			t.Fatalf("sensitiveAttributeKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"risk_score", "control_status", "classification_level", "posture_state"} {
		if sensitiveAttributeKey(key) {
			t.Fatalf("sensitiveAttributeKey(%q) = true, want false", key)
		}
	}
}

func TestProjectEventRejectsRawSensitiveLinkEndpoint(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
		Links: []Link{{
			FromURN:  "urn:cerebro:tenant-a:okta.user:alice@example.com",
			ToURN:    "urn:cerebro:tenant-a:data.classification:restricted",
			Relation: "has_classification",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want raw sensitive link endpoint rejection")
	}
}

func TestProjectEventRejectsCrossTenantURN(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)},
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

func TestProjectEventRejectsAttestedURNWithRawTokenSegment(t *testing.T) {
	tokenizer, err := NewTokenizer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewTokenizer() error = %v", err)
	}
	userToken := tokenizer.Token("identity.email", "alice@example.com")
	rawAttestedURN := "urn:cerebro:tenant-a:attested:okta.user:alice@example.com"
	validTokenURN := TokenURN("tenant-a", "okta.user", userToken)
	for _, tc := range []struct {
		name  string
		delta GraphDelta
	}{
		{
			name: "entity urn",
			delta: GraphDelta{
				Entities: []Entity{{
					URN:        rawAttestedURN,
					EntityType: "okta.user",
				}},
			},
		},
		{
			name: "link endpoint",
			delta: GraphDelta{
				Links: []Link{{
					FromURN:  rawAttestedURN,
					ToURN:    "urn:cerebro:tenant-a:data.classification:restricted",
					Relation: "has_classification",
				}},
			},
		},
		{
			name: "sensitive attribute",
			delta: GraphDelta{
				Entities: []Entity{{
					URN:        validTokenURN,
					EntityType: "okta.user",
					Label:      userToken,
					Attributes: map[string]string{
						"user_urn": rawAttestedURN,
					},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.delta.Attestation = Attestation{Format: AttestationFormatAWSNitroEnclavePOC, Measurement: strings.Repeat("a", 96)}
			if _, _, err := ProjectEvent(eventWithPayload(t, tc.delta)); err == nil {
				t.Fatalf("ProjectEvent() error = nil, want raw attested URN token rejection")
			}
		})
	}
}

func TestProjectEventDropsCallerSuppliedAttestationAttributes(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: AttestationFormatAWSNitroEnclavePOC, ImageDigest: "sha256:abc"},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:data.classification:restricted",
			EntityType: "data.classification",
			Label:      "restricted",
			Attributes: map[string]string{
				"attested_compute_claimed_key_id":      "fake-key",
				"attested_compute_claimed_measurement": "fake-measurement",
			},
		}},
	}
	entities, _, err := ProjectEvent(eventWithPayload(t, payload))
	if err != nil {
		t.Fatalf("ProjectEvent() error = %v", err)
	}
	attributes := entities[0].Attributes
	if got := attributes["attested_compute_claimed_key_id"]; got != "" {
		t.Fatalf("caller-supplied claimed key id survived = %q", got)
	}
	if got := attributes["attested_compute_claimed_measurement"]; got != "" {
		t.Fatalf("caller-supplied claimed measurement survived = %q", got)
	}
	if got := attributes["attested_compute_claimed_image_digest"]; got != "" {
		t.Fatalf("claimed image digest = %q, want empty for unverified attestation", got)
	}
}

func TestProjectEventRejectsUnsupportedAttestationFormat(t *testing.T) {
	payload := GraphDelta{
		Attestation: Attestation{Format: "self-asserted", ImageDigest: "sha256:abc"},
		Entities: []Entity{{
			URN:        "urn:cerebro:tenant-a:data.classification:restricted",
			EntityType: "data.classification",
			Label:      "restricted",
		}},
	}
	if _, _, err := ProjectEvent(eventWithPayload(t, payload)); err == nil {
		t.Fatalf("ProjectEvent() error = nil, want unsupported attestation format rejection")
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
