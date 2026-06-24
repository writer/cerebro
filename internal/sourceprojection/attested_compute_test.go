package sourceprojection

import (
	"encoding/json"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/attestedcompute"
	"github.com/writer/cerebro/internal/ports"
)

func TestAttestedComputeGraphDeltaProjectsIntoGraphRecords(t *testing.T) {
	tokenizer, err := attestedcompute.NewTokenizer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewTokenizer() error = %v", err)
	}
	userToken := tokenizer.Token("identity.email", "alice@example.com")
	resourceToken := tokenizer.Token("aws.arn", "arn:aws:s3:::sensitive-bucket")
	userURN := attestedcompute.TokenURN("tenant-a", "okta.user", userToken)
	resourceURN := attestedcompute.TokenURN("tenant-a", "aws.s3_bucket", resourceToken)
	payload := attestedcompute.GraphDelta{
		Attestation: attestedcompute.Attestation{
			Format:      "aws-nitro-enclave-poc",
			Measurement: strings.Repeat("a", 96),
			KeyID:       "collector-key",
		},
		Entities: []attestedcompute.Entity{
			{URN: userURN, EntityType: "okta.user", Label: userToken, Attributes: map[string]string{"is_admin": "true"}},
			{URN: resourceURN, EntityType: "aws.s3_bucket", Label: resourceToken, Attributes: map[string]string{"is_public": "true"}},
		},
		Links: []attestedcompute.Link{
			{FromURN: userURN, ToURN: resourceURN, Relation: "can_admin", Attributes: map[string]string{"observed_at": "2026-06-24T00:00:00Z"}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:       "evt-attested",
		TenantId: "tenant-a",
		SourceId: "attested_compute",
		Kind:     attestedcompute.EventKindGraphDelta,
		Payload:  body,
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "runtime-attested",
		},
	}

	entities, links, err := New(nil, nil).ProjectRecords(event)
	if err != nil {
		t.Fatalf("ProjectRecords() error = %v", err)
	}
	if len(entities) != 2 || len(links) != 1 {
		t.Fatalf("ProjectRecords() produced %d entities/%d links, want 2/1", len(entities), len(links))
	}
	for _, entity := range entities {
		if entity.RuntimeID != "runtime-attested" {
			t.Fatalf("entity runtime_id = %q, want runtime-attested", entity.RuntimeID)
		}
		if strings.Contains(entity.Label, "alice") || strings.Contains(entity.Label, "sensitive-bucket") {
			t.Fatalf("entity label leaked raw identifier: %q", entity.Label)
		}
	}
	if links[0].Relation != "can_admin" {
		t.Fatalf("link relation = %q, want can_admin", links[0].Relation)
	}
	if got := links[0].Attributes["attested_compute_format"]; got != "aws-nitro-enclave-poc" {
		t.Fatalf("link attestation format = %q, want aws-nitro-enclave-poc", got)
	}
}
