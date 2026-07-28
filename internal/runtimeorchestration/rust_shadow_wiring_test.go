package runtimeorchestration

import (
	"encoding/json"
	"testing"

	"github.com/writer/cerebro/internal/securitypathdelta"
)

func TestJobPayloadIncludesBoundRustAuthorityReceipts(t *testing.T) {
	t.Parallel()
	result := OrchestrationResult{SecurityPath: &SecurityPathResult{
		Delta: securitypathdelta.Delta{ID: "delta-a", Digest: "digest-a"},
		RustAuthority: []securitypathdelta.RustAuthorityReceipt{{
			Operation: "compare", SchemaVersion: "security-path-decision-input/v1",
			InputDigest: "input-digest", DecisionDigest: "decision-digest",
		}},
	}}
	payload, _, err := result.JobPayload()
	if err != nil {
		t.Fatal(err)
	}
	securityPath := payload.SecurityPathDelta
	if securityPath == nil {
		t.Fatalf("security_path_delta = %#v", payload.SecurityPathDelta)
	}
	authority := securityPath.RustAuthority
	if len(authority) != 1 || authority[0].Operation != "compare" {
		t.Fatalf("rust_authority = %#v", authority)
	}
	encoded, err := json.Marshal(payload.Result())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	securityPathWire, ok := wire["security_path_delta"].(map[string]any)
	if !ok {
		t.Fatalf("wire security_path_delta = %#v", wire["security_path_delta"])
	}
	if _, ok := securityPathWire["rust_authority"].([]any); !ok {
		t.Fatalf("wire rust_authority = %#v", securityPathWire["rust_authority"])
	}
}
