package runtimeorchestration

import (
	"encoding/json"
	"testing"

	"github.com/writer/cerebro/internal/securitypathdelta"
)

func TestJobPayloadIncludesBoundedRustShadowEvidence(t *testing.T) {
	t.Parallel()
	result := OrchestrationResult{SecurityPath: &SecurityPathResult{
		Delta: securitypathdelta.Delta{ID: "delta-a", Digest: "digest-a"},
		RustShadow: []securitypathdelta.RustShadowResult{{
			Operation: "compare", Status: securitypathdelta.RustShadowMatch,
			GoDigest: "go-digest", RustDigest: "rust-digest",
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
	shadow := securityPath.RustShadow
	if len(shadow) != 1 || shadow[0].Status != securitypathdelta.RustShadowMatch {
		t.Fatalf("rust_shadow = %#v", shadow)
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
	if _, ok := securityPathWire["rust_shadow"].([]any); !ok {
		t.Fatalf("wire rust_shadow = %#v", securityPathWire["rust_shadow"])
	}
}
