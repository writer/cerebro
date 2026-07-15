package runtimeorchestration

import (
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
	securityPath, ok := payload["security_path_delta"].(map[string]any)
	if !ok {
		t.Fatalf("security_path_delta = %#v", payload["security_path_delta"])
	}
	shadow, ok := securityPath["rust_shadow"].([]securitypathdelta.RustShadowResult)
	if !ok || len(shadow) != 1 || shadow[0].Status != securitypathdelta.RustShadowMatch {
		t.Fatalf("rust_shadow = %#v", securityPath["rust_shadow"])
	}
}
