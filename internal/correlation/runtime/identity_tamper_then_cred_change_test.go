package runtime

import (
	"slices"
	"testing"
	"time"
)

func TestIdentityTamperThenCredentialChangeHint(t *testing.T) {
	hint := IdentityTamperThenCredentialChangeHint()
	if hint.ID != IdentityTamperThenCredentialChangeHintID {
		t.Fatalf("ID = %q, want %q", hint.ID, IdentityTamperThenCredentialChangeHintID)
	}
	wantRules := []string{
		"identity-auth-control-lifecycle-tampering",
		"identity-api-token-or-oauth-app-created",
	}
	if !slices.Equal(hint.RuleIDs, wantRules) {
		t.Fatalf("RuleIDs = %#v, want %#v", hint.RuleIDs, wantRules)
	}
	if !slices.Equal(hint.Dimensions, []string{"actor", "resource"}) {
		t.Fatalf("Dimensions = %#v, want actor/resource", hint.Dimensions)
	}
	if hint.Window != 24*time.Hour {
		t.Fatalf("Window = %v, want 24h", hint.Window)
	}
	for _, reason := range []string{"control_tamper", "credential_change"} {
		if !slices.Contains(hint.Reasons, reason) {
			t.Fatalf("Reasons = %#v, want %q", hint.Reasons, reason)
		}
	}
	if len(hint.Tests) == 0 {
		t.Fatal("Tests = 0, want at least one catalog test")
	}
}

func TestRuntimeActiveThreatWithPublicExposureHint(t *testing.T) {
	hint := RuntimeActiveThreatWithPublicExposureHint()
	if hint.ID != RuntimeActiveThreatWithPublicExposureHintID {
		t.Fatalf("ID = %q, want %q", hint.ID, RuntimeActiveThreatWithPublicExposureHintID)
	}
	wantRules := []string{
		"cloud-public-resource-exposure",
		"runtime-active-threat-evidence",
	}
	if !slices.Equal(hint.RuleIDs, wantRules) {
		t.Fatalf("RuleIDs = %#v, want %#v", hint.RuleIDs, wantRules)
	}
	if !slices.Equal(hint.Dimensions, []string{"resource"}) {
		t.Fatalf("Dimensions = %#v, want resource", hint.Dimensions)
	}
	if hint.Window != 24*time.Hour {
		t.Fatalf("Window = %v, want 24h", hint.Window)
	}
	for _, reason := range []string{"active_threat", "external_exposure"} {
		if !slices.Contains(hint.Reasons, reason) {
			t.Fatalf("Reasons = %#v, want %q", hint.Reasons, reason)
		}
	}
	if len(hint.Tests) == 0 {
		t.Fatal("Tests = 0, want at least one catalog test")
	}
}

func TestBuiltinHintsIncludeRuntimeExposureHint(t *testing.T) {
	hints := BuiltinHints()
	for _, hint := range hints {
		if hint.ID == RuntimeActiveThreatWithPublicExposureHintID {
			return
		}
	}
	t.Fatalf("BuiltinHints() = %#v, want %q", hints, RuntimeActiveThreatWithPublicExposureHintID)
}

func TestBuiltinHintsReturnsIsolatedCopies(t *testing.T) {
	first := BuiltinHints()
	if len(first) == 0 || len(first[0].RuleIDs) == 0 || len(first[0].Tests) == 0 {
		t.Fatal("BuiltinHints() missing identity hint data")
	}
	first[0].ID = "mutated"
	first[0].RuleIDs[0] = "mutated"
	first[0].Tests[0].Name = "mutated"

	second := BuiltinHints()
	if second[0].ID == "mutated" {
		t.Fatal("BuiltinHints() returned mutable cached hint id")
	}
	if second[0].RuleIDs[0] == "mutated" {
		t.Fatal("BuiltinHints() returned mutable cached rule ids")
	}
	if second[0].Tests[0].Name == "mutated" {
		t.Fatal("BuiltinHints() returned mutable cached tests")
	}
}
