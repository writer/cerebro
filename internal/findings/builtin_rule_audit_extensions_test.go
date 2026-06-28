package findings

import (
	"strings"
	"testing"
)

func TestBuiltinRuleAuditExtensionDefaultsComplete(t *testing.T) {
	if got := strings.TrimSpace(builtinRuleAuditExtensionSet.Version); got == "" {
		t.Fatal("builtin rule audit extension version is empty")
	}
	if missing := missingBuiltinRuleAuditFields(builtinRuleAuditExtensionSet.Defaults); len(missing) != 0 {
		t.Fatalf("builtin rule audit extension defaults missing fields: %v", missing)
	}
}

func TestBuiltinPublicDetectionCatalogHasAuditDepth(t *testing.T) {
	catalog := BuiltinPublicDetectionCatalog()
	if len(catalog.Detections) == 0 {
		t.Fatal("BuiltinPublicDetectionCatalog returned no detections")
	}
	if errs := ValidatePublicDetectionAuditDepth(catalog); len(errs) != 0 {
		t.Fatalf("catalog missing audit depth: first error = %v (count=%d)", errs[0], len(errs))
	}
	nonPolicy := 0
	for _, detection := range catalog.Detections {
		if strings.EqualFold(strings.TrimSpace(detection.SourceID), policyRuleSourceID) {
			continue
		}
		nonPolicy++
		if strings.TrimSpace(detection.RiskStatement) == "" || strings.TrimSpace(detection.RemediationIntent) == "" {
			t.Fatalf("non-policy detection %q missing risk/remediation audit depth", detection.ID)
		}
	}
	if nonPolicy == 0 {
		t.Fatal("expected non-policy detections in the catalog")
	}
}

func TestApplyBuiltinRuleAuditDepthLayering(t *testing.T) {
	def := RuleDefinition{
		ID:       "identity-privileged-no-mfa-plus-sensitive-access",
		SourceID: "identity",
		Lifecycle: Lifecycle{
			Kind:   LifecycleDurableState,
			Anchor: AnchorGraphAnchored,
		},
	}
	got := applyBuiltinRuleAuditDepth(def)

	if want := "identity_governance"; got.EvidenceType != want {
		t.Fatalf("EvidenceType = %q, want source layer %q", got.EvidenceType, want)
	}
	if !strings.Contains(got.RiskStatement, "crown-jewel") {
		t.Fatalf("RiskStatement = %q, want rule-level override mentioning crown-jewel", got.RiskStatement)
	}
	if !strings.Contains(got.AuditorGuidance, "graph path") {
		t.Fatalf("AuditorGuidance = %q, want graph_anchored anchor guidance", got.AuditorGuidance)
	}
	if len(got.AssessmentMethods) == 0 {
		t.Fatal("AssessmentMethods empty, want anchor/default methods")
	}
}

func TestApplyBuiltinRuleAuditDepthSkipsPolicyAndPreservesExisting(t *testing.T) {
	policyDef := RuleDefinition{ID: "policy-example", SourceID: policyRuleSourceID}
	if got := applyBuiltinRuleAuditDepth(policyDef); got.EvidenceType != "" || got.RiskStatement != "" {
		t.Fatalf("policy detection received overlay audit depth: %+v", got)
	}

	existing := RuleDefinition{
		ID:            "sentinelone-endpoint-active-infection",
		SourceID:      "sentinelone",
		RiskStatement: "custom risk statement",
		Lifecycle:     Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
	}
	got := applyBuiltinRuleAuditDepth(existing)
	if got.RiskStatement != "custom risk statement" {
		t.Fatalf("RiskStatement = %q, want preserved rule-declared value", got.RiskStatement)
	}
	if strings.TrimSpace(got.EvidenceType) == "" {
		t.Fatal("EvidenceType not filled from overlay")
	}
}
