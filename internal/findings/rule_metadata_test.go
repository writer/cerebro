package findings

import (
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestBuiltinRuleMetadataIsComplete(t *testing.T) {
	metadata := BuiltinRuleMetadata()
	if len(metadata) == 0 {
		t.Fatal("BuiltinRuleMetadata() = 0, want built-in rule metadata")
	}
	if errs := ValidateRuleMetadataCompleteness(metadata); len(errs) != 0 {
		t.Fatalf("ValidateRuleMetadataCompleteness() first error = %v (count=%d)", errs[0], len(errs))
	}
}

func TestBuiltinRuleMetadataReturnsIsolatedCopies(t *testing.T) {
	first := BuiltinRuleMetadata()
	if len(first) == 0 {
		t.Fatal("BuiltinRuleMetadata() missing expected test data")
	}
	index := -1
	for i, metadata := range first {
		if len(metadata.Tags) > 0 {
			index = i
			break
		}
	}
	if index == -1 {
		t.Fatal("BuiltinRuleMetadata() missing tagged rule metadata")
	}
	first[index].ID = "mutated"
	first[index].Tags[0] = "mutated"

	second := BuiltinRuleMetadata()
	if second[index].ID == "mutated" {
		t.Fatal("BuiltinRuleMetadata() returned mutable cached metadata id")
	}
	if second[index].Tags[0] == "mutated" {
		t.Fatal("BuiltinRuleMetadata() returned mutable cached metadata tags")
	}
}

func TestValidateRuleMetadataCompletenessAcceptsCandidateAndProductionMaturity(t *testing.T) {
	for _, maturity := range []string{RuleMaturityTest, RuleMaturityCandidate, RuleMaturityExperimental, RuleMaturityGA, RuleMaturityProduction, RuleMaturityRetired} {
		metadata := RuleDefinition{
			ID:                "rule-" + maturity,
			Name:              "Rule " + maturity,
			Description:       "Rule description",
			SourceID:          "okta",
			OutputKind:        "finding",
			Severity:          "LOW",
			Status:            "active",
			Maturity:          maturity,
			Tags:              []string{"identity"},
			References:        []string{"https://example.com"},
			FalsePositives:    []string{"test"},
			Runbook:           "Review source evidence.",
			FingerprintFields: []string{"tenant_id"},
			ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC6.1"}},
		}
		if errs := ValidateRuleMetadataCompleteness([]RuleDefinition{metadata}); len(errs) != 0 {
			t.Fatalf("ValidateRuleMetadataCompleteness(%q) errors = %v", maturity, errs)
		}
	}
}

func TestValidateRuleMetadataCompletenessRejectsUnknownMaturity(t *testing.T) {
	metadata := RuleDefinition{
		ID:                "rule-unknown",
		Name:              "Rule unknown",
		Description:       "Rule description",
		SourceID:          "okta",
		OutputKind:        "finding",
		Severity:          "LOW",
		Status:            "active",
		Maturity:          "preview-ish",
		Tags:              []string{"identity"},
		References:        []string{"https://example.com"},
		FalsePositives:    []string{"test"},
		Runbook:           "Review source evidence.",
		FingerprintFields: []string{"tenant_id"},
		ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC6.1"}},
	}
	if errs := ValidateRuleMetadataCompleteness([]RuleDefinition{metadata}); len(errs) == 0 {
		t.Fatal("ValidateRuleMetadataCompleteness() errors = 0, want unsupported maturity")
	}
}

func TestValidateRuleMetadataCompletenessAllowsPolicyRulesWithoutReferences(t *testing.T) {
	metadata := RuleDefinition{
		ID:                "policy-rule",
		Name:              "Policy Rule",
		Description:       "Generated policy rule metadata",
		SourceID:          policyRuleSourceID,
		OutputKind:        policyRuleOutputKind,
		Severity:          "LOW",
		Status:            "active",
		Maturity:          RuleMaturityCandidate,
		Tags:              []string{"policy"},
		FalsePositives:    []string{"Approved exception."},
		Runbook:           "Review policy evidence.",
		FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn", "resource_id"},
		ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6"}},
	}
	if errs := ValidateRuleMetadataCompleteness([]RuleDefinition{metadata}); len(errs) != 0 {
		t.Fatalf("ValidateRuleMetadataCompleteness() errors = %v, want none", errs)
	}
}

func TestBuiltinRuleSourceIDsReturnsIsolatedCopies(t *testing.T) {
	first := BuiltinRuleSourceIDs()
	if len(first) == 0 {
		t.Fatal("BuiltinRuleSourceIDs() = 0, want source id index")
	}
	first[githubAppIntegrationInstalledRuleID] = "mutated"

	second := BuiltinRuleSourceIDs()
	if second[githubAppIntegrationInstalledRuleID] == "mutated" {
		t.Fatal("BuiltinRuleSourceIDs() returned mutable cached source id map")
	}
}

func TestBuiltinPublicDetectionCatalogIncludesGraphRules(t *testing.T) {
	catalog := BuiltinPublicDetectionCatalog()
	if len(catalog.Detections) == 0 {
		t.Fatal("BuiltinPublicDetectionCatalog() has no detections")
	}
	for _, detection := range catalog.Detections {
		if detection.ID == "cloud-public-exposure-privileged-principal" {
			if detection.EvaluationMode != "graph" {
				t.Fatalf("graph detection evaluation_mode = %q, want graph", detection.EvaluationMode)
			}
			return
		}
	}
	t.Fatal("BuiltinPublicDetectionCatalog() missing cloud graph rule")
}

func TestBuiltinPublicDetectionCatalogPreservesFingerprintFieldOrder(t *testing.T) {
	catalog := BuiltinPublicDetectionCatalog()
	for _, detection := range catalog.Detections {
		if detection.ID == githubAppIntegrationInstalledRuleID {
			want := []string{"org", "github_app_id"}
			if !slices.Equal(detection.FingerprintFields, want) {
				t.Fatalf("FingerprintFields = %#v, want %#v", detection.FingerprintFields, want)
			}
			return
		}
	}
	t.Fatalf("BuiltinPublicDetectionCatalog() missing %s", githubAppIntegrationInstalledRuleID)
}

func TestBuiltinPublicDetectionCatalogPublishesPolicyAuditDepth(t *testing.T) {
	catalog := BuiltinPublicDetectionCatalog()
	for _, detection := range catalog.Detections {
		if detection.ID != "aws-s3-bucket-no-public-access" {
			continue
		}
		if detection.EvidenceType != "cloud_configuration" {
			t.Fatalf("EvidenceType = %q, want cloud_configuration", detection.EvidenceType)
		}
		if !slices.Equal(detection.AssessmentMethods, []string{"examine", "test"}) {
			t.Fatalf("AssessmentMethods = %#v, want examine/test", detection.AssessmentMethods)
		}
		if detection.AuditorGuidance == "" || detection.RiskStatement == "" || detection.RemediationIntent == "" {
			t.Fatalf("policy audit depth missing: guidance=%q risk=%q remediation=%q", detection.AuditorGuidance, detection.RiskStatement, detection.RemediationIntent)
		}
		wantMITRE := []MITREAttackRef{
			{Tactic: "Initial Access", Technique: "T1190"},
			{Tactic: "Collection", Technique: "T1530"},
		}
		if !slices.Equal(detection.MITREAttack, wantMITRE) {
			t.Fatalf("MITREAttack = %#v, want %#v", detection.MITREAttack, wantMITRE)
		}
		return
	}
	t.Fatal("BuiltinPublicDetectionCatalog() missing aws-s3-bucket-no-public-access")
}

func TestEnrichPublicDetectionCatalogWithSourceCoverageLinksPolicyRules(t *testing.T) {
	catalog := PublicDetectionCatalog{
		Version: "test",
		Detections: []PublicDetection{{
			ID:                        "aws-s3-bucket-no-public-access",
			Name:                      "S3 Bucket Allows Public Access",
			SourceID:                  policyRuleSourceID,
			Tags:                      []string{"aws", "policy", "s3"},
			PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "cloud_configuration"},
			ControlRefs:               []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6"}},
			MITREAttack:               []MITREAttackRef{{Tactic: "Initial Access", Technique: "T1190"}},
		}},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:             "s3_bucket",
			Type:           "entity_family",
			Families:       []string{"s3_bucket"},
			Support:        sourcecdk.CoverageSupportSupported,
			HighValue:      true,
			EvidenceTypes:  []string{"network_exposure"},
			ControlDomains: []string{"network_security"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.6",
			}},
		}},
	}}

	enriched := EnrichPublicDetectionCatalogWithSourceCoverage(catalog, contracts)
	if got := len(enriched.Detections[0].SourceCoverageRefs); got != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want 1", got)
	}
	ref := enriched.Detections[0].SourceCoverageRefs[0]
	if ref.SourceID != "aws" || ref.DimensionID != "s3_bucket" {
		t.Fatalf("SourceCoverageRefs[0] = %#v, want aws/s3_bucket", ref)
	}
	if got, want := ref.MatchedControlRefs, []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}, {FrameworkName: "SOC 2", ControlID: "CC6.7"}}; !slices.Equal(got, want) {
		t.Fatalf("MatchedControlRefs = %#v, want %#v", got, want)
	}
	if got, want := enriched.Detections[0].MITREAttack, []MITREAttackRef{{Tactic: "Initial Access", Technique: "T1190"}}; !slices.Equal(got, want) {
		t.Fatalf("MITREAttack = %#v, want %#v", got, want)
	}
}

func TestEnrichPublicDetectionCatalogWithSourceCoverageAvoidsBroadCrossSourceParentMatches(t *testing.T) {
	catalog := PublicDetectionCatalog{
		Version: "test",
		Detections: []PublicDetection{{
			ID:          "okta-admin-without-mfa",
			Name:        "Okta Admin Without MFA",
			SourceID:    policyRuleSourceID,
			Tags:        []string{"okta", "policy"},
			ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC6"}},
		}},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:       "s3_bucket",
			Type:     "entity_family",
			Families: []string{"s3_bucket"},
			Support:  sourcecdk.CoverageSupportSupported,
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.6",
			}},
		}},
	}}

	enriched := EnrichPublicDetectionCatalogWithSourceCoverage(catalog, contracts)
	if got := enriched.Detections[0].SourceCoverageRefs; len(got) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no cross-source broad match", got)
	}
}

func TestBuiltinPublicDetectionCatalogPublishesGRCFingerprintSalts(t *testing.T) {
	wantByID := map[string][]string{
		grcControlTestNeedsAttentionRuleID: {"tenant_id", "runtime_id", "provider", "test_id"},
		grcVulnerabilitySLAOverdueRuleID:   {"tenant_id", "runtime_id", "provider", "name", "package", "target_id"},
		grcVendorReviewOverdueRuleID:       {"tenant_id", "runtime_id", "provider", "vendor_id"},
	}
	catalog := BuiltinPublicDetectionCatalog()
	for _, detection := range catalog.Detections {
		want, ok := wantByID[detection.ID]
		if !ok {
			continue
		}
		if !slices.Equal(detection.FingerprintFields, want) {
			t.Fatalf("%s FingerprintFields = %#v, want %#v", detection.ID, detection.FingerprintFields, want)
		}
		delete(wantByID, detection.ID)
	}
	if len(wantByID) != 0 {
		t.Fatalf("BuiltinPublicDetectionCatalog() missing GRC detections: %#v", wantByID)
	}
}

func TestBuiltinPublicDetectionCatalogPublishesGraphInputKinds(t *testing.T) {
	wantByID := map[string][]string{
		sentinelOneEndpointActiveInfectionRuleID:      {"sentinelone.agent", "sentinelone.threat"},
		vulnViewExternalAssetConcentratedSignalRuleID: {"vulnview.dns_alert", "vulnview.vulnerability"},
	}
	catalog := BuiltinPublicDetectionCatalog()
	for _, detection := range catalog.Detections {
		want, ok := wantByID[detection.ID]
		if !ok {
			continue
		}
		if !slices.Equal(detection.EventKinds, want) {
			t.Fatalf("%s EventKinds = %#v, want %#v", detection.ID, detection.EventKinds, want)
		}
		delete(wantByID, detection.ID)
	}
	if len(wantByID) != 0 {
		t.Fatalf("BuiltinPublicDetectionCatalog() missing graph detections: %#v", wantByID)
	}
}
