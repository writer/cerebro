package dspm

import (
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

func TestScanResult_ToPolicyFindings(t *testing.T) {
	target := &ScanTarget{
		ID:          "bucket-123",
		Type:        "s3_bucket",
		Provider:    "aws",
		Name:        "prod-sensitive-bucket",
		IsPublic:    true,
		IsEncrypted: false,
	}

	result := &ScanResult{
		TargetID:       target.ID,
		TargetType:     target.Type,
		TargetName:     target.Name,
		Provider:       target.Provider,
		Classification: ClassificationRestricted,
		RiskScore:      96.5,
		Findings: []SensitiveDataFinding{
			{
				DataType:       DataTypeCreditCard,
				Classification: ClassificationRestricted,
				Confidence:     0.92,
				MatchCount:     3,
				Frameworks:     []ComplianceFramework{FrameworkPCI},
			},
			{
				DataType:       DataTypeHealthRecord,
				Classification: ClassificationRestricted,
				Confidence:     0.81,
				MatchCount:     2,
				Frameworks:     []ComplianceFramework{FrameworkHIPAA},
			},
		},
		ComplianceGaps: []ComplianceGap{
			{
				Framework:   FrameworkHIPAA,
				Requirement: "164.312(e)(1)",
				Description: "PHI found in publicly accessible storage",
				Severity:    "critical",
			},
		},
	}

	findings := result.ToPolicyFindings(target)
	if len(findings) < 5 {
		t.Fatalf("expected at least 5 findings, got %d", len(findings))
	}

	byPolicy := map[string][]string{}
	for _, finding := range findings {
		byPolicy[finding.PolicyID] = append(byPolicy[finding.PolicyID], finding.ID)
	}

	requiredPolicies := []string{
		"dspm-sensitive-data-credit-card",
		"dspm-sensitive-data-health-record",
		PolicyIDRestrictedDataUnencrypted,
		PolicyIDConfidentialDataPublic,
		"dspm-compliance-gap-hipaa",
	}
	for _, policyID := range requiredPolicies {
		if len(byPolicy[policyID]) == 0 {
			t.Fatalf("expected finding for policy %s", policyID)
		}
	}

	publicExposure := findFindingByPolicyID(findings, PolicyIDConfidentialDataPublic)
	if publicExposure == nil {
		t.Fatal("expected public exposure finding")
	}
	if publicExposure.Severity != "critical" {
		t.Fatalf("expected public exposure severity critical, got %s", publicExposure.Severity)
	}

	restrictedUnencrypted := findFindingByPolicyID(findings, PolicyIDRestrictedDataUnencrypted)
	if restrictedUnencrypted == nil {
		t.Fatal("expected restricted-unencrypted finding")
	}
	if len(restrictedUnencrypted.Frameworks) == 0 {
		t.Fatal("expected restricted-unencrypted finding to include framework mappings")
	}

	pciSensitive := findFindingByPolicyID(findings, "dspm-sensitive-data-credit-card")
	if pciSensitive == nil {
		t.Fatal("expected PCI sensitive data finding")
	}
	if !hasFrameworkControl(pciSensitive.Frameworks, "PCI DSS", "3.5.1") {
		t.Fatal("expected PCI sensitive finding to map PCI DSS control 3.5.1")
	}

	hipaaGap := findFindingByPolicyID(findings, "dspm-compliance-gap-hipaa")
	if hipaaGap == nil {
		t.Fatal("expected HIPAA compliance gap finding")
	}
	if !hasFrameworkControl(hipaaGap.Frameworks, "HIPAA Security Rule", "164.312(e)(1)") {
		t.Fatal("expected HIPAA gap finding to include requirement control mapping")
	}
}

func TestScanResult_ToPolicyFindings_NilOrEmpty(t *testing.T) {
	var nilResult *ScanResult
	if got := nilResult.ToPolicyFindings(nil); got != nil {
		t.Fatalf("expected nil findings for nil result, got %d", len(got))
	}

	empty := &ScanResult{}
	if got := empty.ToPolicyFindings(&ScanTarget{ID: "target"}); len(got) != 0 {
		t.Fatalf("expected empty findings for empty result, got %d", len(got))
	}
}

func findFindingByPolicyID(findings []policy.Finding, policyID string) *policy.Finding {
	for i := range findings {
		if findings[i].PolicyID == policyID {
			return &findings[i]
		}
	}
	return nil
}

func hasFrameworkControl(mappings []policy.FrameworkMapping, frameworkName, controlID string) bool {
	for _, mapping := range mappings {
		if mapping.Name != frameworkName {
			continue
		}
		for _, control := range mapping.Controls {
			if control == controlID {
				return true
			}
		}
	}
	return false
}
