package main

import (
	"strings"
	"testing"
)

func TestPolicyRuleExtensionMergeOverridesAssessmentMethods(t *testing.T) {
	extensions := policyRuleExtensions{
		Defaults: policyRuleExtension{
			AssessmentMethods: []string{"examine", "test"},
			FalsePositives:    []string{"default fp"},
		},
		EvidenceModes: map[string]policyRuleExtension{
			"query": {
				AssessmentMethods: []string{"examine"},
				FalsePositives:    []string{"query fp"},
			},
		},
		Domains: map[string]policyRuleExtension{
			"compliance": {
				AssessmentMethods: []string{"examine", "interview"},
				FalsePositives:    []string{"domain fp"},
			},
		},
	}
	extension := extensions.extensionFor(policyFile{ID: "policy-1", Query: "SELECT 1", domain: "compliance"})
	if got, want := strings.Join(extension.AssessmentMethods, ","), "examine,interview"; got != want {
		t.Fatalf("AssessmentMethods = %q, want %q", got, want)
	}
	for _, want := range []string{"default fp", "query fp", "domain fp"} {
		if !contains(extension.FalsePositives, want) {
			t.Fatalf("FalsePositives = %#v, missing %q", extension.FalsePositives, want)
		}
	}
}

func TestPolicyDescriptionNormalizesEnsuresCopy(t *testing.T) {
	description := policyDescription(policyFile{
		Name:        "CloudTrail Enabled",
		Description: "Ensures CloudTrail is enabled in all regions",
		Resource:    "aws::cloudtrail::trail",
	}, policyRuleExtension{RiskStatement: "Audit logging evidence may be incomplete."})
	if !strings.Contains(description, "Checks whether CloudTrail is enabled in all regions.") {
		t.Fatalf("description = %q, want normalized copy", description)
	}
	if !strings.Contains(description, "Risk: Audit logging evidence may be incomplete.") {
		t.Fatalf("description = %q, want risk statement", description)
	}
}

func TestControlFamilyIndexMapsControlsToFamilyLabels(t *testing.T) {
	index := controlFamilyIndex{
		"SOC 2\x00CC6.1":         "SOC 2 CC6 Logical and Physical Access",
		"NIST 800-53 r5\x00AC-2": "NIST 800-53 r5 AC Access Control",
	}
	families := index.familiesFor([]policyFramework{
		{Name: "SOC 2", Controls: []string{"CC6.1"}},
		{Name: "NIST 800-53 r5", Controls: []string{"AC-2"}},
		{Name: "SOC 2", Controls: []string{"CC6.1"}},
	})
	if got, want := strings.Join(families, "|"), "NIST 800-53 r5 AC Access Control|SOC 2 CC6 Logical and Physical Access"; got != want {
		t.Fatalf("families = %q, want %q", got, want)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
