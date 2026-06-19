package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
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
	if !strings.Contains(description, "Flags failed manual-attestation evidence for aws cloudtrail trail: CloudTrail Enabled.") {
		t.Fatalf("description = %q, want failed evidence framing", description)
	}
	if !strings.Contains(description, "Checks whether CloudTrail is enabled in all regions.") {
		t.Fatalf("description = %q, want normalized copy", description)
	}
	if !strings.Contains(description, "Audit impact: Audit logging evidence may be incomplete.") {
		t.Fatalf("description = %q, want audit impact statement", description)
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

func TestPolicyDSLContractMetadataOverridesGeneratedRuleFields(t *testing.T) {
	policy := policyFile{
		ID:       "identity-okta-privileged-no-mfa",
		Name:     "Okta Privileged No MFA",
		Severity: "high",
		Input: findingdsl.PolicyRuleInput{
			EventKinds:     []string{"policy.result"},
			RequiredFields: []string{"tenant_id", "policy_id", "resource_urn"},
			RequiredFieldsByKind: map[string][]string{
				"policy.result": {"resource_urn", "mfa_enrolled"},
			},
			FreshnessSLA: "24h",
		},
		Evidence: findingdsl.PolicyRuleEvidence{
			Type:              "identity_configuration",
			AssessmentMethods: []string{"test", "examine"},
			RequiredForAudit:  true,
			FreshnessSLA:      "24h",
			FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn"},
			AcceptableSources: []string{"okta"},
		},
		Audit: findingdsl.PolicyRuleAudit{
			AuditorStatement:  "Privileged users must have MFA.",
			RiskStatement:     "Privileged users without MFA weaken identity controls.",
			RemediationIntent: "Require MFA.",
			FalsePositives:    []string{"Approved exception."},
		},
		Context: findingdsl.PolicyRuleContext{
			Graph: findingdsl.PolicyRuleGraphContext{
				Anchors: []string{"resource_urn"},
				Enrich:  []string{"owner"},
			},
		},
		Verification: findingdsl.PolicyRuleVerification{
			Fixtures:       []findingdsl.PolicyRuleVerificationFixture{{Name: "admin-without-mfa", Expect: "finding"}},
			MutationChecks: []string{"missing_required_field"},
		},
		Actions: findingdsl.PolicyRuleActions{
			Owner:  findingdsl.PolicyRuleActionOwner{From: "graph.owner"},
			Effort: "low",
		},
	}
	extension := policyRuleExtension{
		EvidenceType:      "control_evidence",
		AssessmentMethods: []string{"interview"},
		AuditorGuidance:   "Extension guidance.",
		RiskStatement:     "Extension risk.",
		RemediationIntent: "Extension remediation.",
	}

	if got, want := strings.Join(policyEventKinds(policy), ","), "policy.result"; got != want {
		t.Fatalf("policyEventKinds() = %q, want %q", got, want)
	}
	if got, want := strings.Join(policyRequiredAttributes(policy), ","), "policy_id,resource_urn,tenant_id"; got != want {
		t.Fatalf("policyRequiredAttributes() = %q, want %q", got, want)
	}
	if got, want := strings.Join(policyRequiredAttributesByKind(policy)["policy.result"], ","), "mfa_enrolled,resource_urn"; got != want {
		t.Fatalf("policyRequiredAttributesByKind() = %q, want %q", got, want)
	}
	if got := policyEvidenceType(policy, extension); got != "identity_configuration" {
		t.Fatalf("policyEvidenceType() = %q, want identity_configuration", got)
	}
	if got, want := strings.Join(policyAssessmentMethods(policy, extension), ","), "examine,test"; got != want {
		t.Fatalf("policyAssessmentMethods() = %q, want %q", got, want)
	}
	if got := policyAuditorGuidance(policy, extension); got != "Privileged users must have MFA." {
		t.Fatalf("policyAuditorGuidance() = %q, want audit statement", got)
	}
	if got := policyRiskStatement(policy, extension); got != "Privileged users without MFA weaken identity controls." {
		t.Fatalf("policyRiskStatement() = %q, want DSL risk", got)
	}
	if got := policyRemediationIntent(policy, extension); got != "Require MFA." {
		t.Fatalf("policyRemediationIntent() = %q, want DSL remediation", got)
	}
	if !contains(policyFalsePositives(policy, extension), "Approved exception.") {
		t.Fatalf("policyFalsePositives() missing DSL false positive")
	}
	attrs := policyContractAttributes(policy)
	for key, want := range map[string]string{
		"policy_input_freshness_sla":          "24h",
		"policy_evidence_required_for_audit":  "true",
		"policy_evidence_acceptable_sources":  "okta",
		"policy_context_graph_anchors":        "resource_urn",
		"policy_context_graph_enrich":         "owner",
		"policy_verification_fixtures":        "admin-without-mfa:finding",
		"policy_verification_mutation_checks": "missing_required_field",
		"policy_action_owner_from":            "graph.owner",
		"policy_action_effort":                "low",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("contract attr %s = %q, want %q; attrs=%#v", key, got, want, attrs)
		}
	}
}

func TestGraphPolicyGenerationDefaults(t *testing.T) {
	policy := policyFile{
		ID:       "graph-orphan-nonfinding-node",
		Name:     "Graph Orphan Non-Finding Node",
		Severity: "low",
		Input: findingdsl.PolicyRuleInput{
			SourceKinds: []string{"graph"},
		},
		Graph: findingdsl.PolicyRuleGraphFinding{
			Query:           "MATCH (entity:Entity {tenant_id: $tenant_id}) RETURN entity.urn AS primary_urn, entity.urn AS fingerprint_key, 'Graph finding' AS summary LIMIT $row_limit",
			RowLimit:        500,
			RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary"},
		},
		domain: "graph",
	}

	if got := policyEvidenceMode(policy); got != "graph" {
		t.Fatalf("policyEvidenceMode() = %q, want graph", got)
	}
	if got, want := strings.Join(policyEventKinds(policy), ","), "graph"; got != want {
		t.Fatalf("policyEventKinds() = %q, want %q", got, want)
	}
	if got := policySourceIDLiteral(policy); got != `"graph"` {
		t.Fatalf("policySourceIDLiteral() = %q, want graph literal", got)
	}
	if got := policyOutputKindLiteral(policy); got != "policyGraphOutputKind" {
		t.Fatalf("policyOutputKindLiteral() = %q, want policyGraphOutputKind", got)
	}
	if got := policyEvidenceLabel(policyEvidenceMode(policy)); got != "graph-state" {
		t.Fatalf("policyEvidenceLabel(graph) = %q, want graph-state", got)
	}
}

func TestSafeRepoRelRejectsEscapingOutput(t *testing.T) {
	for _, value := range []string{"../outside.go", "/tmp/out.go"} {
		if _, err := safeRepoRel(value); err == nil {
			t.Fatalf("safeRepoRel(%q) error = nil, want escape rejection", value)
		}
	}
	if got, err := safeRepoRel("internal/findings/policy_rule_catalog_gen.go"); err != nil || got != "internal/findings/policy_rule_catalog_gen.go" {
		t.Fatalf("safeRepoRel(valid) = %q, %v", got, err)
	}
}

func TestWriteRepoFileUsesReadableGeneratedFileMode(t *testing.T) {
	root := t.TempDir()
	if err := writeRepoFile(root, "internal/findings/generated.go", []byte("package findings\n")); err != nil {
		t.Fatalf("writeRepoFile() error = %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "internal/findings/generated.go"))
	if err != nil {
		t.Fatalf("stat generated file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("generated file mode = %#o, want 0644", got)
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
