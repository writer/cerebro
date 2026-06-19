package findingdsl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyRulesLoadsValidatedYAML(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-example
  name: AWS Example
  description: Example policy
  tags: [aws]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public"), true)
  frameworks:
    - name: SOC 2
      controls: [CC6]
`)
	writeTestFile(t, root, ControlMappingRelPath, `{"version":"1.0.0","controls":{}}`)

	rules, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
	if got := len(rules); got != 1 {
		t.Fatalf("len(rules) = %d, want 1", got)
	}
	rule := rules[0]
	if rule.Metadata.ID != "aws-example" || rule.Domain != "aws" || rule.RelPath != "policies/aws/example.yaml" {
		t.Fatalf("loaded rule = %#v", rule)
	}
}

func TestLoadPolicyRulesLoadsContractMetadataBlocks(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/identity/privileged-no-mfa.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: privileged-no-mfa
  name: Privileged No MFA
  description: Privileged users must have MFA
spec:
  severity: high
  category: identity
  resourceType: identity.user
  input:
    sourceKinds: [okta.user]
    eventKinds: [policy.evidence, policy.result]
    requiredClaims: [identity.user, identity.mfa_status]
    requiredFields: [tenant_id, policy_id, resource_urn, mfa_enrolled]
    freshnessSLA: 24h
  assert:
    all:
      - field: privilege_level
        op: in
        value: [admin, owner]
      - field: mfa_enrolled
        op: eq
        value: false
  context:
    graph:
      anchors: [resource_urn, principal_urn]
      enrich: [owner, privileged_access_path]
    severityAdjustments:
      - when: context.crown_jewel_distance <= 2
        set: critical
  evidence:
    type: identity_configuration
    assessmentMethods: [examine, test]
    requiredForAudit: true
    freshnessSLA: 24h
    acceptableSources: [okta]
    requiredFields: [subject_urn, mfa_enrolled]
    fingerprintFields: [tenant_id, policy_id, resource_urn]
  audit:
    evidenceType: identity_configuration
    assessmentMethods: [examine, test]
    freshnessSLA: 24h
    auditorStatement: Privileged users are required to have MFA enabled.
    riskStatement: Privileged users without MFA weaken identity controls.
    acceptableEvidence:
      - source: okta
        fields: [user_id, role, mfa_status, observed_at]
    exceptionPolicy:
      maxAge: 14d
      requiresApproval: true
  verification:
    fixtures:
      - name: admin-without-mfa
        expect: finding
      - name: admin-with-mfa
        expect: pass
    mutationChecks: [missing_required_field, stale_evidence]
    remediationCheck:
      rerunAfter: source_sync
      expectedStatus: pass
  actions:
    owner:
      from: graph.owner
      fallback: resource.tags.owner
    remediation:
      type: manual
      steps: [Require MFA enrollment.]
    effort: low
    blastRadius:
      estimateFrom: graph.neighborhood
    verification:
      rerunPolicy: true
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
`)

	rules, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
	rule := rules[0]
	if got := rule.Spec.Input.FreshnessSLA; got != "24h" {
		t.Fatalf("Input.FreshnessSLA = %q, want 24h", got)
	}
	if got := rule.Spec.Evidence.Type; got != "identity_configuration" {
		t.Fatalf("Evidence.Type = %q, want identity_configuration", got)
	}
	if got := len(rule.Spec.Assert.All); got != 2 {
		t.Fatalf("len(Assert.All) = %d, want 2", got)
	}
	if got := rule.Spec.Actions.Owner.From; got != "graph.owner" {
		t.Fatalf("Actions.Owner.From = %q, want graph.owner", got)
	}
}

func TestValidatePolicyRuleRejectsUnsafeContractMetadata(t *testing.T) {
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "unsafe",
			Name:        "Unsafe",
			Description: "Unsafe contract metadata",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "high",
			Assert:   PolicyRuleAssert{All: []PolicyRuleAssertion{{Field: "mfa_enrolled", Op: "eq", Value: false}}},
			Frameworks: []PolicyFramework{
				{Name: "SOC 2", Controls: []string{"CC6.1"}},
			},
			Evidence: PolicyRuleEvidence{
				AssessmentMethods: []string{"guess"},
				FreshnessSLA:      "soon",
				FingerprintFields: []string{"event_id"},
			},
			Verification: PolicyRuleVerification{
				Fixtures: []PolicyRuleVerificationFixture{{Name: "bad", Expect: "maybe"}},
			},
			Actions: PolicyRuleActions{Effort: "huge"},
		},
	}
	issues := ValidatePolicyRule(rule)
	for _, want := range []string{
		"assessmentMethods[0]",
		"freshnessSLA",
		"fingerprintFields[0]",
		"fixtures[0].expect",
		"effort",
	} {
		if !issuesContain(issues, want) {
			t.Fatalf("issues = %#v, missing %q", issues, want)
		}
	}
}

func TestLoadPolicyRulesRejectsLegacyJSONPolicies(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.json", `{"id":"aws-example"}`)

	_, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "legacy JSON") {
		t.Fatalf("issues = %#v, want legacy JSON rejection", issues)
	}
}

func TestLoadPolicyRulesRejectsDuplicatePolicyIDs(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/a.yaml", testPolicyRuleYAML("aws-duplicate", "AWS A"))
	writeTestFile(t, root, "policies/aws/b.yaml", testPolicyRuleYAML("aws-duplicate", "AWS B"))

	_, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, `duplicate metadata.id "aws-duplicate"`) {
		t.Fatalf("issues = %#v, want duplicate metadata.id issue", issues)
	}
	if issues[0].Path != "policies/aws/b.yaml" {
		t.Fatalf("issue path = %q, want duplicate path", issues[0].Path)
	}
}

func TestValidateStringArrayReportsAllBlankEntries(t *testing.T) {
	issues := validateStringArray("policies/aws/example.yaml", "metadata.tags", []string{"", "aws", " "})
	for _, want := range []string{"metadata.tags[0]", "metadata.tags[2]"} {
		if !issuesContain(issues, want) {
			t.Fatalf("issues = %#v, missing %q", issues, want)
		}
	}
}

func TestLegacyPolicyRoundTrip(t *testing.T) {
	rule := FromLegacyPolicy("policies/aws/example.yaml", LegacyPolicy{
		ID:              "aws-example",
		Name:            "AWS Example",
		Description:     "Example policy",
		Severity:        "medium",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"true"},
		ConditionFormat: "cel",
		Tags:            []string{"aws"},
		Frameworks:      []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6"}}},
	})
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v", issues)
	}
	legacy := rule.LegacyPolicy()
	if legacy.ID != "aws-example" || legacy.Resource != "aws::s3::bucket" || legacy.ConditionFormat != "cel" {
		t.Fatalf("LegacyPolicy() = %#v", legacy)
	}
}

func issuesContain(issues []Issue, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, want) {
			return true
		}
	}
	return false
}

func testPolicyRuleYAML(id string, name string) string {
	return `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: ` + id + `
  name: ` + name + `
  description: Example policy
  tags: [aws]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public"), true)
  frameworks:
    - name: SOC 2
      controls: [CC6]
`
}

func writeTestFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
