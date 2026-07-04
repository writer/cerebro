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

func TestOktaCompliancePoliciesStayGraphReasoned(t *testing.T) {
	root := repoRoot(t)
	rules, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
	byID := map[string]PolicyFindingRule{}
	for _, rule := range rules {
		byID[rule.Metadata.ID] = rule
	}
	graphPolicyIDs := []string{
		"identity-okta-sign-on-rule-without-mfa",
		"identity-okta-privileged-missing-owner",
		"identity-okta-suspended-user-active-assignment",
		"identity-okta-suspended-user-active-group-membership",
		"identity-okta-external-account-no-owner",
		"identity-okta-dormant-admin-role-assignment",
		"identity-okta-stale-app-assignment-graph-30d",
		"identity-okta-stale-group-membership-graph-90d",
		"identity-okta-group-grants-admin-app-graph",
	}
	for _, id := range graphPolicyIDs {
		rule, ok := byID[id]
		if !ok {
			t.Fatalf("policy %s not loaded", id)
		}
		if strings.TrimSpace(rule.Spec.Match.Query) != "" {
			t.Fatalf("%s has spec.match.query; want graph-only finding", id)
		}
		query := strings.ToLower(rule.Spec.Graph.Query)
		if strings.TrimSpace(query) == "" {
			t.Fatalf("%s missing spec.graph.query", id)
		}
		for _, want := range []string{"graph_path", "finding_attributes", "evidence_basis", "source_provenance", "remediation_intent", "limitation"} {
			if !strings.Contains(query, want) {
				t.Fatalf("%s graph query missing %q", id, want)
			}
		}
		for _, column := range []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"} {
			if !stringSliceContains(rule.Spec.Graph.RequiredColumns, column) {
				t.Fatalf("%s spec.graph.requiredColumns missing %s", id, column)
			}
		}
		if rule.Spec.Graph.RowLimit <= 0 || rule.Spec.Graph.RowLimit > 500 {
			t.Fatalf("%s rowLimit = %d, want bounded <= 500", id, rule.Spec.Graph.RowLimit)
		}
	}
	for _, id := range []string{
		"identity-okta-privileged-missing-owner",
		"identity-okta-suspended-user-active-assignment",
		"identity-okta-suspended-user-active-group-membership",
		"identity-okta-external-account-no-owner",
		"identity-okta-dormant-admin-role-assignment",
		"identity-okta-stale-app-assignment-graph-30d",
		"identity-okta-stale-group-membership-graph-90d",
	} {
		query := strings.ToLower(byID[id].Spec.Graph.Query)
		for _, want := range []string{"lifecycle_state", "mfa_state"} {
			if !strings.Contains(query, want) {
				t.Fatalf("%s graph query missing %q", id, want)
			}
		}
	}
	for _, id := range []string{"identity-okta-dormant-admin-role-assignment", "identity-okta-stale-group-membership-graph-90d"} {
		if query := strings.ToLower(byID[id].Spec.Graph.Query); !strings.Contains(query, "last_login_at") {
			t.Fatalf("%s graph query missing last_login_at source fact", id)
		}
	}
	for _, tc := range []struct {
		id       string
		duration string
	}{
		{id: "identity-okta-dormant-admin-role-assignment", duration: "P30D"},
		{id: "identity-okta-stale-group-membership-graph-90d", duration: "P90D"},
	} {
		query := byID[tc.id].Spec.Graph.Query
		if strings.Contains(query, "datetime(last_login_at)") {
			t.Fatalf("%s graph query parses extracted login timestamps with datetime():\n%s", tc.id, query)
		}
		for _, want := range []string{
			"last_login_at =~ '^[0-9]{4}-",
			"substring(toString(datetime() - duration('" + tc.duration + "')), 0, 19)",
			"malformed login timestamps are ignored",
		} {
			if !strings.Contains(query, want) {
				t.Fatalf("%s graph query missing %q:\n%s", tc.id, want, query)
			}
		}
	}
	for _, id := range []string{
		"identity-okta-stale-app-assignment-30d",
		"identity-okta-stale-group-membership-90d",
		"identity-okta-group-grants-admin-app",
	} {
		rule, ok := byID[id]
		if !ok {
			t.Fatalf("legacy policy %s not loaded", id)
		}
		if strings.TrimSpace(rule.Spec.Match.Query) == "" {
			t.Fatalf("%s missing legacy spec.match.query", id)
		}
		if strings.TrimSpace(rule.Spec.Graph.Query) != "" {
			t.Fatalf("%s has spec.graph.query; legacy query-backed rule must not silently change evaluation mode", id)
		}
	}
	groupAdminGraph := byID["identity-okta-group-grants-admin-app-graph"].Spec.Graph.Query
	if strings.Contains(groupAdminGraph, "toLower(coalesce(app.label, '') + ' ' + coalesce(app.attributes_json, '')) AS app_text") {
		t.Fatalf("group admin graph query should not match admin-like terms across full application attributes:\n%s", groupAdminGraph)
	}
	if !strings.Contains(groupAdminGraph, "toLower(coalesce(app.label, '')) AS app_text") {
		t.Fatalf("group admin graph query should restrict app_text to the application label:\n%s", groupAdminGraph)
	}
	staleAppGraph := byID["identity-okta-stale-app-assignment-graph-30d"].Spec.Graph.Query
	for _, want := range []string{
		"[assignment:RELATION {relation: 'assigned_to'}]",
		"toLower(coalesce(assignment.attributes_json, '')) AS assignment_attrs",
		"NOT assignment_attrs CONTAINS '\"status\":'",
		"assignment_attrs CONTAINS '\"status\":\"active\"'",
		"assignment_attrs CONTAINS '\"status\":\"assigned\"'",
		"activity.attributes_json, '') CONTAINS '\"event_type\":\"app.oauth2.token.grant.",
	} {
		if !strings.Contains(staleAppGraph, want) {
			t.Fatalf("stale app assignment graph query missing %q:\n%s", want, staleAppGraph)
		}
	}
	if strings.Contains(staleAppGraph, "CONTAINS '\"event_type\":\"app.oauth2.token.grant\"'") {
		t.Fatalf("stale app assignment graph query must match OAuth token grant event prefixes with a suffix separator:\n%s", staleAppGraph)
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

func TestValidatePolicyRuleRejectsAssertionOperands(t *testing.T) {
	for _, tc := range []struct {
		name       string
		assertions []PolicyRuleAssertion
		wantIssue  string
	}{
		{
			name:       "binary op missing value",
			assertions: []PolicyRuleAssertion{{Field: "privilege_level", Op: "eq"}},
			wantIssue:  "spec.assert.all[0].value is required for op eq",
		},
		{
			name:       "membership op missing value",
			assertions: []PolicyRuleAssertion{{Field: "privilege_level", Op: "in"}},
			wantIssue:  "spec.assert.all[0].value is required for op in",
		},
		{
			name:       "membership op scalar value",
			assertions: []PolicyRuleAssertion{{Field: "privilege_level", Op: "in", Value: "admin"}},
			wantIssue:  "spec.assert.all[0].value must be a list for op in",
		},
		{
			name:       "membership op empty list",
			assertions: []PolicyRuleAssertion{{Field: "privilege_level", Op: "in", Value: []string{}}},
			wantIssue:  "spec.assert.all[0].value must be a non-empty list for op in",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := ValidatePolicyRule(policyRuleWithAssertions(tc.assertions...))
			if !issuesContain(issues, tc.wantIssue) {
				t.Fatalf("issues = %#v, missing %q", issues, tc.wantIssue)
			}
		})
	}
}

func TestValidatePolicyRuleAcceptsAssertionOperands(t *testing.T) {
	rule := policyRuleWithAssertions(
		PolicyRuleAssertion{Field: "mfa_enrolled", Op: "exists"},
		PolicyRuleAssertion{Field: "mfa_enrolled", Op: "eq", Value: false},
		PolicyRuleAssertion{Field: "privilege_level", Op: "in", Value: []string{"admin", "owner"}},
	)
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want none", issues)
	}
}

func TestValidatePolicyRuleAcceptsDepthBackedPolicy(t *testing.T) {
	rule := depthBackedPolicyRule()
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want none", issues)
	}
}

func TestValidatePolicyRuleRejectsMalformedEvidenceRequirementRefs(t *testing.T) {
	rule := depthBackedPolicyRule()
	rule.Spec.Evidence.RequirementRefs = []string{"identity-access/okta", "identity-access/okta/identity_user"}
	issues := ValidatePolicyRule(rule)
	if !policyIssueContains(issues, "spec.evidence.requirementRefs[0] must use profile_id/source_id/entity_type") {
		t.Fatalf("issues = %#v, want malformed requirement ref issue", issues)
	}
}

func TestValidatePolicyRuleRejectsPartialAuditClaimFields(t *testing.T) {
	rule := depthBackedPolicyRule()
	rule.Spec.Audit.OverclaimGuard = ""
	issues := ValidatePolicyRule(rule)
	if !policyIssueContains(issues, "spec.audit.overclaimGuard is required when any audit claim field is set") {
		t.Fatalf("issues = %#v, want partial claim field issue", issues)
	}
}

func TestValidatePolicyRuleRequiresDepthMetadataWhenRequirementRefsSet(t *testing.T) {
	rule := depthBackedPolicyRule()
	rule.Spec.Verification.MutationChecks = nil
	rule.Spec.Actions.Verification.RerunPolicy = false
	issues := ValidatePolicyRule(rule)
	for _, want := range []string{
		"spec.verification.mutationChecks is required when spec.evidence.requirementRefs is set",
		"spec.actions.verification.rerunPolicy is required when spec.evidence.requirementRefs is set",
	} {
		if !policyIssueContains(issues, want) {
			t.Fatalf("issues = %#v, want %q", issues, want)
		}
	}
}

func TestValidatePolicyRuleAcceptsGraphPolicy(t *testing.T) {
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "graph-example",
			Name:        "Graph Example",
			Description: "Example graph policy",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "low",
			Graph: PolicyRuleGraphFinding{
				Query: `MATCH (entity:Entity {tenant_id: $tenant_id})
WHERE entity.relationship_count >= $minimum_count
RETURN entity.urn AS primary_urn,
       entity.urn AS fingerprint_key,
       'Graph finding' AS summary
LIMIT $row_limit`,
				RowLimit:        500,
				Params:          map[string]any{"minimum_count": int64(3)},
				RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary"},
			},
			Frameworks: []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC7.1"}}},
		},
	}
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want none", issues)
	}
}

func TestValidatePolicyRuleAcceptsEscapedCypherLiteralsAndBacktickIdentifiers(t *testing.T) {
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "graph-escaped",
			Name:        "Graph Escaped",
			Description: "Graph policy using escaped literals and quoted identifiers",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "low",
			Graph: PolicyRuleGraphFinding{
				Query: `MATCH (entity:Entity {tenant_id: $tenant_id})
WHERE entity.note = "escaped \" DELETE still literal"
  AND entity.` + "`MERGE status`" + ` = 'healthy'
RETURN entity.urn AS ` + "`primary_urn`" + `,
       entity.urn AS ` + "`fingerprint_key`" + `,
       entity.label AS ` + "`summary`" + `
LIMIT $row_limit`,
				RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary"},
			},
			Frameworks: []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC7.1"}}},
		},
	}
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want none", issues)
	}
}

func TestValidatePolicyRuleReservedGraphParamDoesNotRequestQueryReference(t *testing.T) {
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "graph-reserved-param",
			Name:        "Graph Reserved Param",
			Description: "Graph policy with a reserved static param",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "low",
			Graph: PolicyRuleGraphFinding{
				Query: `MATCH (entity:Entity)
RETURN entity.urn AS primary_urn,
       entity.urn AS fingerprint_key,
       'Graph finding' AS summary
LIMIT $row_limit`,
				Params: map[string]any{"tenant_id": "writer"},
			},
			Frameworks: []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC7.1"}}},
		},
	}
	issues := ValidatePolicyRule(rule)
	if !issuesContain(issues, "spec.graph.params.tenant_id must not override runtime parameter $tenant_id") {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want reserved param issue", issues)
	}
	if issuesContain(issues, "spec.graph.params.tenant_id must be referenced") {
		t.Fatalf("ValidatePolicyRule() issues = %#v, want no misleading query reference issue", issues)
	}
}

func TestLintPolicyRuleAcceptsInlineLimitAndMultilineOrderBy(t *testing.T) {
	rule := PolicyFindingRule{
		RelPath: "policies/graph/example.yaml",
		Spec: PolicyFindingRuleSpec{
			Graph: PolicyRuleGraphFinding{
				Query: `MATCH (entity:Entity {tenant_id: $tenant_id})
RETURN entity.urn AS primary_urn,
       entity.label AS primary_label,
       entity.entity_type AS primary_type,
       entity.urn AS fingerprint_key,
       'LOW' AS severity,
       'Graph finding' AS summary,
       'Fix graph projection' AS action,
       [entity.urn] AS resource_urns,
       [] AS evidence
ORDER
BY entity.urn
LIMIT 500`,
				RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary"},
			},
		},
	}
	if issues := LintPolicyRule(rule); len(issues) != 0 {
		t.Fatalf("LintPolicyRule() issues = %#v, want none", issues)
	}
}

func TestValidatePolicyRuleRejectsInvalidGraphPolicy(t *testing.T) {
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "graph-invalid",
			Name:        "Graph Invalid",
			Description: "Invalid graph policy",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "low",
			Match: PolicyRuleMatch{
				Conditions: []string{"cmp_eq(path(resource, \"public\"), true)"},
			},
			Graph: PolicyRuleGraphFinding{
				Query:           "MATCH (entity) SET entity.checked = true RETURN entity.urn AS primary_urn",
				RowLimit:        4000,
				Params:          map[string]any{"bad": map[string]any{"nested": true}},
				RequiredColumns: []string{"primary_urn", "fingerprint-key"},
			},
			Frameworks: []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC7.1"}}},
		},
	}
	issues := ValidatePolicyRule(rule)
	for _, want := range []string{
		"spec.graph is mutually exclusive",
		"spec.graph.query must be read-only",
		"spec.graph.query must return fingerprint_key",
		"spec.graph.query must return summary",
		"spec.graph.query must include LIMIT or spec.graph.rowLimit",
		"spec.graph.rowLimit",
		"spec.graph.requiredColumns[1] must be an identifier",
		"spec.graph.params.bad must be referenced",
		"spec.graph.params.bad",
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

func TestValidatePolicyRuleRejectsUnknownYAMLFields(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-example
  name: AWS Example
  description: Example policy
spec:
  severity: high
  match:
    query: SELECT id FROM resources
  frameworks:
    - name: SOC 2
      controls: [CC6]
unexpected: true
`)

	_, issues, err := LoadPolicyRuleFile(root, filepath.Join(root, "policies/aws/example.yaml"))
	if err != nil {
		t.Fatalf("LoadPolicyRuleFile() error = %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "field unexpected not found") {
		t.Fatalf("issues = %#v, want unknown field rejection", issues)
	}
}

func TestEvaluatePolicyConditions(t *testing.T) {
	resource := PolicyResource{
		"public": true,
		"rules": []any{
			map[string]any{"port": "443", "source": "10.0.0.0/8"},
			map[string]any{"port": "22", "source": "0.0.0.0/0"},
		},
	}
	got, err := EvaluatePolicyConditions([]string{
		`cmp_eq(path(resource, "public"), true)`,
		`list_value(path(resource, "rules")).exists(item, (cmp_eq(path(item, "port"), "22")) && (cmp_eq(path(item, "source"), "0.0.0.0/0")))`,
	}, resource)
	if err != nil {
		t.Fatalf("EvaluatePolicyConditions() error = %v", err)
	}
	if !got {
		t.Fatal("EvaluatePolicyConditions() = false, want true")
	}
}

func TestPolicyConditionsResourceFields(t *testing.T) {
	fields, err := PolicyConditionsResourceFields([]string{
		`cmp_eq(path(resource, "public"), true)`,
		`exists_path(resource, "settings.password.min_length")`,
		`list_value(path(resource, "rules")).exists(item, (cmp_eq(path(item, "port"), "22")) && (cmp_eq(path(item, "source"), "0.0.0.0/0")))`,
	})
	if err != nil {
		t.Fatalf("PolicyConditionsResourceFields() error = %v", err)
	}
	want := []string{"public", "rules", "settings.password.min_length"}
	if strings.Join(fields, ",") != strings.Join(want, ",") {
		t.Fatalf("fields = %v, want %v", fields, want)
	}
}

func TestRunPolicyRuleTestSuite(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-example
  name: AWS Example
  description: Example policy
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
	writeTestFile(t, root, "policies/aws/example.test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
cases:
  - name: public bucket fails
    resource:
      public: true
    wantFinding: true
  - name: private bucket passes
    resource:
      public: false
    wantFinding: false
`)

	issues := RunPolicyRuleTestSuite(root, filepath.Join(root, "policies/aws/example.test.yaml"))
	if len(issues) != 0 {
		t.Fatalf("RunPolicyRuleTestSuite() issues = %#v, want none", issues)
	}
}

func TestRunPolicyRuleTestSuiteSupportsGraphRows(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/graph/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: graph-example
  name: Graph Example
  description: Example graph policy
spec:
  severity: low
  graph:
    query: |
      MATCH (entity:Entity {tenant_id: $tenant_id})
      RETURN entity.urn AS primary_urn,
             entity.urn AS fingerprint_key,
             'Graph finding' AS summary
      LIMIT $row_limit
    requiredColumns:
      - primary_urn
      - fingerprint_key
      - summary
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
`)
	writeTestFile(t, root, "policies/graph/example.test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
cases:
  - name: returned primary urn fails
    queryRows:
      - primary_urn: urn:cerebro:writer:resource:one
        fingerprint_key: urn:cerebro:writer:resource:one
        summary: Graph finding
    wantFinding: true
  - name: empty graph rows pass
    resource:
      placeholder: true
    wantFinding: false
`)

	issues := RunPolicyRuleTestSuite(root, filepath.Join(root, "policies/graph/example.test.yaml"))
	if len(issues) != 0 {
		t.Fatalf("RunPolicyRuleTestSuite() issues = %#v, want none", issues)
	}
}

func TestRunPolicyRuleTestSuiteRejectsIncompleteGraphRows(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/graph/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: graph-example
  name: Graph Example
  description: Example graph policy
spec:
  severity: low
  graph:
    query: |
      MATCH (entity:Entity {tenant_id: $tenant_id})
      RETURN entity.urn AS primary_urn,
             entity.urn AS fingerprint_key,
             'Graph finding' AS summary
      LIMIT $row_limit
    requiredColumns:
      - primary_urn
      - fingerprint_key
      - summary
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
`)
	writeTestFile(t, root, "policies/graph/example.test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
cases:
  - name: missing fingerprint
    queryRows:
      - primary_urn: urn:cerebro:writer:resource:one
        summary: Graph finding
    wantFinding: true
`)

	issues := RunPolicyRuleTestSuite(root, filepath.Join(root, "policies/graph/example.test.yaml"))
	if !issuesContain(issues, "queryRows[0].fingerprint_key is a required graph return alias") {
		t.Fatalf("RunPolicyRuleTestSuite() issues = %#v, want missing fingerprint", issues)
	}
	if issuesContain(issues, "queryRows[0].fingerprint_key is required by spec.graph.requiredColumns") {
		t.Fatalf("RunPolicyRuleTestSuite() issues = %#v, want system requirement message", issues)
	}
}

func TestLintPolicyRulesRequiresGraphFixtureCoverage(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/graph/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: graph-example
  name: Graph Example
  description: Example graph policy
  tags: [graph]
spec:
  severity: low
  graph:
    query: |
      MATCH (entity:Entity {tenant_id: $tenant_id})
      RETURN entity.urn AS primary_urn,
             entity.label AS primary_label,
             entity.entity_type AS primary_type,
             entity.urn AS fingerprint_key,
             'LOW' AS severity,
             'Graph finding' AS summary,
             'Fix graph projection' AS action,
             [entity.urn] AS resource_urns,
             [] AS evidence
      ORDER BY entity.urn
      LIMIT $row_limit
    rowLimit: 500
    requiredColumns:
      - primary_urn
      - fingerprint_key
      - summary
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
`)
	issues, err := LintPolicyRules(root)
	if err != nil {
		t.Fatalf("LintPolicyRules() error = %v", err)
	}
	if !issuesContain(issues, "must have a fixture suite") {
		t.Fatalf("LintPolicyRules() issues = %#v, want missing suite", issues)
	}

	writeTestFile(t, root, "policies/graph/example.test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
cases:
  - name: graph finding
    queryRows:
      - primary_urn: urn:cerebro:writer:resource:one
        fingerprint_key: urn:cerebro:writer:resource:one
        summary: Graph finding
    wantFinding: true
  - name: graph pass
    resource:
      placeholder: true
    wantFinding: false
`)
	issues, err = LintPolicyRules(root)
	if err != nil {
		t.Fatalf("LintPolicyRules() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("LintPolicyRules() issues = %#v, want none", issues)
	}
}

func TestPolicyRuleJSONSchema(t *testing.T) {
	schema, err := PolicyRuleJSONSchema()
	if err != nil {
		t.Fatalf("PolicyRuleJSONSchema() error = %v", err)
	}
	text := string(schema)
	for _, want := range []string{
		`"apiVersion"`,
		APIVersion,
		KindPolicyFindingRule,
		`"additionalProperties": false`,
		`"input"`,
		`"assert"`,
		`"context"`,
		`"evidence"`,
		`"audit"`,
		`"verification"`,
		`"actions"`,
		`"auditorStatement"`,
		`"acceptableEvidence"`,
		`"remediationCheck"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("schema missing %q:\n%s", want, text)
		}
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

func policyRuleWithAssertions(assertions ...PolicyRuleAssertion) PolicyFindingRule {
	return PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "assertions",
			Name:        "Assertions",
			Description: "Assertion validation test",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "high",
			Assert:   PolicyRuleAssert{All: assertions},
			Frameworks: []PolicyFramework{
				{Name: "SOC 2", Controls: []string{"CC6.1"}},
			},
		},
	}
}

func depthBackedPolicyRule() PolicyFindingRule {
	return PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          "depth-backed",
			Name:        "Depth Backed",
			Description: "Depth backed policy",
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "high",
			Effect:   "forbid",
			Resource: "okta::user",
			Match: PolicyRuleMatch{
				ConditionFormat: "cel",
				Conditions:      []string{`cmp_eq(path(resource, "mfa_enrolled"), false)`},
			},
			Frameworks: []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}},
			Input: PolicyRuleInput{
				SourceKinds:    []string{"okta"},
				EventKinds:     []string{"okta.identity_user"},
				RequiredFields: []string{"user_id", "mfa_enrolled"},
				FreshnessSLA:   "24h",
			},
			Evidence: PolicyRuleEvidence{
				Type:              "identity_configuration",
				RequirementRefs:   []string{"identity-access/okta/identity_user"},
				AssessmentMethods: []string{"examine", "test"},
				RequiredForAudit:  true,
				FreshnessSLA:      "24h",
				AcceptableSources: []string{"okta"},
				RequiredFields:    []string{"user_id", "mfa_enrolled"},
				FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn"},
			},
			Audit: PolicyRuleAudit{
				AuditorStatement:         "Identity evidence shows MFA state for the user.",
				RiskStatement:            "Users without MFA weaken access controls.",
				RemediationIntent:        "Require MFA for the affected user.",
				ClaimStrength:            "source_backed",
				SufficiencyRule:          "source_period_state_exception",
				CoverageClaim:            "supports_control",
				OverclaimGuard:           "Do not claim broader framework coverage from this requirement alone.",
				AdjacentControlRationale: "Use adjacent controls as review context until they have their own evidence.",
				AcceptableEvidence:       []PolicyRuleAcceptableEvidence{{Source: "okta", Fields: []string{"user_id", "mfa_enrolled"}}},
				ExceptionPolicy:          PolicyRuleExceptionPolicy{MaxAge: "14d", RequiresApproval: true},
				ExceptionGuidance:        []string{"Document compensating monitoring."},
			},
			Verification: PolicyRuleVerification{
				Fixtures: []PolicyRuleVerificationFixture{
					{Name: "missing-mfa", Expect: "finding"},
					{Name: "mfa-present", Expect: "pass"},
				},
				MutationChecks:   []string{"missing_required_field"},
				RemediationCheck: PolicyRuleRemediationCheck{RerunAfter: "source_sync", ExpectedStatus: "pass"},
			},
			Actions: PolicyRuleActions{
				Owner:        PolicyRuleActionOwner{From: "graph.owner"},
				Remediation:  PolicyRuleActionRemediation{Steps: []string{"Require MFA for the affected user."}},
				Effort:       "low",
				Verification: PolicyRuleActionVerification{RerunPolicy: true},
			},
		},
	}
}

func policyIssueContains(issues []Issue, substring string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, substring) {
			return true
		}
	}
	return false
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

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s missing go.mod: %v", root, err)
	}
	return root
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
