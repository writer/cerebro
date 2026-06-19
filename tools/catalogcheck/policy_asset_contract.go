package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/sourceprojection"
)

type policyAssetContract struct {
	EntityType string
	EventKinds []string
	Fields     []string
}

var requiredGraphAssetColumns = []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"}

var policyAssetContracts = map[string]policyAssetContract{
	"github.code.repository": {
		EntityType: "github.code.repository",
		EventKinds: []string{
			"github.audit",
			"github.code.repository",
		},
		Fields: []string{
			"action",
			"actions_artifact_attestation_missing",
			"actions_oidc_subject_too_broad_compliant",
			"actions_permissions",
			"archived",
			"artifact_attestation_missing",
			"auth_control_weakened",
			"branch",
			"branch_requires_linear_history_compliant",
			"branch_requires_signed_commits",
			"bypass_actor_added",
			"code_security_enabled",
			"codeowners_missing",
			"content",
			"default_branch",
			"default_branch_protection",
			"default_branch_protection_enabled",
			"deletions_allowed",
			"dependabot_alerts_enabled",
			"dependabot_security_updates",
			"dependabot_security_updates_disabled",
			"force_pushes_allowed",
			"fork",
			"full_name",
			"github_advanced_security_enabled",
			"has_self_hosted_runners",
			"hook_id",
			"hook_url_non_allowlisted",
			"name",
			"owner",
			"owner_login",
			"private",
			"repo",
			"repo_webhook_insecure_ssl_compliant",
			"repository",
			"repository_secret_scanning_enabled",
			"repository_vulnerability_alerts_enabled",
			"required_review_removed",
			"required_status_check_removed",
			"resource_id",
			"resource_type",
			"ruleset_bypass_unrestricted",
			"ruleset_enforcement",
			"ruleset_id",
			"ruleset_name",
			"ruleset_required",
			"secret_push_protection_disabled",
			"secret_scanning",
			"secret_scanning_push_protection",
			"secret_scanning_push_protection_enabled",
			"visibility",
			"webhook_destination_non_allowlisted",
			"webhook_url_non_allowlisted",
		},
	},
	"github.credential": {
		EntityType: "github.credential",
		EventKinds: []string{"github.audit"},
		Fields: []string{
			"actor",
			"actor_is_agent",
			"actor_is_bot",
			"actor_type",
			"credential_type",
			"github_app_id",
			"org",
			"org_id",
			"programmatic_access_type",
			"repository",
			"resource_id",
			"resource_type",
			"scope",
			"status",
			"token_id",
			"transport_protocol_name",
		},
	},
	"github.dependabot_alert": {
		EntityType: "github.dependabot_alert",
		EventKinds: []string{"github.dependabot_alert"},
		Fields: []string{
			"alert_number",
			"created_at",
			"created_at_days",
			"dependency_scope",
			"ecosystem",
			"first_patched_version",
			"manifest_path",
			"package",
			"repository",
			"severity",
			"state",
			"visibility",
			"vulnerable_version_range",
		},
	},
	"github.org_installation": {
		EntityType: "github.org_installation",
		EventKinds: []string{"github.org_installation"},
		Fields: []string{
			"app_slug",
			"created_at",
			"events",
			"installation_id",
			"owner",
			"permissions",
			"repository_selection",
			"target_type",
			"updated_at",
		},
	},
	"github.pull_request": {
		EntityType: "github.pull_request",
		EventKinds: []string{"github.pull_request"},
		Fields: []string{
			"html_url",
			"pull_number",
			"repository",
			"state",
		},
	},
	"github.resource": {
		EntityType: "github.resource",
		EventKinds: []string{"github.audit"},
		Fields: []string{
			"action",
			"actions_oidc_subject_too_broad_compliant",
			"actions_permissions",
			"allowed_cidrs_compliant",
			"ip_allow_list_enabled",
			"mfa_required",
			"oauth_app_restrictions_enabled",
			"org",
			"permission",
			"private_repository_forking_enabled",
			"resource_id",
			"resource_type",
			"rule",
			"saml_enabled",
			"saml_enforced",
			"saml_provider_settings_weakened",
			"secret_scanning_enabled",
			"secret_scanning_push_protection_enabled",
			"state",
			"two_factor_requirement_enabled",
		},
	},
	"github.runner": {
		EntityType: "github.runner",
		EventKinds: []string{"github.audit"},
		Fields: []string{
			"allows_public_repositories",
			"host_trusted",
			"repository",
			"runner_ephemeral",
			"runner_group",
			"runner_group_name",
			"runner_id",
			"runner_name",
			"runner_registered",
			"runner_scope",
			"runner_scope_type",
			"runner_state",
			"runner_status",
			"runner_untrusted",
			"selected_repositories_count",
			"visibility",
		},
	},
	"github.secret_scanning_alert": {
		EntityType: "github.secret_scanning_alert",
		EventKinds: []string{"github.secret_scanning_alert"},
		Fields: []string{
			"alert_number",
			"push_protection_bypassed",
			"repository",
			"resolution",
			"resolved_at",
			"resolver",
			"secret_type",
			"state",
			"url",
			"visibility",
		},
	},
	"github.user": {
		EntityType: "github.user",
		EventKinds: []string{
			"github.audit",
			"github.org_member",
		},
		Fields: []string{
			"actor",
			"login",
			"role",
			"two_factor_enabled",
			"user_id",
		},
	},
}

func checkPolicyAssetContracts(rules []findingdsl.PolicyFindingRule) []issue {
	var issues []issue
	issues = append(issues, validatePolicyAssetContractCatalog()...)
	for _, rule := range rules {
		if !policyRequiresGraphBackedAsset(rule) {
			continue
		}
		issues = append(issues, validateGraphBackedPolicyFixtures(rule)...)
		if strings.TrimSpace(rule.Spec.Graph.Query) != "" {
			issues = append(issues, validateGraphPolicyAssetColumns(rule)...)
			continue
		}
		resources := splitPolicyResources(rule.Spec.Resource)
		if len(resources) == 0 {
			issues = append(issues, issue{path: rule.RelPath, message: "graph-backed policy must declare spec.resource or spec.graph.query"})
			continue
		}
		conditionFields, err := findingdsl.PolicyConditionsResourceFields(rule.Spec.Match.Conditions)
		if err != nil {
			issues = append(issues, issue{path: rule.RelPath, message: "extract policy resource fields: " + err.Error()})
			continue
		}
		assertFields := policyRuleAssertFields(rule.Spec.Assert)
		for _, resource := range resources {
			contract, ok := policyAssetContracts[resource]
			if !ok {
				issues = append(issues, issue{path: rule.RelPath, message: fmt.Sprintf("graph-backed policy resource %q has no projected asset contract", resource)})
				continue
			}
			issues = append(issues, validatePolicyAssetEventKinds(rule.RelPath, resource, contract, rule.Spec.Input.EventKinds)...)
			issues = append(issues, validatePolicyAssetFields(rule.RelPath, resource, contract, conditionFields, "spec.match.conditions")...)
			issues = append(issues, validatePolicyAssetFields(rule.RelPath, resource, contract, assertFields, "spec.assert")...)
		}
		if !containsString(rule.Spec.Context.Graph.Anchors, "resource_urn") {
			issues = append(issues, issue{path: rule.RelPath, message: "graph-backed policy must include resource_urn in spec.context.graph.anchors"})
		}
		if !containsString(rule.Spec.Evidence.FingerprintFields, "resource_urn") {
			issues = append(issues, issue{path: rule.RelPath, message: "graph-backed policy must include resource_urn in spec.evidence.fingerprintFields"})
		}
	}
	return issues
}

func validateGraphPolicyAssetColumns(rule findingdsl.PolicyFindingRule) []issue {
	var issues []issue
	for _, column := range requiredGraphAssetColumns {
		if containsString(rule.Spec.Graph.RequiredColumns, column) {
			continue
		}
		issues = append(issues, issue{path: rule.RelPath, message: fmt.Sprintf("graph-backed graph policy must include %q in spec.graph.requiredColumns", column)})
	}
	return issues
}

func validatePolicyAssetContractCatalog() []issue {
	projectedKinds := map[string]struct{}{}
	for _, kind := range sourceprojection.BuiltinRegistry().Kinds() {
		projectedKinds[kind] = struct{}{}
	}
	var issues []issue
	for resource, contract := range policyAssetContracts {
		if strings.TrimSpace(contract.EntityType) == "" {
			issues = append(issues, issue{path: "tools/catalogcheck/policy_asset_contract.go", message: fmt.Sprintf("policy asset contract %q missing entity type", resource)})
		}
		if len(contract.EventKinds) == 0 {
			issues = append(issues, issue{path: "tools/catalogcheck/policy_asset_contract.go", message: fmt.Sprintf("policy asset contract %q missing source event kinds", resource)})
		}
		for _, kind := range contract.EventKinds {
			if _, ok := projectedKinds[kind]; !ok {
				issues = append(issues, issue{path: "tools/catalogcheck/policy_asset_contract.go", message: fmt.Sprintf("policy asset contract %q event kind %q has no projector", resource, kind)})
			}
		}
	}
	return issues
}

func validatePolicyAssetEventKinds(path string, resource string, contract policyAssetContract, eventKinds []string) []issue {
	if !hasNonEmptyString(eventKinds) {
		return nil
	}
	for _, eventKind := range eventKinds {
		if containsString(contract.EventKinds, eventKind) {
			return nil
		}
	}
	return []issue{{
		path:    path,
		message: fmt.Sprintf("graph-backed policy resource %q must use a projected event kind from: %s", resource, strings.Join(contract.EventKinds, ", ")),
	}}
}

func hasNonEmptyString(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func policyRequiresGraphBackedAsset(rule findingdsl.PolicyFindingRule) bool {
	return containsString(rule.Metadata.Tags, "graph-backed") || strings.TrimSpace(rule.Spec.Graph.Query) != ""
}

func validateGraphBackedPolicyFixtures(rule findingdsl.PolicyFindingRule) []issue {
	hasFinding := false
	hasPass := false
	for _, fixture := range rule.Spec.Verification.Fixtures {
		switch strings.ToLower(strings.TrimSpace(fixture.Expect)) {
		case "finding":
			hasFinding = true
		case "pass":
			hasPass = true
		}
	}
	var issues []issue
	if !hasFinding {
		issues = append(issues, issue{path: rule.RelPath, message: "graph-backed policy verification fixtures must include an expect=finding case"})
	}
	if !hasPass {
		issues = append(issues, issue{path: rule.RelPath, message: "graph-backed policy verification fixtures must include an expect=pass case"})
	}
	return issues
}

func validatePolicyAssetFields(path string, resource string, contract policyAssetContract, fields []string, location string) []issue {
	var issues []issue
	for _, field := range fields {
		if policyAssetContractAllowsField(contract, field) {
			continue
		}
		issues = append(issues, issue{path: path, message: fmt.Sprintf("%s references %q, but graph-backed resource %q only supports projected asset fields: %s", location, field, resource, strings.Join(contract.Fields, ", "))})
	}
	return issues
}

func policyAssetContractAllowsField(contract policyAssetContract, field string) bool {
	field = strings.TrimSpace(field)
	if field == "" {
		return true
	}
	for _, allowed := range contract.Fields {
		if field == allowed || strings.HasPrefix(field, allowed+".") {
			return true
		}
	}
	return false
}

func policyRuleAssertFields(assert findingdsl.PolicyRuleAssert) []string {
	seen := map[string]struct{}{}
	for _, assertions := range [][]findingdsl.PolicyRuleAssertion{assert.All, assert.Any} {
		for _, assertion := range assertions {
			field := strings.TrimSpace(assertion.Field)
			if field == "" {
				continue
			}
			seen[field] = struct{}{}
		}
	}
	fields := make([]string, 0, len(seen))
	for field := range seen {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
