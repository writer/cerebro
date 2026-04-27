package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type githubAuditSignalPredicate func(map[string]string) bool
type githubAuditSignalRenderer func(map[string]string) string

type githubAuditSignalConfig struct {
	definition RuleDefinition
	actions    map[string]struct{}
	predicate  githubAuditSignalPredicate
	severity   githubAuditSignalRenderer
	summary    githubAuditSignalRenderer
	policyID   githubAuditSignalRenderer
	checkID    string
	checkName  string
}

const (
	githubSecretScanningDisabledRuleID          = "github-secret-scanning-disabled"
	githubPushProtectionDisabledRuleID          = "github-push-protection-disabled"
	githubBranchProtectionDisabledRuleID        = "github-branch-protection-disabled"
	githubRepositoryMadePublicRuleID            = "github-repository-made-public"
	githubSecretScanningAlertCreatedRuleID      = "github-secret-scanning-alert-created"
	githubSelfHostedRunnerChangeRuleID          = "github-self-hosted-runner-change"
	githubRepositoryCollaboratorAddedRuleID     = "github-repository-collaborator-added"
	githubOrganizationOwnerAddedRuleID          = "github-organization-owner-added"
	githubCodeSecurityControlsDisabledRuleID    = "github-code-security-controls-disabled"
	githubOrgAuthControlModifiedRuleID          = "github-org-auth-control-modified"
	githubOrgIPAllowListModifiedRuleID          = "github-org-ip-allow-list-modified"
	githubAppIntegrationInstalledRuleID         = "github-app-integration-installed"
	githubPersonalAccessTokenCreatedRuleID      = "github-personal-access-token-created"
	githubProtectedBranchPolicyOverrideRuleID   = "github-protected-branch-policy-override"
	githubRepositoryRulesetModifiedRuleID       = "github-repository-ruleset-modified"
	githubCriticalResourceDeletedRuleID         = "github-critical-resource-deleted"
	githubWebhookModifiedRuleID                 = "github-webhook-modified"
	githubPrivateRepositoryForkingEnabledRuleID = "github-private-repository-forking-enabled"
)

var githubAuditControlRefs = []ports.FindingControlRef{
	{
		FrameworkName: "SOC 2",
		ControlID:     "CC6.6",
	},
	{
		FrameworkName: "ISO 27001:2022",
		ControlID:     "A.8.9",
	},
}

var githubAuditSignalKindMatcher = eventKindMatcher("github.audit")

var githubSecretScanningDisabledDefinition = RuleDefinition{
	ID:                 githubSecretScanningDisabledRuleID,
	Name:               "GitHub Secret Scanning Disabled",
	Description:        "Detect GitHub audit events where secret scanning is disabled for an enterprise, organization, or repository.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_secret_scanning_disabled",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "secret-scanning", "defense-evasion", "attack.t1562.001"},
	References:         []string{"https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_secret_scanning_feature_disabled.yml", "https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_secret_scanning_disabled.toml"},
	FalsePositives:     []string{"Approved repository migration or temporary maintenance by authorized administrators."},
	Runbook:            "Verify the actor and change request, re-enable secret scanning and push protection, then review commits and workflow runs during the exposure window.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"repo", "resource_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubPushProtectionDisabledDefinition = RuleDefinition{
	ID:                 githubPushProtectionDisabledRuleID,
	Name:               "GitHub Push Protection Disabled",
	Description:        "Detect GitHub audit events where secret scanning push protection is disabled.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_push_protection_disabled",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "push-protection", "secret-scanning", "defense-evasion", "attack.t1562.001"},
	References:         []string{"https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_push_protection_disabled.yml"},
	FalsePositives:     []string{"Approved administrative testing or controlled rollout changes."},
	Runbook:            "Confirm whether push protection was intentionally disabled; re-enable enforcement and inspect nearby pushes for exposed credentials.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"repo", "resource_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubBranchProtectionDisabledDefinition = RuleDefinition{
	ID:                 githubBranchProtectionDisabledRuleID,
	Name:               "GitHub Branch Protection Disabled",
	Description:        "Detect removal of GitHub protected branch rules.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_branch_protection_disabled",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "branch-protection", "supply-chain", "initial-access", "attack.t1195"},
	References:         []string{"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_branch_protection_disabled.yml"},
	FalsePositives:     []string{"Approved repository administration during migration or branch policy redesign."},
	Runbook:            "Validate the actor and ticket, restore branch protections, and review protected-branch pushes or force-push attempts after the change.",
	RequiredAttributes: []string{"action", "repo"},
	FingerprintFields:  []string{"repo", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubRepositoryMadePublicDefinition = RuleDefinition{
	ID:                 githubRepositoryMadePublicRuleID,
	Name:               "GitHub Repository Made Public",
	Description:        "Detect private GitHub repositories changed to public visibility.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_repository_made_public",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "repository", "exfiltration", "impact", "attack.t1567.001"},
	References:         []string{"https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_private_repository_turned_public.toml"},
	FalsePositives:     []string{"Approved open-source release of a sanitized repository."},
	Runbook:            "Confirm the visibility change, revert if unauthorized, enumerate forks/downloads, and rotate secrets exposed in repository history.",
	RequiredAttributes: []string{"action", "repo", "previous_visibility", "visibility"},
	FingerprintFields:  []string{"repo", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubSecretScanningAlertCreatedDefinition = RuleDefinition{
	ID:                 githubSecretScanningAlertCreatedRuleID,
	Name:               "GitHub Secret Scanning Alert Created",
	Description:        "Detect GitHub audit events indicating a new secret scanning alert.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_secret_scanning_alert_created",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "secret-scanning", "credential-access", "attack.t1552"},
	References:         []string{"https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_secret_scanning_alert_created.yml"},
	FalsePositives:     []string{"Canary tokens or expected test secrets in controlled repositories."},
	Runbook:            "Review the alert, revoke or rotate the exposed credential, and inspect commits, artifacts, and workflow logs for further exposure.",
	RequiredAttributes: []string{"action", "repo", "number"},
	FingerprintFields:  []string{"repo", "number"},
	ControlRefs:        githubAuditControlRefs,
}

var githubSelfHostedRunnerChangeDefinition = RuleDefinition{
	ID:                 githubSelfHostedRunnerChangeRuleID,
	Name:               "GitHub Self-Hosted Runner Change",
	Description:        "Detect GitHub audit events that register or modify self-hosted runner configuration.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_self_hosted_runner_change",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "actions", "self-hosted-runner", "supply-chain", "attack.t1195"},
	References:         []string{"https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_self_hosted_runner_changes_detected.yml", "https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/initial_access_github_register_self_hosted_runner.toml"},
	FalsePositives:     []string{"Approved runner maintenance, ephemeral runner churn, or expected runner group administration."},
	Runbook:            "Validate the runner owner and host, inspect recent workflows assigned to it, and isolate the runner if authorization is unclear.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"repo", "resource_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubRepositoryCollaboratorAddedDefinition = RuleDefinition{
	ID:                 githubRepositoryCollaboratorAddedRuleID,
	Name:               "GitHub Repository Collaborator Added",
	Description:        "Detect users added as collaborators to GitHub repositories.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_repository_collaborator_added",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "collaborator", "supply-chain", "initial-access", "attack.t1195"},
	References:         []string{"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_repo_collaborator_change.yml"},
	FalsePositives:     []string{"Expected onboarding or approved repository access change."},
	Runbook:            "Confirm the collaborator is authorized, review their repository permissions, and inspect immediate repository activity after access was granted.",
	RequiredAttributes: []string{"action", "repo", "user"},
	FingerprintFields:  []string{"repo", "user", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubOrganizationOwnerAddedDefinition = RuleDefinition{
	ID:                 githubOrganizationOwnerAddedRuleID,
	Name:               "GitHub Organization Owner Added",
	Description:        "Detect new GitHub organization members added with owner/admin privileges.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_organization_owner_added",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "organization-owner", "persistence", "privilege-escalation", "attack.t1098.003"},
	References:         []string{"https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/persistence_github_org_owner_added.toml"},
	FalsePositives:     []string{"Approved organization owner onboarding or break-glass access grant."},
	Runbook:            "Validate the new owner, revoke unauthorized access immediately, review owner activity, and require MFA/SSO re-verification.",
	RequiredAttributes: []string{"action", "user", "permission"},
	FingerprintFields:  []string{"org", "user", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubCodeSecurityControlsDisabledDefinition = RuleDefinition{
	ID:                 githubCodeSecurityControlsDisabledRuleID,
	Name:               "GitHub Code Security Controls Disabled",
	Description:        "Detect GitHub audit events where Dependabot, vulnerability alerts, or GitHub Advanced Security controls are disabled.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_code_security_controls_disabled",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "advanced-security", "dependabot", "defense-evasion", "supply-chain", "attack.t1562"},
	References:         []string{"https://docs.github.com/en/code-security/getting-started/github-security-features", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_advanced_security_change.yml", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_disabled_outdated_dependency_or_vulnerability.yml"},
	FalsePositives:     []string{"Approved security control migration or temporary configuration rollback by authorized administrators."},
	Runbook:            "Confirm authorization, re-enable code security controls, review package and secret exposure during the disabled window, and inspect adjacent repository changes by the actor.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"repo", "resource_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubOrgAuthControlModifiedDefinition = RuleDefinition{
	ID:                 githubOrgAuthControlModifiedRuleID,
	Name:               "GitHub Organization Authentication Control Modified",
	Description:        "Detect GitHub organization authentication control changes including SAML, 2FA, and OAuth app restrictions.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_org_auth_control_modified",
	Severity:           "CRITICAL",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "organization", "authentication", "persistence", "privilege-escalation", "defense-evasion", "attack.t1098"},
	References:         []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_org_auth_modified.yml"},
	FalsePositives:     []string{"Planned identity provider migration or approved organization security policy update."},
	Runbook:            "Verify the owner action, review organization membership and token activity around the change, and restore SAML/2FA/OAuth restrictions if unauthorized.",
	RequiredAttributes: []string{"action", "org"},
	FingerprintFields:  []string{"org", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubOrgIPAllowListModifiedDefinition = RuleDefinition{
	ID:                 githubOrgIPAllowListModifiedRuleID,
	Name:               "GitHub Organization IP Allow List Modified",
	Description:        "Detect GitHub organization IP allow list changes.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_org_ip_allow_list_modified",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "ip-allow-list", "persistence", "account-manipulation", "attack.t1098"},
	References:         []string{"https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-allowed-ip-addresses-for-your-organization", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_org_ip_allowlist.yml"},
	FalsePositives:     []string{"Approved network perimeter update or corporate egress address rotation."},
	Runbook:            "Validate the IP allow list change, remove unauthorized CIDRs, and correlate actor access from newly allowed networks.",
	RequiredAttributes: []string{"action", "org"},
	FingerprintFields:  []string{"org", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubAppIntegrationInstalledDefinition = RuleDefinition{
	ID:                 githubAppIntegrationInstalledRuleID,
	Name:               "GitHub App Integration Installed",
	Description:        "Detect new GitHub App integration installations.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_app_integration_installed",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "github-app", "execution", "persistence", "attack.t1072", "attack.t1098"},
	References:         []string{"https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party", "https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/execution_new_github_app_installed.toml"},
	FalsePositives:     []string{"Approved GitHub App onboarding through standard change management."},
	Runbook:            "Review installer, app publisher, requested permissions, repository scope, and revoke unauthorized installations.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"org", "repo", "name", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubPersonalAccessTokenCreatedDefinition = RuleDefinition{
	ID:                 githubPersonalAccessTokenCreatedRuleID,
	Name:               "GitHub Personal Access Token Created",
	Description:        "Detect creation or authorization of GitHub personal access tokens.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_personal_access_token_created",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "personal-access-token", "persistence", "credential-access", "attack.t1098.001", "attack.t1528"},
	References:         []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens", "https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/persistence_new_pat_created.toml"},
	FalsePositives:     []string{"Expected developer token creation following approved access request."},
	Runbook:            "Verify token owner, scopes, and source IP; revoke suspicious tokens and review git/API activity after creation.",
	RequiredAttributes: []string{"action", "operation_type", "user"},
	FingerprintFields:  []string{"user", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubProtectedBranchPolicyOverrideDefinition = RuleDefinition{
	ID:                 githubProtectedBranchPolicyOverrideRuleID,
	Name:               "GitHub Protected Branch Policy Override",
	Description:        "Detect GitHub protected branch policy overrides.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_protected_branch_policy_override",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "branch-protection", "policy-override", "supply-chain", "impact", "attack.t1195"},
	References:         []string{"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_branch_policy_override.yml"},
	FalsePositives:     []string{"Emergency production fix by authorized repository administrator."},
	Runbook:            "Validate override approval, inspect commits or force-pushes made under the override, and restore protections.",
	RequiredAttributes: []string{"action", "repo"},
	FingerprintFields:  []string{"repo", "branch", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubRepositoryRulesetModifiedDefinition = RuleDefinition{
	ID:                 githubRepositoryRulesetModifiedRuleID,
	Name:               "GitHub Repository Ruleset Modified",
	Description:        "Detect destructive or weakening changes to GitHub repository rulesets.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_repository_ruleset_modified",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "ruleset", "branch-protection", "defense-evasion", "attack.t1562"},
	References:         []string{"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_repo_ruleset_modified.yml"},
	FalsePositives:     []string{"Approved repository governance migration or ruleset tuning."},
	Runbook:            "Review changed ruleset enforcement and bypass actors, restore required checks/reviews, and inspect protected branch activity.",
	RequiredAttributes: []string{"action", "repo"},
	FingerprintFields:  []string{"repo", "ruleset_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubCriticalResourceDeletedDefinition = RuleDefinition{
	ID:                 githubCriticalResourceDeletedRuleID,
	Name:               "GitHub Critical Resource Deleted",
	Description:        "Detect deletion of critical GitHub resources such as repositories, environments, projects, or codespaces.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_critical_resource_deleted",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "destructive-action", "impact", "attack.t1485"},
	References:         []string{"https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_delete_action_invoked.yml", "https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_github_repository_deleted.toml"},
	FalsePositives:     []string{"Approved repository or environment decommissioning."},
	Runbook:            "Validate the deletion, recover the resource if unauthorized, and review actor access plus adjacent destructive events.",
	RequiredAttributes: []string{"action"},
	FingerprintFields:  []string{"repo", "resource_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubWebhookModifiedDefinition = RuleDefinition{
	ID:                 githubWebhookModifiedRuleID,
	Name:               "GitHub Webhook Modified",
	Description:        "Detect GitHub webhook creation, deletion, or configuration changes.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_webhook_modified",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "webhook", "exfiltration", "attack.t1020"},
	References:         []string{"https://docs.github.com/en/webhooks", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_webhook_modified.yml"},
	FalsePositives:     []string{"Approved integration onboarding or webhook maintenance."},
	Runbook:            "Verify webhook destination and events, remove unauthorized hooks, and rotate secrets if repository data may have been sent externally.",
	RequiredAttributes: []string{"action", "repo"},
	FingerprintFields:  []string{"repo", "hook_id", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubPrivateRepositoryForkingEnabledDefinition = RuleDefinition{
	ID:                 githubPrivateRepositoryForkingEnabledRuleID,
	Name:               "GitHub Private Repository Forking Enabled",
	Description:        "Detect GitHub private repository forking being enabled or reset.",
	SourceID:           "github",
	EventKinds:         []string{"github.audit"},
	OutputKind:         "finding.github_private_repository_forking_enabled",
	Severity:           "MEDIUM",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"github", "private-forking", "exfiltration", "attack.t1020"},
	References:         []string{"https://docs.github.com/en/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_fork_private_repos_enabled_or_cleared.yml"},
	FalsePositives:     []string{"Approved policy change to support internal development workflows."},
	Runbook:            "Validate forking policy approval, disable unauthorized private forking, and enumerate forks created after the policy change.",
	RequiredAttributes: []string{"action", "org"},
	FingerprintFields:  []string{"org", "repo", "action"},
	ControlRefs:        githubAuditControlRefs,
}

var githubSecretScanningDisabledConfig = githubAuditSignalConfig{
	definition: githubSecretScanningDisabledDefinition,
	actions: githubAuditActionSet(
		"business_secret_scanning.disable",
		"business_secret_scanning.disabled_for_new_repos",
		"repository_secret_scanning.disable",
		"secret_scanning_new_repos.disable",
		"secret_scanning.disable",
	),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s disabled GitHub secret scanning for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubPushProtectionDisabledConfig = githubAuditSignalConfig{
	definition: githubPushProtectionDisabledDefinition,
	actions: githubAuditActionSet(
		"business_secret_scanning_custom_pattern_push_protection.disabled",
		"business_secret_scanning_push_protection.disable",
		"business_secret_scanning_push_protection.disabled_for_new_repos",
		"org.secret_scanning_custom_pattern_push_protection_disabled",
		"org.secret_scanning_push_protection_disable",
		"org.secret_scanning_push_protection_new_repos_disable",
		"repository_secret_scanning_custom_pattern_push_protection.disabled",
	),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s disabled GitHub push protection for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubBranchProtectionDisabledConfig = githubAuditSignalConfig{
	definition: githubBranchProtectionDisabledDefinition,
	actions:    githubAuditActionSet("protected_branch.destroy"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s removed branch protection from %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubRepositoryMadePublicConfig = githubAuditSignalConfig{
	definition: githubRepositoryMadePublicDefinition,
	actions:    githubAuditActionSet("repo.access"),
	predicate: func(attributes map[string]string) bool {
		return strings.EqualFold(attributes["previous_visibility"], "private") &&
			strings.EqualFold(attributes["visibility"], "public")
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s changed %s visibility from private to public", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubSecretScanningAlertCreatedConfig = githubAuditSignalConfig{
	definition: githubSecretScanningAlertCreatedDefinition,
	actions:    githubAuditActionSet("secret_scanning_alert.create"),
	policyID: func(attributes map[string]string) string {
		return "secret_scanning_alert:" + githubAuditTarget(attributes) + ":" + strings.TrimSpace(attributes["number"])
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("GitHub secret scanning alert #%s created for %s", strings.TrimSpace(attributes["number"]), githubAuditTarget(attributes))
	},
}

var githubSelfHostedRunnerChangeConfig = githubAuditSignalConfig{
	definition: githubSelfHostedRunnerChangeDefinition,
	actions: githubAuditActionSet(
		"enterprise.register_self_hosted_runner",
		"org.register_self_hosted_runner",
		"org.remove_self_hosted_runner",
		"org.runner_group_created",
		"org.runner_group_removed",
		"org.runner_group_runner_removed",
		"org.runner_group_runners_added",
		"org.runner_group_runners_updated",
		"org.runner_group_updated",
		"repo.register_self_hosted_runner",
		"repo.remove_self_hosted_runner",
	),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s changed self-hosted runner configuration for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubRepositoryCollaboratorAddedConfig = githubAuditSignalConfig{
	definition: githubRepositoryCollaboratorAddedDefinition,
	actions:    githubAuditActionSet("repo.add_member"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s was added to %s by %s", firstNonEmpty(attributes["user"], "unknown user"), githubAuditTarget(attributes), githubAuditActor(attributes))
	},
}

var githubOrganizationOwnerAddedConfig = githubAuditSignalConfig{
	definition: githubOrganizationOwnerAddedDefinition,
	actions:    githubAuditActionSet("org.add_member"),
	predicate: func(attributes map[string]string) bool {
		return strings.EqualFold(attributes["permission"], "admin") || strings.EqualFold(attributes["permission"], "owner")
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s was added as a GitHub organization owner by %s", firstNonEmpty(attributes["user"], "unknown user"), githubAuditActor(attributes))
	},
}

var githubCodeSecurityControlSeverities = map[string]string{
	"business_advanced_security.disabled":                    "CRITICAL",
	"business_advanced_security.disabled_for_new_repos":      "HIGH",
	"dependabot_alerts.disable":                              "CRITICAL",
	"dependabot_alerts_new_repos.disable":                    "HIGH",
	"dependabot_security_updates.disable":                    "CRITICAL",
	"dependabot_security_updates_new_repos.disable":          "HIGH",
	"org.advanced_security_disabled_for_new_repos":           "HIGH",
	"org.advanced_security_disabled_on_all_repos":            "CRITICAL",
	"org.advanced_security_policy_selected_member_disabled":  "HIGH",
	"repo.advanced_security_disabled":                        "CRITICAL",
	"repo.advanced_security_policy_selected_member_disabled": "HIGH",
	"repository_vulnerability_alerts.disable":                "HIGH",
}

var githubCodeSecurityControlsDisabledConfig = githubAuditSignalConfig{
	definition: githubCodeSecurityControlsDisabledDefinition,
	actions:    githubAuditActionSet(keysOfStringMap(githubCodeSecurityControlSeverities)...),
	severity: func(attributes map[string]string) string {
		return firstNonEmpty(githubCodeSecurityControlSeverities[strings.TrimSpace(attributes["action"])], "HIGH")
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s disabled GitHub code security control %s for %s", githubAuditActor(attributes), strings.TrimSpace(attributes["action"]), githubAuditTarget(attributes))
	},
}

var githubOrgAuthControlModifiedConfig = githubAuditSignalConfig{
	definition: githubOrgAuthControlModifiedDefinition,
	actions: githubAuditActionSet(
		"org.disable_oauth_app_restrictions",
		"org.disable_two_factor_requirement",
		"org.enable_oauth_app_restrictions",
		"org.enable_two_factor_requirement",
		"org.saml_disabled",
		"org.saml_enabled",
		"org.update_saml_provider_settings",
	),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub organization authentication control %s for %s", githubAuditActor(attributes), strings.TrimSpace(attributes["action"]), githubAuditTarget(attributes))
	},
}

var githubOrgIPAllowListModifiedConfig = githubAuditSignalConfig{
	definition: githubOrgIPAllowListModifiedDefinition,
	actions: githubAuditActionSet(
		"ip_allow_list.disable",
		"ip_allow_list.disable_for_installed_apps",
		"ip_allow_list.enable",
		"ip_allow_list.enable_for_installed_apps",
		"ip_allow_list_entry.create",
		"ip_allow_list_entry.destroy",
		"ip_allow_list_entry.update",
	),
	severity: func(attributes map[string]string) string {
		if strings.Contains(strings.TrimSpace(attributes["action"]), "disable") || strings.Contains(strings.TrimSpace(attributes["action"]), "destroy") {
			return "HIGH"
		}
		return "MEDIUM"
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub organization IP allow list for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

var githubAppIntegrationInstalledConfig = githubAuditSignalConfig{
	definition: githubAppIntegrationInstalledDefinition,
	actions:    githubAuditActionSet("integration_installation.create"),
	policyID: func(attributes map[string]string) string {
		if name := strings.TrimSpace(attributes["name"]); name != "" {
			return "github_app:" + name
		}
		return ""
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s installed GitHub App integration %s for %s", githubAuditActor(attributes), firstNonEmpty(attributes["name"], "unknown app"), githubAuditTarget(attributes))
	},
}

var githubPersonalAccessTokenCreatedConfig = githubAuditSignalConfig{
	definition: githubPersonalAccessTokenCreatedDefinition,
	actions:    githubAuditActionSet("personal_access_token.access_granted"),
	predicate: func(attributes map[string]string) bool {
		return strings.EqualFold(attributes["operation_type"], "create")
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s created or authorized a GitHub personal access token for %s", githubAuditActor(attributes), firstNonEmpty(attributes["user"], "unknown user"))
	},
}

var githubProtectedBranchPolicyOverrideConfig = githubAuditSignalConfig{
	definition: githubProtectedBranchPolicyOverrideDefinition,
	actions:    githubAuditActionSet("protected_branch.policy_override"),
	summary: func(attributes map[string]string) string {
		branch := firstNonEmpty(attributes["branch"], "protected branch")
		return fmt.Sprintf("%s overrode GitHub branch policy %s for %s", githubAuditActor(attributes), branch, githubAuditTarget(attributes))
	},
}

var githubRepositoryRulesetModifiedConfig = githubAuditSignalConfig{
	definition: githubRepositoryRulesetModifiedDefinition,
	actions:    githubAuditActionSet("repository_ruleset.destroy", "repository_ruleset.update"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub repository ruleset %s for %s", githubAuditActor(attributes), firstNonEmpty(attributes["ruleset_name"], attributes["ruleset_id"], "unknown ruleset"), githubAuditTarget(attributes))
	},
}

var githubCriticalResourceDeletedConfig = githubAuditSignalConfig{
	definition: githubCriticalResourceDeletedDefinition,
	actions:    githubAuditActionSet("codespaces.delete", "environment.delete", "project.delete", "repo.destroy"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s deleted GitHub resource %s for %s", githubAuditActor(attributes), strings.TrimSpace(attributes["action"]), githubAuditTarget(attributes))
	},
}

var githubWebhookModifiedConfig = githubAuditSignalConfig{
	definition: githubWebhookModifiedDefinition,
	actions:    githubAuditActionSet("hook.config_changed", "hook.create", "hook.destroy"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub webhook %s for %s", githubAuditActor(attributes), firstNonEmpty(attributes["hook_id"], "unknown hook"), githubAuditTarget(attributes))
	},
}

var githubPrivateRepositoryForkingEnabledConfig = githubAuditSignalConfig{
	definition: githubPrivateRepositoryForkingEnabledDefinition,
	actions:    githubAuditActionSet("private_repository_forking.clear", "private_repository_forking.enable"),
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s enabled or reset private repository forking for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

func newGitHubSecretScanningDisabledRule() Rule {
	return newGitHubAuditSignalRule(githubSecretScanningDisabledConfig)
}

func newGitHubPushProtectionDisabledRule() Rule {
	return newGitHubAuditSignalRule(githubPushProtectionDisabledConfig)
}

func newGitHubBranchProtectionDisabledRule() Rule {
	return newGitHubAuditSignalRule(githubBranchProtectionDisabledConfig)
}

func newGitHubRepositoryMadePublicRule() Rule {
	return newGitHubAuditSignalRule(githubRepositoryMadePublicConfig)
}

func newGitHubSecretScanningAlertCreatedRule() Rule {
	return newGitHubAuditSignalRule(githubSecretScanningAlertCreatedConfig)
}

func newGitHubSelfHostedRunnerChangeRule() Rule {
	return newGitHubAuditSignalRule(githubSelfHostedRunnerChangeConfig)
}

func newGitHubRepositoryCollaboratorAddedRule() Rule {
	return newGitHubAuditSignalRule(githubRepositoryCollaboratorAddedConfig)
}

func newGitHubOrganizationOwnerAddedRule() Rule {
	return newGitHubAuditSignalRule(githubOrganizationOwnerAddedConfig)
}

func newGitHubCodeSecurityControlsDisabledRule() Rule {
	return newGitHubAuditSignalRule(githubCodeSecurityControlsDisabledConfig)
}

func newGitHubOrgAuthControlModifiedRule() Rule {
	return newGitHubAuditSignalRule(githubOrgAuthControlModifiedConfig)
}

func newGitHubOrgIPAllowListModifiedRule() Rule {
	return newGitHubAuditSignalRule(githubOrgIPAllowListModifiedConfig)
}

func newGitHubAppIntegrationInstalledRule() Rule {
	return newGitHubAuditSignalRule(githubAppIntegrationInstalledConfig)
}

func newGitHubPersonalAccessTokenCreatedRule() Rule {
	return newGitHubAuditSignalRule(githubPersonalAccessTokenCreatedConfig)
}

func newGitHubProtectedBranchPolicyOverrideRule() Rule {
	return newGitHubAuditSignalRule(githubProtectedBranchPolicyOverrideConfig)
}

func newGitHubRepositoryRulesetModifiedRule() Rule {
	return newGitHubAuditSignalRule(githubRepositoryRulesetModifiedConfig)
}

func newGitHubCriticalResourceDeletedRule() Rule {
	return newGitHubAuditSignalRule(githubCriticalResourceDeletedConfig)
}

func newGitHubWebhookModifiedRule() Rule {
	return newGitHubAuditSignalRule(githubWebhookModifiedConfig)
}

func newGitHubPrivateRepositoryForkingEnabledRule() Rule {
	return newGitHubAuditSignalRule(githubPrivateRepositoryForkingEnabledConfig)
}

func newGitHubAuditSignalRule(config githubAuditSignalConfig) Rule {
	return newEventRule(eventRuleConfig{
		definition: config.definition,
		match: func(event *cerebrov1.EventEnvelope) bool {
			if !githubAuditSignalKindMatcher(event) || !hasRequiredAttributes(event, config.definition.RequiredAttributes...) {
				return false
			}
			attributes := eventAttributes(event)
			if len(config.actions) != 0 {
				if _, ok := config.actions[strings.TrimSpace(attributes["action"])]; !ok {
					return false
				}
			}
			return config.predicate == nil || config.predicate(attributes)
		},
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return githubAuditSignalFinding(ctx, runtime, event, config)
		},
	})
}

func githubAuditSignalFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, config githubAuditSignalConfig) (*ports.FindingRecord, error) {
	resourceURNs, actorURN, resourceURN, _, _, err := projectedEntityContext(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	attributes := eventAttributes(event)
	findingAttributes := githubAuditSignalAttributes(event, config, actorURN, resourceURN)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	severity := config.definition.Severity
	if config.severity != nil {
		severity = config.severity(attributes)
	}
	policyID := ""
	if config.policyID != nil {
		policyID = config.policyID(attributes)
	}
	fingerprint := githubAuditSignalFingerprint(event, config.definition)
	checkID := firstNonEmpty(config.checkID, config.definition.ID)
	checkName := firstNonEmpty(config.checkName, config.definition.Name)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            config.definition.ID,
		Title:             config.definition.Name,
		Severity:          normalizeFindingSeverity(severity),
		Status:            config.definition.Status,
		Summary:           githubAuditSignalSummary(attributes, config),
		ResourceURNs:      resourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: githubObservedPolicyIDs(policyID),
		PolicyID:          policyID,
		PolicyName:        policyID,
		CheckID:           checkID,
		CheckName:         checkName,
		ControlRefs:       cloneFindingControlRefs(config.definition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func githubAuditSignalAttributes(event *cerebrov1.EventEnvelope, config githubAuditSignalConfig, actorURN string, resourceURN string) map[string]string {
	eventAttrs := eventAttributes(event)
	attributes := map[string]string{
		"action":               strings.TrimSpace(eventAttrs["action"]),
		"actor":                strings.TrimSpace(eventAttrs["actor"]),
		"branch":               strings.TrimSpace(eventAttrs["branch"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"hook_id":              strings.TrimSpace(eventAttrs["hook_id"]),
		"name":                 strings.TrimSpace(eventAttrs["name"]),
		"number":               strings.TrimSpace(eventAttrs["number"]),
		"operation_type":       strings.TrimSpace(eventAttrs["operation_type"]),
		"org":                  strings.TrimSpace(eventAttrs["org"]),
		"permission":           strings.TrimSpace(eventAttrs["permission"]),
		"previous_visibility":  strings.TrimSpace(eventAttrs["previous_visibility"]),
		"primary_actor_urn":    actorURN,
		"primary_resource_urn": resourceURN,
		"repo":                 strings.TrimSpace(eventAttrs["repo"]),
		"resource_id":          strings.TrimSpace(eventAttrs["resource_id"]),
		"resource_type":        strings.TrimSpace(eventAttrs["resource_type"]),
		"ruleset_id":           strings.TrimSpace(eventAttrs["ruleset_id"]),
		"ruleset_name":         strings.TrimSpace(eventAttrs["ruleset_name"]),
		"runner_group_name":    strings.TrimSpace(eventAttrs["runner_group_name"]),
		"source_runtime_id":    strings.TrimSpace(eventAttrs[ports.EventAttributeSourceRuntimeID]),
		"user":                 strings.TrimSpace(eventAttrs["user"]),
		"visibility":           strings.TrimSpace(eventAttrs["visibility"]),
	}
	for _, key := range config.definition.RequiredAttributes {
		attributes[key] = strings.TrimSpace(eventAttrs[key])
	}
	for key, value := range config.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func githubAuditSignalFingerprint(event *cerebrov1.EventEnvelope, definition RuleDefinition) string {
	attributes := eventAttributes(event)
	parts := []string{definition.ID}
	fields := definition.FingerprintFields
	if len(fields) == 0 {
		fields = []string{"event_id"}
	}
	for _, field := range fields {
		switch strings.TrimSpace(field) {
		case "event_id":
			parts = append(parts, event.GetId())
		default:
			parts = append(parts, attributes[field])
		}
	}
	return hashFindingFingerprint(parts...)
}

func githubAuditSignalSummary(attributes map[string]string, config githubAuditSignalConfig) string {
	if config.summary != nil {
		return config.summary(attributes)
	}
	return fmt.Sprintf("%s performed %s on %s", githubAuditActor(attributes), strings.TrimSpace(attributes["action"]), githubAuditTarget(attributes))
}

func githubAuditActor(attributes map[string]string) string {
	return firstNonEmpty(attributes["actor"], "unknown actor")
}

func githubAuditTarget(attributes map[string]string) string {
	return firstNonEmpty(attributes["repo"], attributes["resource_id"], attributes["org"], "unknown target")
}

func githubObservedPolicyIDs(policyID string) []string {
	if strings.TrimSpace(policyID) == "" {
		return nil
	}
	return []string{strings.TrimSpace(policyID)}
}

func githubAuditActionSet(actions ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if strings.TrimSpace(action) != "" {
			set[strings.TrimSpace(action)] = struct{}{}
		}
	}
	return set
}

func keysOfStringMap(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
