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
type githubAuditSignalFingerprintInputs func(*cerebrov1.EventEnvelope, RuleDefinition) []string

type githubAuditSignalConfig struct {
	definition        RuleDefinition
	actions           map[string]struct{}
	predicate         githubAuditSignalPredicate
	severity          githubAuditSignalRenderer
	summary           githubAuditSignalRenderer
	policyID          githubAuditSignalRenderer
	primaryEntityType githubAuditSignalRenderer
	fingerprint       githubAuditSignalFingerprintInputs
	checkID           string
	checkName         string
}

type githubAuditSignalClosePredicate func(Event) (string, bool)

type githubAuditCounterEventRule struct {
	Rule
	definition    RuleDefinition
	openAnchor    func(map[string]string) string
	closeAnchor   githubAuditSignalClosePredicate
	counterStates func(Event) []CounterEventStateUpdate
}

func newGitHubAggregateAuditCounterEventRule(config githubAuditSignalConfig, openAnchor func(map[string]string) string, closeAnchor githubAuditSignalClosePredicate, counterStates func(Event) []CounterEventStateUpdate) Rule {
	return &githubAuditCounterEventRule{
		Rule:          newGitHubAuditSignalRule(config),
		definition:    config.definition,
		openAnchor:    openAnchor,
		closeAnchor:   closeAnchor,
		counterStates: counterStates,
	}
}

func (r *githubAuditCounterEventRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *githubAuditCounterEventRule) OpenAnchor(attributes map[string]string) string {
	if r == nil || r.openAnchor == nil {
		return ""
	}
	return strings.TrimSpace(r.openAnchor(attributes))
}

func (r *githubAuditCounterEventRule) CloseOnEvent(event Event) (string, bool) {
	if r == nil || r.closeAnchor == nil {
		return "", false
	}
	anchor, closes := r.closeAnchor(event)
	anchor = strings.TrimSpace(anchor)
	if anchor == "" || !closes {
		return "", false
	}
	return anchor, true
}

func (r *githubAuditCounterEventRule) CounterEventStates(event Event) []CounterEventStateUpdate {
	if r == nil || r.counterStates == nil {
		return nil
	}
	return r.counterStates(event)
}

const (
	githubSecretScanningDisabledRuleID          = "github-secret-scanning-disabled" // #nosec G101 -- finding rule identifier, not a secret.
	githubPushProtectionDisabledRuleID          = "github-push-protection-disabled"
	githubBranchProtectionDisabledRuleID        = "github-branch-protection-disabled"
	githubRepositoryMadePublicRuleID            = "github-repository-made-public"
	githubSecretScanningAlertCreatedRuleID      = "github-secret-scanning-alert-created" // #nosec G101 -- finding rule identifier, not a secret.
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
	Description:        "Detect open GitHub secret scanning alerts replayed from GitHub audit events.",
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
	RequiredAttributes: []string{"action", "repo", "number", "secret_scanning_alert.state"},
	FingerprintFields:  []string{"repo", "number"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
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
	RequiredAttributes: []string{"scope", "runner_id"},
	FingerprintFields:  []string{"scope", "runner_id"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	FingerprintFields:  []string{"repo", "user"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"action", "org", "user", "permission"},
	FingerprintFields:  []string{"org", "user"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
}

var githubCodeSecurityControlsDisabledDefinition = RuleDefinition{
	ID:                githubCodeSecurityControlsDisabledRuleID,
	Name:              "GitHub Code Security Controls Disabled",
	Description:       "Detect GitHub audit events where Dependabot, vulnerability alerts, secret scanning, or GitHub Advanced Security controls are disabled.",
	SourceID:          "github",
	EventKinds:        []string{"github.audit"},
	OutputKind:        "finding.github_code_security_controls_disabled",
	Severity:          "HIGH",
	Status:            findingStatusOpen,
	Maturity:          "test",
	Tags:              []string{"github", "advanced-security", "dependabot", "secret-scanning", "defense-evasion", "supply-chain", "attack.t1562"},
	References:        []string{"https://docs.github.com/en/code-security/getting-started/github-security-features", "https://github.com/panther-labs/panther-analysis/blob/develop/rules/github_rules/github_advanced_security_change.yml", "https://github.com/SigmaHQ/sigma/blob/master/rules/application/github/audit/github_disabled_outdated_dependency_or_vulnerability.yml"},
	FalsePositives:    []string{"Approved security control migration or temporary configuration rollback by authorized administrators."},
	Runbook:           "Confirm authorization, re-enable code security controls, review package and secret exposure during the disabled window, and inspect adjacent repository changes by the actor.",
	FingerprintFields: []string{"repo", "org"},
	ControlRefs:       githubAuditControlRefs,
	Lifecycle:         Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"org"},
	FingerprintFields:  []string{"org"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"org"},
	FingerprintFields:  []string{"org"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"action", "github_app_id", "org"},
	FingerprintFields:  []string{"org", "github_app_id"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"action", "operation_type", "token_id", "user_id"},
	FingerprintFields:  []string{"user_id", "token_id"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"action", "repo", "ruleset_id"},
	FingerprintFields:  []string{"repo", "ruleset_id"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"action", "repo", "hook_id"},
	FingerprintFields:  []string{"repo", "hook_id"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
	RequiredAttributes: []string{"org"},
	FingerprintFields:  []string{"org", "repo"},
	ControlRefs:        githubAuditControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
}

// Note: retired GitHub audit-event mirror rules keep their RuleDefinition
// values above so the retirement wrapper can keep advertising the original
// output_kind, control refs, and references when the rule appears in the
// catalog. Their match configs were removed with the event-mirror logic.

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
	"repository_secret_scanning.disable":                     "HIGH",
	"repository_vulnerability_alerts.disable":                "HIGH",
	"org.secret_scanning_push_protection_disable":            "HIGH",
}

var githubCodeSecurityControlsDisabledConfig = githubAuditSignalConfig{
	definition:  githubCodeSecurityControlsDisabledDefinition,
	predicate:   githubCodeSecurityControlsPostureDisabledAtScopedAnchor,
	fingerprint: githubCodeSecurityControlsFingerprintInputs,
	primaryEntityType: func(attributes map[string]string) string {
		scope, _ := githubCodeSecurityControlsScope(attributes)
		if scope == "org" {
			return "github.org"
		}
		if scope == "repo" {
			return "github.code.repository"
		}
		return ""
	},
	severity: func(attributes map[string]string) string {
		return firstNonEmpty(githubCodeSecurityControlSeverities[strings.TrimSpace(attributes["action"])], "HIGH")
	},
	summary: func(attributes map[string]string) string {
		control := firstNonEmpty(strings.TrimSpace(attributes["action"]), strings.TrimSpace(attributes["disabled_controls"]), "code security control")
		return fmt.Sprintf("%s disabled GitHub code security control %s for %s", githubAuditActor(attributes), control, githubAuditTarget(attributes))
	},
}

// githubProtectedBranchPolicyOverrideConfig and the other retired mirror
// configs were removed with the per-event finding implementations; durable
// coverage lives in graph/current-state rules while retired wrappers keep
// stale findings resolvable.

// newGitHubSecretScanningDisabledRule is retired. The mirror produced one
// finding per audit event, which collapses repeated tampering on the same
// repo into noise instead of one durable "secret scanning disabled" finding
// keyed by repo. Posture coverage moves to a future graph rule over the
// projected `github.code.repository` entity. The wrapper stays registered so any open
// mirror findings are auto-resolved by the existing stale-finding sweep on
// the next replay.
func newGitHubSecretScanningDisabledRule() Rule {
	return newRetiredGitHubAuditRule(githubSecretScanningDisabledDefinition)
}

// newGitHubPushProtectionDisabledRule is retired. See
// `newGitHubSecretScanningDisabledRule` for the retirement rationale; the
// durable replacement is a graph rule over repos missing push protection.
func newGitHubPushProtectionDisabledRule() Rule {
	return newRetiredGitHubAuditRule(githubPushProtectionDisabledDefinition)
}

// newGitHubBranchProtectionDisabledRule is retired. The durable replacement
// is a graph rule that reports protected-branch coverage gaps over
// `github.code.repository` -> `github.branch` paths.
func newGitHubBranchProtectionDisabledRule() Rule {
	return newRetiredGitHubAuditRule(githubBranchProtectionDisabledDefinition)
}

// newGitHubRepositoryMadePublicRule is retired. The durable replacement is
// a graph rule reporting public repos that violate the org's visibility
// policy; the visibility-change audit event becomes evidence on that
// finding rather than an independent mirror finding.
func newGitHubRepositoryMadePublicRule() Rule {
	return newRetiredGitHubAuditRule(githubRepositoryMadePublicDefinition)
}

func newGitHubSecretScanningAlertCreatedRule() Rule {
	return &githubAuditCounterEventRule{
		Rule: newEventRule(eventRuleConfig{
			definition: githubSecretScanningAlertCreatedDefinition,
			match:      matchesGitHubSecretScanningOpenAlert,
			build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
				return githubSecretScanningAlertFinding(ctx, runtime, event)
			},
		}),
		definition:  githubSecretScanningAlertCreatedDefinition,
		openAnchor:  githubSecretScanningAlertAnchor,
		closeAnchor: githubSecretScanningAlertCloseAnchor,
	}
}

func newGitHubSelfHostedRunnerChangeRule() Rule {
	return newRetiredGitHubAuditRule(githubSelfHostedRunnerChangeDefinition)
}

func newGitHubRepositoryCollaboratorAddedRule() Rule {
	return newRetiredGitHubAuditRule(githubRepositoryCollaboratorAddedDefinition)
}

func newGitHubOrganizationOwnerAddedRule() Rule {
	return newRetiredGitHubAuditRule(githubOrganizationOwnerAddedDefinition)
}

func newGitHubCodeSecurityControlsDisabledRule() Rule {
	return newGitHubAggregateAuditCounterEventRule(githubCodeSecurityControlsDisabledConfig, githubCodeSecurityControlsAnchor, githubCodeSecurityControlsCloseAnchor, githubCodeSecurityControlsCounterEventStates)
}

func newGitHubOrgAuthControlModifiedRule() Rule {
	return newRetiredGitHubAuditRule(githubOrgAuthControlModifiedDefinition)
}

func newGitHubOrgIPAllowListModifiedRule() Rule {
	return newRetiredGitHubAuditRule(githubOrgIPAllowListModifiedDefinition)
}

func newGitHubAppIntegrationInstalledRule() Rule {
	return newRetiredGitHubAuditRule(githubAppIntegrationInstalledDefinition)
}

func newGitHubPersonalAccessTokenCreatedRule() Rule {
	return newRetiredGitHubAuditRule(githubPersonalAccessTokenCreatedDefinition)
}

// newGitHubProtectedBranchPolicyOverrideRule is retired. Per-event overrides
// turn into evidence on the durable "protected branch policy degraded"
// posture finding (future graph rule) rather than a standalone mirror
// finding per override event.
func newGitHubProtectedBranchPolicyOverrideRule() Rule {
	return newRetiredGitHubAuditRule(githubProtectedBranchPolicyOverrideDefinition)
}

func newGitHubRepositoryRulesetModifiedRule() Rule {
	return newRetiredGitHubAuditRule(githubRepositoryRulesetModifiedDefinition)
}

func newGitHubCriticalResourceDeletedRule() Rule {
	return newRetiredGitHubAuditRule(githubCriticalResourceDeletedDefinition)
}

func newGitHubWebhookModifiedRule() Rule {
	return newRetiredGitHubAuditRule(githubWebhookModifiedDefinition)
}

func newGitHubPrivateRepositoryForkingEnabledRule() Rule {
	return newRetiredGitHubAuditRule(githubPrivateRepositoryForkingEnabledDefinition)
}

func matchesGitHubSecretScanningOpenAlert(event *cerebrov1.EventEnvelope) bool {
	if !githubAuditSignalKindMatcher(event) {
		return false
	}
	attributes := eventAttributes(event)
	if !strings.HasPrefix(strings.TrimSpace(attributes["action"]), "secret_scanning_alert.") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(attributes["secret_scanning_alert.state"]), findingStatusOpen)
}

func githubSecretScanningAlertFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attributes := eventAttributes(event)
	repo := strings.TrimSpace(attributes["repo"])
	number := strings.TrimSpace(attributes["number"])
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryEntityType:  "github.secret_scanning_alert",
		CollectAllEntities: true,
		ResourceFallbacks:  []string{repo, number},
	})
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	alertURN := firstNonEmpty(githubProjectionURN(event.GetTenantId(), "github_secret_scanning_alert", repo, number), projectedContext.PrimaryResourceURN)
	repoURN := githubProjectionURN(event.GetTenantId(), "github_code_repository", repo)
	resourceURNs := deduplicateStrings(append(projectedContext.ResourceURNs, alertURN, repoURN))
	findingAttributes := githubSecretScanningAlertAttributes(event, alertURN)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	policyID := "secret_scanning_alert:" + repo + ":" + number
	fingerprint := hashFindingFingerprint(githubSecretScanningAlertCreatedRuleID, event.GetTenantId(), repo, number)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            githubSecretScanningAlertCreatedRuleID,
		Title:             githubSecretScanningAlertCreatedDefinition.Name,
		Severity:          normalizeFindingSeverity(githubSecretScanningAlertCreatedDefinition.Severity),
		Status:            githubSecretScanningAlertCreatedDefinition.Status,
		Summary:           githubSecretScanningAlertSummary(attributes),
		ResourceURNs:      resourceURNs,
		EventIDs:          githubSecretScanningAlertEventIDs(event),
		ObservedPolicyIDs: githubObservedPolicyIDs(policyID),
		PolicyID:          policyID,
		PolicyName:        policyID,
		CheckID:           githubSecretScanningAlertCreatedRuleID,
		CheckName:         githubSecretScanningAlertCreatedDefinition.Name,
		ControlRefs:       cloneFindingControlRefs(githubSecretScanningAlertCreatedDefinition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func githubSecretScanningAlertAttributes(event *cerebrov1.EventEnvelope, primaryResourceURN string) map[string]string {
	eventAttrs := eventAttributes(event)
	state := strings.TrimSpace(eventAttrs["secret_scanning_alert.state"])
	attributes := map[string]string{
		"audit_event_id":              strings.TrimSpace(eventAttrs["audit_event_id"]),
		"event_id":                    strings.TrimSpace(event.GetId()),
		"html_url":                    strings.TrimSpace(eventAttrs["html_url"]),
		"number":                      strings.TrimSpace(eventAttrs["number"]),
		"primary_resource_urn":        primaryResourceURN,
		"repo":                        strings.TrimSpace(eventAttrs["repo"]),
		"repository":                  strings.TrimSpace(eventAttrs["repo"]),
		"secret_type":                 strings.TrimSpace(eventAttrs["secret_type"]),
		"secret_type_display":         strings.TrimSpace(eventAttrs["secret_type_display"]),
		"secret_scanning_alert.state": state,
		"source_runtime_id":           strings.TrimSpace(eventAttrs[ports.EventAttributeSourceRuntimeID]),
		"state":                       state,
		"tenant_id":                   strings.TrimSpace(event.GetTenantId()),
	}
	for key, value := range githubSecretScanningAlertCreatedDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func githubSecretScanningAlertEventIDs(event *cerebrov1.EventEnvelope) []string {
	attributes := eventAttributes(event)
	eventIDs := []string{strings.TrimSpace(event.GetId())}
	for _, key := range []string{"audit_event_id", "audit_event_ids"} {
		for _, value := range strings.Split(attributes[key], ",") {
			eventIDs = append(eventIDs, strings.TrimSpace(value))
		}
	}
	return deduplicateStrings(eventIDs)
}

func githubSecretScanningAlertSummary(attributes map[string]string) string {
	return fmt.Sprintf("GitHub secret scanning alert #%s is open for %s", strings.TrimSpace(attributes["number"]), githubAuditTarget(attributes))
}

func githubProjectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := []string{"urn", "cerebro", tenant, entityKind}
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return strings.Join(values, ":")
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
	attributes := eventAttributes(event)
	fingerprint := githubAuditSignalFingerprint(event, config)
	if fingerprint == nil {
		return nil, nil
	}
	primaryEntityType := ""
	if config.primaryEntityType != nil {
		primaryEntityType = strings.TrimSpace(config.primaryEntityType(attributes))
	}
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"acted_on"},
		PrimaryEntityType:  primaryEntityType,
		CollectAllLinkURNs: true,
		ActorFallbacks: []string{
			event.GetAttributes()["actor"],
			event.GetAttributes()["user"],
		},
		ResourceFallbacks: []string{
			event.GetAttributes()["repo"],
			event.GetAttributes()["resource_id"],
			event.GetAttributes()["resource_type"],
		},
	})
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	if projectedContext.PrimaryResourceURN != "" {
		projectedContext.ResourceURNs = deduplicateStrings(append(projectedContext.ResourceURNs, projectedContext.PrimaryResourceURN))
	}
	findingAttributes := githubAuditSignalAttributes(event, config, projectedContext.PrimaryActorURN, projectedContext.PrimaryResourceURN)
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
	checkID := firstNonEmpty(config.checkID, config.definition.ID)
	checkName := firstNonEmpty(config.checkName, config.definition.Name)
	return &ports.FindingRecord{
		ID:                *fingerprint,
		Fingerprint:       *fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            config.definition.ID,
		Title:             config.definition.Name,
		Severity:          normalizeFindingSeverity(severity),
		Status:            config.definition.Status,
		Summary:           githubAuditSignalSummary(attributes, config),
		ResourceURNs:      projectedContext.ResourceURNs,
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
		"runner_ephemeral":     strings.TrimSpace(firstNonEmpty(eventAttrs["runner_ephemeral"], eventAttrs["ephemeral"], eventAttrs["is_ephemeral"])),
		"ruleset_id":           strings.TrimSpace(eventAttrs["ruleset_id"]),
		"ruleset_name":         strings.TrimSpace(eventAttrs["ruleset_name"]),
		"runner_group_name":    strings.TrimSpace(eventAttrs["runner_group_name"]),
		"runner_id":            strings.TrimSpace(eventAttrs["runner_id"]),
		"runner_name":          strings.TrimSpace(eventAttrs["runner_name"]),
		"runner_registered":    strings.TrimSpace(firstNonEmpty(eventAttrs["runner_registered"], eventAttrs["registered"], eventAttrs["is_registered"])),
		"source_runtime_id":    strings.TrimSpace(eventAttrs[ports.EventAttributeSourceRuntimeID]),
		"tenant_id":            strings.TrimSpace(event.GetTenantId()),
		"user":                 strings.TrimSpace(eventAttrs["user"]),
		"visibility":           strings.TrimSpace(eventAttrs["visibility"]),
	}
	for _, key := range githubPostureAttributeKeys {
		attributes[key] = strings.TrimSpace(eventAttrs[key])
	}
	if disabledControls := strings.Join(githubDisabledCodeSecurityControls(eventAttrs), ","); disabledControls != "" {
		attributes["disabled_controls"] = disabledControls
	}
	if weakenedControls := strings.Join(githubWeakenedAuthControls(eventAttrs), ","); weakenedControls != "" {
		attributes["weakened_auth_controls"] = weakenedControls
	}
	if scope, scopeID := githubPrivateRepositoryForkingScope(eventAttrs); scopeID != "" {
		attributes["posture_scope"] = scope
		attributes["posture_scope_id"] = scopeID
	}
	if scopeType, scopeID := githubSelfHostedRunnerScope(eventAttrs); scopeID != "" {
		attributes["scope"] = scopeID
		attributes["runner_scope"] = scopeID
		attributes["runner_scope_type"] = scopeType
	}
	for _, key := range config.definition.RequiredAttributes {
		if value := strings.TrimSpace(eventAttrs[key]); value != "" {
			attributes[key] = value
		}
	}
	for key, value := range config.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func githubAuditSignalFingerprint(event *cerebrov1.EventEnvelope, config githubAuditSignalConfig) *string {
	definition := config.definition
	if !hasRequiredAttributes(event, definition.RequiredAttributes...) {
		return nil
	}
	parts := []string{definition.ID, strings.TrimSpace(event.GetTenantId())}
	if config.fingerprint != nil {
		inputs := config.fingerprint(event, definition)
		if len(inputs) == 0 {
			return nil
		}
		for _, input := range inputs {
			if strings.TrimSpace(input) == "" {
				return nil
			}
			parts = append(parts, input)
		}
		fingerprint := hashFindingFingerprint(parts...)
		return &fingerprint
	}
	fields := definition.FingerprintFields
	if len(fields) == 0 {
		fields = []string{"event_id"}
	}
	for _, field := range fields {
		value := githubAuditSignalFingerprintFieldValue(event, field)
		if value == "" {
			return nil
		}
		parts = append(parts, value)
	}
	fingerprint := hashFindingFingerprint(parts...)
	return &fingerprint
}

func githubAuditSignalFingerprintFieldValue(event *cerebrov1.EventEnvelope, field string) string {
	normalizedField := strings.TrimSpace(field)
	if normalizedField == "" {
		return ""
	}
	return requiredAttributeValue(event, normalizedField)
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

func githubCounterEventAnchor(attributes map[string]string, fields ...string) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			return ""
		}
		value := strings.TrimSpace(attributes[field])
		if value == "" {
			return ""
		}
		parts = append(parts, field+"="+value)
	}
	return strings.Join(parts, "|")
}

func githubSecretScanningAlertAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "repo", "number")
}

func githubSecretScanningAlertCloseAnchor(event Event) (string, bool) {
	if !githubAuditSignalKindMatcher(event) {
		return "", false
	}
	attributes := eventAttributes(event)
	switch strings.TrimSpace(attributes["action"]) {
	case "secret_scanning_alert.resolve", "secret_scanning_alert.revoke", "secret_scanning_alert.false_positive":
		switch strings.ToLower(strings.TrimSpace(attributes["secret_scanning_alert.state"])) {
		case "resolved", "revoked", "false_positive":
			return githubSecretScanningAlertAnchor(attributes), true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func githubCodeSecurityControlsAnchor(attributes map[string]string) string {
	scope, scopeID := githubCodeSecurityControlsScope(attributes)
	if scope == "" || scopeID == "" {
		return ""
	}
	return githubCounterEventAnchor(map[string]string{scope: scopeID}, scope)
}

func githubCodeSecurityControlsFingerprintInputs(event *cerebrov1.EventEnvelope, _ RuleDefinition) []string {
	_, scopeID := githubCodeSecurityControlsScope(eventAttributes(event))
	if scopeID == "" {
		return nil
	}
	return []string{scopeID}
}

func githubCodeSecurityControlsPostureDisabledAtScopedAnchor(attributes map[string]string) bool {
	_, scopeID := githubCodeSecurityControlsScope(attributes)
	return scopeID != "" && githubCodeSecurityControlsPostureDisabled(attributes)
}

func githubCodeSecurityControlsScope(attributes map[string]string) (string, string) {
	explicitScope := strings.ToLower(strings.TrimSpace(attributes["scope"]))
	switch explicitScope {
	case "repo", "repository":
		repo := strings.TrimSpace(firstNonEmpty(attributes["repo"], attributes["repository"]))
		if repo == "" {
			return "", ""
		}
		return "repo", repo
	case "org", "organization":
		org := strings.TrimSpace(firstNonEmpty(attributes["org"], attributes["organization"]))
		if org == "" {
			return "", ""
		}
		return "org", org
	}
	if repo := strings.TrimSpace(firstNonEmpty(attributes["repo"], attributes["repository"])); repo != "" {
		return "repo", repo
	}
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.ToLower(strings.TrimSpace(attributes["resource_type"]))
	if strings.Contains(resourceID, "/") || strings.Contains(resourceType, "repo") {
		return "", ""
	}
	if org := strings.TrimSpace(firstNonEmpty(attributes["org"], attributes["organization"])); org != "" {
		return "org", org
	}
	return "", ""
}

func githubCodeSecurityControlsCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !githubCodeSecurityControlsRestored(attributes) {
		return "", false
	}
	return githubCodeSecurityControlsAnchor(attributes), true
}

func githubCodeSecurityControlsRestored(attributes map[string]string) bool {
	if githubCodeSecurityControlsPostureDisabled(attributes) {
		return false
	}
	switch strings.TrimSpace(attributes["action"]) {
	case "business_advanced_security.enabled",
		"business_advanced_security.enabled_for_new_repos",
		"dependabot_alerts.enable",
		"dependabot_alerts_new_repos.enable",
		"dependabot_security_updates.enable",
		"dependabot_security_updates_new_repos.enable",
		"org.advanced_security_enabled_for_new_repos",
		"org.advanced_security_enabled_on_all_repos",
		"org.advanced_security_policy_selected_member_enabled",
		"org.secret_scanning_push_protection_enable",
		"repo.advanced_security_enabled",
		"repo.advanced_security_policy_selected_member_enabled",
		"repository_secret_scanning.enable",
		"repository_secret_scanning_push_protection.enable",
		"repository_vulnerability_alerts.enable":
		return true
	}
	return findingAttributeBool(
		attributes,
		"advanced_security_enabled",
		"github_advanced_security_enabled",
		"code_security_enabled",
		"dependabot_enabled",
		"dependabot_alerts_enabled",
		"dependabot_security_updates_enabled",
		"secret_scanning_enabled",
		"repository_secret_scanning_enabled",
		"secret_scanning_push_protection_enabled",
		"repository_vulnerability_alerts_enabled",
		"vulnerability_alerts_enabled",
	)
}

func githubCodeSecurityControlsCounterEventStates(event Event) []CounterEventStateUpdate {
	if !githubAuditSignalKindMatcher(event) {
		return nil
	}
	attributes := eventAttributes(event)
	return githubCounterEventStateUpdates(
		githubCodeSecurityControlsAnchor(attributes),
		githubDisabledCodeSecurityControls(attributes),
		githubRestoredCodeSecurityControls(attributes),
		event,
	)
}

func githubRestoredCodeSecurityControls(attributes map[string]string) []string {
	restored := []string{}
	switch strings.TrimSpace(attributes["action"]) {
	case "business_advanced_security.enabled",
		"business_advanced_security.enabled_for_new_repos",
		"org.advanced_security_enabled_for_new_repos",
		"org.advanced_security_enabled_on_all_repos",
		"org.advanced_security_policy_selected_member_enabled",
		"repo.advanced_security_enabled",
		"repo.advanced_security_policy_selected_member_enabled":
		restored = append(restored, "advanced_security")
	case "dependabot_alerts.enable",
		"dependabot_alerts_new_repos.enable",
		"dependabot_security_updates.enable",
		"dependabot_security_updates_new_repos.enable":
		restored = append(restored, "dependabot")
	case "org.secret_scanning_push_protection_enable",
		"repository_secret_scanning.enable",
		"repository_secret_scanning_push_protection.enable":
		restored = append(restored, "secret_scanning")
	case "repository_vulnerability_alerts.enable":
		restored = append(restored, "vulnerability_alerts")
	}
	if findingAttributeBool(attributes, "advanced_security_enabled", "github_advanced_security_enabled") {
		restored = append(restored, "advanced_security")
	}
	if findingAttributeBool(attributes, "code_security_enabled") {
		restored = append(restored, "advanced_security", "dependabot", "secret_scanning", "vulnerability_alerts")
	}
	if findingAttributeBool(attributes, "dependabot_enabled", "dependabot_alerts_enabled", "dependabot_security_updates_enabled") {
		restored = append(restored, "dependabot")
	}
	if findingAttributeBool(attributes, "secret_scanning_enabled", "repository_secret_scanning_enabled", "secret_scanning_push_protection_enabled") {
		restored = append(restored, "secret_scanning")
	}
	if findingAttributeBool(attributes, "vulnerability_alerts_enabled", "repository_vulnerability_alerts_enabled") {
		restored = append(restored, "vulnerability_alerts")
	}
	return deduplicateStrings(restored)
}

func githubCounterEventStateUpdates(anchor string, openKeys []string, closeKeys []string, event Event) []CounterEventStateUpdate {
	anchor = strings.TrimSpace(anchor)
	if anchor == "" {
		return nil
	}
	openKeys = deduplicateStrings(openKeys)
	closeKeys = deduplicateStrings(closeKeys)
	if len(openKeys) == 0 && len(closeKeys) == 0 {
		return nil
	}
	eventIDs := []string(nil)
	if event != nil {
		if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
			eventIDs = []string{eventID}
		}
	}
	states := make([]CounterEventStateUpdate, 0, len(openKeys)+len(closeKeys))
	openSet := make(map[string]struct{}, len(openKeys))
	for _, key := range openKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		openSet[key] = struct{}{}
		states = append(states, CounterEventStateUpdate{
			Anchor:   anchor,
			Key:      key,
			Closes:   false,
			EventIDs: eventIDs,
		})
	}
	for _, key := range closeKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, open := openSet[key]; open {
			continue
		}
		states = append(states, CounterEventStateUpdate{
			Anchor:   anchor,
			Key:      key,
			Closes:   true,
			EventIDs: eventIDs,
		})
	}
	return states
}

var githubPostureAttributeKeys = []string{
	"advanced_security_enabled",
	"allowed_cidrs_compliant",
	"auth_control_weakened",
	"code_security_enabled",
	"dependabot_alerts_enabled",
	"dependabot_enabled",
	"dependabot_security_updates_enabled",
	"github_advanced_security_enabled",
	"ip_allow_list_disabled",
	"ip_allow_list_enabled",
	"ip_allow_list_entries_compliant",
	"mfa_required",
	"non_allowlisted_cidr_count",
	"non_allowlisted_cidrs",
	"oauth_app_restrictions_enabled",
	"oauth_app_restrictions_enforced",
	"private_forking_enabled",
	"private_repository_forking_enabled",
	"repository_secret_scanning_enabled",
	"repository_vulnerability_alerts_enabled",
	"saml_enabled",
	"saml_enforced",
	"saml_provider_settings_weakened",
	"saml_required",
	"saml_sso_enabled",
	"secret_scanning_enabled",
	"secret_scanning_push_protection_enabled",
	"two_factor_enforced",
	"two_factor_required",
	"two_factor_requirement_enabled",
	"vulnerability_alerts_enabled",
}

func githubCodeSecurityControlsPostureDisabled(attributes map[string]string) bool {
	return len(githubDisabledCodeSecurityControls(attributes)) > 0
}

func githubDisabledCodeSecurityControls(attributes map[string]string) []string {
	disabled := []string{}
	if githubAttributeExplicitlyFalse(attributes, "advanced_security_enabled", "github_advanced_security_enabled", "code_security_enabled") {
		disabled = append(disabled, "advanced_security")
	}
	if githubAttributeExplicitlyFalse(attributes, "dependabot_enabled", "dependabot_alerts_enabled", "dependabot_security_updates_enabled") {
		disabled = append(disabled, "dependabot")
	}
	if githubAttributeExplicitlyFalse(attributes, "secret_scanning_enabled", "repository_secret_scanning_enabled", "secret_scanning_push_protection_enabled") {
		disabled = append(disabled, "secret_scanning")
	}
	if githubAttributeExplicitlyFalse(attributes, "vulnerability_alerts_enabled", "repository_vulnerability_alerts_enabled") {
		disabled = append(disabled, "vulnerability_alerts")
	}
	return disabled
}

func githubWeakenedAuthControls(attributes map[string]string) []string {
	weakened := []string{}
	if githubAttributeExplicitlyFalse(attributes, "oauth_app_restrictions_enabled", "oauth_app_restrictions_enforced") {
		weakened = append(weakened, "oauth_app_restrictions")
	}
	if githubAttributeExplicitlyFalse(attributes, "saml_enabled", "saml_enforced", "saml_required", "saml_sso_enabled") ||
		findingAttributeBool(attributes, "saml_provider_settings_weakened") {
		weakened = append(weakened, "saml")
	}
	if githubAttributeExplicitlyFalse(attributes, "mfa_required", "two_factor_enforced", "two_factor_required", "two_factor_requirement_enabled") {
		weakened = append(weakened, "two_factor_requirement")
	}
	if len(weakened) == 0 && findingAttributeBool(attributes, "auth_control_weakened") {
		weakened = append(weakened, "auth_control")
	}
	return weakened
}

func githubPrivateRepositoryForkingScope(attributes map[string]string) (string, string) {
	if repo := strings.TrimSpace(attributes["repo"]); repo != "" {
		return "repo", repo
	}
	if resourceID := strings.TrimSpace(attributes["resource_id"]); strings.Contains(resourceID, "/") {
		return "repo", resourceID
	}
	org := firstNonEmpty(attributes["org"], attributes["resource_id"])
	if strings.TrimSpace(org) == "" || strings.Contains(org, "/") {
		return "", ""
	}
	return "org", org
}

func githubSelfHostedRunnerScope(attributes map[string]string) (string, string) {
	if scope := strings.TrimSpace(firstNonEmpty(attributes["runner_scope"], attributes["scope"])); scope != "" {
		return githubSelfHostedRunnerScopeFromValue(scope)
	}
	if repo := strings.TrimSpace(firstNonEmpty(attributes["repo"], attributes["repository"])); repo != "" {
		return "repo", "repo:" + repo
	}
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.ToLower(strings.TrimSpace(attributes["resource_type"]))
	if resourceID != "" && (strings.Contains(resourceID, "/") || strings.Contains(resourceType, "repo")) {
		return "repo", "repo:" + resourceID
	}
	if org := strings.TrimSpace(attributes["org"]); org != "" {
		return "org", "org:" + org
	}
	if enterprise := strings.TrimSpace(firstNonEmpty(attributes["enterprise"], attributes["enterprise_slug"], attributes["enterprise_id"])); enterprise != "" {
		return "enterprise", "enterprise:" + enterprise
	}
	if resourceID != "" && (strings.Contains(resourceType, "org") || resourceType == "") {
		return "org", "org:" + resourceID
	}
	return "", ""
}

func githubSelfHostedRunnerScopeFromValue(scope string) (string, string) {
	normalized := strings.TrimSpace(scope)
	if normalized == "" {
		return "", ""
	}
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "repo:"), strings.HasPrefix(lower, "org:"), strings.HasPrefix(lower, "enterprise:"):
		return strings.SplitN(lower, ":", 2)[0], normalized
	case strings.Contains(normalized, "/"):
		return "repo", "repo:" + normalized
	default:
		return "org", "org:" + normalized
	}
}

func githubAttributeExplicitlyFalse(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(attributes[key])) {
		case "0", "f", "false", "n", "no", "disabled", "off":
			return true
		}
	}
	return false
}

// githubRetirementTag marks the rule definition so operators reading the
// rule catalog can see at a glance which mirror rules have been retired.
const githubRetirementTag = "retired"

// newRetiredGitHubAuditRule replaces a 1:1 audit-event mirror rule with an
// inert wrapper. The rule keeps its original id, name, output kind, and
// control refs so:
//
//   - Catalog clients still discover the id (no 404 on existing dashboards).
//   - The finding service sees the retirement marker and resolves any open
//     findings under this rule id without depending on a bounded replay
//     containing the original event ids.
//   - The follow-up posture graph rule can use the same control refs and
//     tags as a starting point, treating audit events as evidence rather
//     than as standalone findings.
//
// The wrapper's `match` and `build` are both no-ops; `build` returns nil for
// extra safety in case `match` is ever flipped on by accident.
func newRetiredGitHubAuditRule(original RuleDefinition) Rule {
	retired := original
	retired.Description = "Retired GitHub audit-mirror rule retained so stale open findings auto-resolve; durable coverage moved to posture findings."
	retired.Maturity = "retired"
	retired.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone}
	retired.Tags = appendUniqueString(cloneStringSlice(retired.Tags), githubRetirementTag, "cleanup")
	return newEventRule(eventRuleConfig{
		definition:         retired,
		sourceID:           "github",
		retireOpenFindings: true,
		match:              func(*cerebrov1.EventEnvelope) bool { return false },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func appendUniqueString(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, addition := range additions {
		if _, exists := seen[addition]; exists {
			continue
		}
		values = append(values, addition)
		seen[addition] = struct{}{}
	}
	return values
}
