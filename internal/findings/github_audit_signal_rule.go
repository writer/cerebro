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

func newGitHubAuditCounterEventRule(config githubAuditSignalConfig, openAnchor func(map[string]string) string, closeAnchor githubAuditSignalClosePredicate) Rule {
	return &githubAuditCounterEventRule{
		Rule:        newGitHubAuditSignalRule(config),
		definition:  config.definition,
		openAnchor:  openAnchor,
		closeAnchor: closeAnchor,
	}
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

// Note: the secret-scanning-disabled, push-protection-disabled,
// branch-protection-disabled, and repository-made-public match configs
// were removed when these audit-event mirror rules were retired. Their
// RuleDefinition values (above) are preserved so the retirement wrapper
// can keep advertising the original output_kind, control refs, and
// references when the rule appears in the catalog. The forthcoming
// posture graph rules will reintroduce the trigger logic in a durable
// state-based form.

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

var githubOrgAuthControlModifiedConfig = githubAuditSignalConfig{
	definition:        githubOrgAuthControlModifiedDefinition,
	predicate:         githubOrgAuthControlWeakening,
	primaryEntityType: func(map[string]string) string { return "github.org" },
	severity: func(attributes map[string]string) string {
		action := strings.TrimSpace(attributes["action"])
		if action == "org.update_saml_provider_settings" {
			return "HIGH"
		}
		return "CRITICAL"
	},
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub organization authentication control %s for %s", githubAuditActor(attributes), strings.TrimSpace(attributes["action"]), githubAuditTarget(attributes))
	},
}

var githubOrgIPAllowListModifiedConfig = githubAuditSignalConfig{
	definition:        githubOrgIPAllowListModifiedDefinition,
	predicate:         githubIPAllowListWeakeningOrExpansion,
	primaryEntityType: func(map[string]string) string { return "github.org" },
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

// githubProtectedBranchPolicyOverrideConfig was removed when the
// per-override mirror rule was retired; durable posture coverage lives in
// graph/current-state rules while the retired wrapper keeps stale findings
// resolvable.

var githubRepositoryRulesetModifiedConfig = githubAuditSignalConfig{
	definition: githubRepositoryRulesetModifiedDefinition,
	actions:    githubAuditActionSet("repository_ruleset.destroy", "repository_ruleset.update"),
	predicate:  githubRepositoryRulesetWeakening,
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub repository ruleset %s for %s", githubAuditActor(attributes), firstNonEmpty(attributes["ruleset_name"], attributes["ruleset_id"], "unknown ruleset"), githubAuditTarget(attributes))
	},
}

var githubWebhookModifiedConfig = githubAuditSignalConfig{
	definition: githubWebhookModifiedDefinition,
	actions:    githubAuditActionSet("hook.config_changed", "hook.create"),
	predicate:  githubWebhookDestinationPolicyViolating,
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s modified GitHub webhook %s for %s", githubAuditActor(attributes), firstNonEmpty(attributes["hook_id"], "unknown hook"), githubAuditTarget(attributes))
	},
}

var githubPrivateRepositoryForkingEnabledConfig = githubAuditSignalConfig{
	definition: githubPrivateRepositoryForkingEnabledDefinition,
	predicate:  githubPrivateRepositoryForkingEnabled,
	primaryEntityType: func(attributes map[string]string) string {
		scope, _ := githubPrivateRepositoryForkingScope(attributes)
		if scope == "repo" {
			return "github.code.repository"
		}
		return "github.org"
	},
	fingerprint: githubPrivateRepositoryForkingFingerprintInputs,
	summary: func(attributes map[string]string) string {
		return fmt.Sprintf("%s enabled or reset private repository forking for %s", githubAuditActor(attributes), githubAuditTarget(attributes))
	},
}

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
	return newGitHubAuditCounterEventRule(githubRepositoryCollaboratorAddedConfig, githubRepositoryCollaboratorAnchor, githubRepositoryCollaboratorCloseAnchor)
}

func newGitHubOrganizationOwnerAddedRule() Rule {
	return newGitHubAuditCounterEventRule(githubOrganizationOwnerAddedConfig, githubOrganizationOwnerAnchor, githubOrganizationOwnerCloseAnchor)
}

func newGitHubCodeSecurityControlsDisabledRule() Rule {
	return newGitHubAggregateAuditCounterEventRule(githubCodeSecurityControlsDisabledConfig, githubCodeSecurityControlsAnchor, githubCodeSecurityControlsCloseAnchor, githubCodeSecurityControlsCounterEventStates)
}

func newGitHubOrgAuthControlModifiedRule() Rule {
	return newGitHubAggregateAuditCounterEventRule(githubOrgAuthControlModifiedConfig, githubOrgPostureAnchor, githubOrgAuthControlCloseAnchor, githubOrgAuthControlCounterEventStates)
}

func newGitHubOrgIPAllowListModifiedRule() Rule {
	return newGitHubAggregateAuditCounterEventRule(githubOrgIPAllowListModifiedConfig, githubOrgPostureAnchor, githubOrgIPAllowListCloseAnchor, githubOrgIPAllowListCounterEventStates)
}

func newGitHubAppIntegrationInstalledRule() Rule {
	return newGitHubAuditCounterEventRule(githubAppIntegrationInstalledConfig, githubAppIntegrationAnchor, githubAppIntegrationCloseAnchor)
}

func newGitHubPersonalAccessTokenCreatedRule() Rule {
	return newGitHubAuditCounterEventRule(githubPersonalAccessTokenCreatedConfig, githubPersonalAccessTokenAnchor, githubPersonalAccessTokenCloseAnchor)
}

// newGitHubProtectedBranchPolicyOverrideRule is retired. Per-event overrides
// turn into evidence on the durable "protected branch policy degraded"
// posture finding (future graph rule) rather than a standalone mirror
// finding per override event.
func newGitHubProtectedBranchPolicyOverrideRule() Rule {
	return newRetiredGitHubAuditRule(githubProtectedBranchPolicyOverrideDefinition)
}

func newGitHubRepositoryRulesetModifiedRule() Rule {
	return newGitHubAuditCounterEventRule(githubRepositoryRulesetModifiedConfig, githubRepositoryRulesetAnchor, githubRepositoryRulesetCloseAnchor)
}

func newGitHubCriticalResourceDeletedRule() Rule {
	return newRetiredGitHubAuditRule(githubCriticalResourceDeletedDefinition)
}

func newGitHubWebhookModifiedRule() Rule {
	return newGitHubAuditCounterEventRule(githubWebhookModifiedConfig, githubWebhookAnchor, githubWebhookCloseAnchor)
}

func newGitHubPrivateRepositoryForkingEnabledRule() Rule {
	return newGitHubAuditCounterEventRule(githubPrivateRepositoryForkingEnabledConfig, githubPrivateRepositoryForkingAnchor, githubPrivateRepositoryForkingCloseAnchor)
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

func githubAuditActionSet(actions ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if strings.TrimSpace(action) != "" {
			set[strings.TrimSpace(action)] = struct{}{}
		}
	}
	return set
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

func githubRepositoryCollaboratorAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "repo", "user")
}

func githubRepositoryCollaboratorCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	action := strings.TrimSpace(attributes["action"])
	switch action {
	case "member.removed", "repo.remove_member", "repository.remove_member", "repo.remove_collaborator", "repository.remove_collaborator", "org.remove_member":
		return githubRepositoryCollaboratorAnchor(attributes), true
	default:
		return "", false
	}
}

func githubOrganizationOwnerAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "org", "user")
}

func githubOrganizationOwnerCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	action := strings.TrimSpace(attributes["action"])
	switch action {
	case "member.removed", "org.remove_member", "organization.remove_member", "org.remove_owner", "organization.remove_owner":
		return githubOrganizationOwnerAnchor(attributes), true
	case "org.add_member", "org.update_member", "org.update_member_role", "member.role_changed", "member.updated":
		permission := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["new_permission"], attributes["permission"], attributes["new_role"], attributes["role"])))
		if permission != "" && permission != "admin" && permission != "owner" {
			return githubOrganizationOwnerAnchor(attributes), true
		}
		return "", false
	default:
		return "", false
	}
}

func githubAppIntegrationAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "org", "github_app_id")
}

func githubAppIntegrationCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	switch strings.TrimSpace(attributes["action"]) {
	case "integration_installation.delete", "integration_installation.destroy", "integration_installation.suspend":
		return githubAppIntegrationAnchor(attributes), true
	default:
		return "", false
	}
}

func githubPersonalAccessTokenAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "user_id", "token_id")
}

func githubPersonalAccessTokenCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !githubPersonalAccessTokenClosed(attributes) {
		return "", false
	}
	return githubPersonalAccessTokenAnchor(attributes), true
}

func githubPersonalAccessTokenClosed(attributes map[string]string) bool {
	action := strings.TrimSpace(attributes["action"])
	switch action {
	case "personal_access_token.access_revoked", "personal_access_token.access_expired", "personal_access_token.expired":
		return true
	case "personal_access_token.access_granted":
		return githubPersonalAccessTokenLifecycleClosed(attributes)
	default:
		if !strings.HasPrefix(action, "personal_access_token.") {
			return false
		}
		return githubPersonalAccessTokenLifecycleClosed(attributes)
	}
}

func githubPersonalAccessTokenLifecycleClosed(attributes map[string]string) bool {
	state := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		attributes["operation_type"],
		attributes["token_state"],
		attributes["token_status"],
		attributes["credential_status"],
		attributes["lifecycle_status"],
		attributes["state"],
		attributes["status"],
		attributes["reason"],
	)))
	switch state {
	case "remove", "removed", "revoke", "revoked", "access_revoked", "expire", "expired", "expiration", "token_expired":
		return true
	}
	return containsAny(strings.ToLower(firstNonEmpty(attributes["change_type"], attributes["changes"])), "revoke", "remove", "expire", "expired")
}

func githubOrgPostureAnchor(attributes map[string]string) string {
	org := strings.TrimSpace(firstNonEmpty(attributes["org"], attributes["organization"]))
	if org == "" {
		resourceID := strings.TrimSpace(attributes["resource_id"])
		if resourceID != "" && !strings.Contains(resourceID, "/") {
			org = resourceID
		}
	}
	return githubCounterEventAnchor(map[string]string{"org": org}, "org")
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

func githubOrgAuthControlCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !githubOrgAuthControlsRestored(attributes) {
		return "", false
	}
	return githubOrgPostureAnchor(attributes), true
}

func githubOrgAuthControlsRestored(attributes map[string]string) bool {
	if githubOrgAuthControlWeakening(attributes) {
		return false
	}
	switch strings.TrimSpace(attributes["action"]) {
	case "oauth_app_policy.enabled",
		"org.enable_oauth_app_restrictions",
		"org.enable_saml_sso",
		"org.enable_two_factor_requirement",
		"org.require_two_factor_requirement":
		return true
	}
	return findingAttributeBool(
		attributes,
		"auth_control_strengthened",
		"oauth_app_restrictions_enabled",
		"oauth_app_restrictions_enforced",
		"saml_enabled",
		"saml_enforced",
		"saml_required",
		"saml_sso_enabled",
		"mfa_required",
		"two_factor_enforced",
		"two_factor_required",
		"two_factor_requirement_enabled",
	)
}

func githubOrgAuthControlCounterEventStates(event Event) []CounterEventStateUpdate {
	if !githubAuditSignalKindMatcher(event) {
		return nil
	}
	attributes := eventAttributes(event)
	return githubCounterEventStateUpdates(
		githubOrgPostureAnchor(attributes),
		githubWeakenedAuthControls(attributes),
		githubRestoredAuthControls(attributes),
		event,
	)
}

func githubRestoredAuthControls(attributes map[string]string) []string {
	restored := []string{}
	switch strings.TrimSpace(attributes["action"]) {
	case "oauth_app_policy.enabled", "org.enable_oauth_app_restrictions":
		restored = append(restored, "oauth_app_restrictions")
	case "org.enable_saml_sso":
		restored = append(restored, "saml")
	case "org.enable_two_factor_requirement", "org.require_two_factor_requirement":
		restored = append(restored, "two_factor_requirement")
	}
	if findingAttributeBool(attributes, "auth_control_strengthened") {
		restored = append(restored, "auth_control", "oauth_app_restrictions", "saml", "two_factor_requirement")
	}
	if findingAttributeBool(attributes, "oauth_app_restrictions_enabled", "oauth_app_restrictions_enforced") {
		restored = append(restored, "oauth_app_restrictions")
	}
	if findingAttributeBool(attributes, "saml_enabled", "saml_enforced", "saml_required", "saml_sso_enabled") {
		restored = append(restored, "saml")
	}
	if findingAttributeBool(attributes, "mfa_required", "two_factor_enforced", "two_factor_required", "two_factor_requirement_enabled") {
		restored = append(restored, "two_factor_requirement")
	}
	return deduplicateStrings(restored)
}

func githubOrgIPAllowListCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !githubIPAllowListRestored(attributes) {
		return "", false
	}
	return githubOrgPostureAnchor(attributes), true
}

func githubIPAllowListRestored(attributes map[string]string) bool {
	if githubIPAllowListWeakeningOrExpansion(attributes) {
		return false
	}
	switch strings.TrimSpace(attributes["action"]) {
	case "ip_allow_list.enable", "ip_allow_list.enabled", "org.enable_ip_allow_list":
		return true
	}
	return findingAttributeBool(attributes, "ip_allow_list_enabled") ||
		findingAttributeBool(attributes, "allowed_cidrs_compliant", "ip_allow_list_entries_compliant")
}

func githubOrgIPAllowListCounterEventStates(event Event) []CounterEventStateUpdate {
	if !githubAuditSignalKindMatcher(event) {
		return nil
	}
	attributes := eventAttributes(event)
	return githubCounterEventStateUpdates(
		githubOrgPostureAnchor(attributes),
		githubWeakenedIPAllowListControls(attributes),
		githubRestoredIPAllowListControls(attributes),
		event,
	)
}

func githubWeakenedIPAllowListControls(attributes map[string]string) []string {
	weakened := []string{}
	if findingAttributeBool(attributes, "ip_allow_list_disabled") || githubAttributeExplicitlyFalse(attributes, "ip_allow_list_enabled") {
		weakened = append(weakened, "enabled")
	}
	if githubAttributeExplicitlyFalse(attributes, "allowed_cidrs_compliant", "ip_allow_list_entries_compliant") ||
		githubNonEmptyListAttribute(attributes, "non_allowlisted_cidrs") ||
		githubPositiveCountAttribute(attributes, "non_allowlisted_cidr_count") {
		weakened = append(weakened, "cidrs")
	}
	return deduplicateStrings(weakened)
}

func githubRestoredIPAllowListControls(attributes map[string]string) []string {
	restored := []string{}
	switch strings.TrimSpace(attributes["action"]) {
	case "ip_allow_list.enable", "ip_allow_list.enabled", "org.enable_ip_allow_list":
		restored = append(restored, "enabled")
	}
	if findingAttributeBool(attributes, "ip_allow_list_enabled") {
		restored = append(restored, "enabled")
	}
	if findingAttributeBool(attributes, "allowed_cidrs_compliant", "ip_allow_list_entries_compliant") ||
		githubZeroCountAttribute(attributes, "non_allowlisted_cidr_count") ||
		githubEmptyListAttribute(attributes, "non_allowlisted_cidrs") {
		restored = append(restored, "cidrs")
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

func githubZeroCountAttribute(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(attributes[key]) == "0" {
			return true
		}
	}
	return false
}

func githubEmptyListAttribute(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		value, ok := attributes[key]
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "", "[]", "{}", "none", "null":
			return true
		}
	}
	return false
}

func githubRepositoryRulesetAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "repo", "ruleset_id")
}

func githubRepositoryRulesetCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	switch strings.TrimSpace(attributes["action"]) {
	case "repository_ruleset.destroy":
		return githubRepositoryRulesetAnchor(attributes), true
	case "repository_ruleset.update":
		if githubRepositoryRulesetRestored(attributes) {
			return githubRepositoryRulesetAnchor(attributes), true
		}
		return "", false
	default:
		return "", false
	}
}

func githubRepositoryRulesetRestored(attributes map[string]string) bool {
	if githubRepositoryRulesetWeakening(attributes) {
		return false
	}
	enforcement := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["new_enforcement"], attributes["enforcement"], attributes["ruleset_enforcement"])))
	switch enforcement {
	case "active", "enabled", "enforced":
		return true
	}
	return containsAny(strings.ToLower(firstNonEmpty(attributes["operation_type"], attributes["change_type"], attributes["changes"])), "enable", "restore", "enforce")
}

func githubWebhookAnchor(attributes map[string]string) string {
	return githubCounterEventAnchor(attributes, "repo", "hook_id")
}

func githubWebhookCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	switch strings.TrimSpace(attributes["action"]) {
	case "hook.destroy":
		return githubWebhookAnchor(attributes), true
	case "hook.config_changed":
		if githubWebhookDestinationAllowlisted(attributes) {
			return githubWebhookAnchor(attributes), true
		}
		return "", false
	default:
		return "", false
	}
}

func githubWebhookDestinationPolicyViolating(attributes map[string]string) bool {
	return !githubWebhookDestinationAllowlisted(attributes)
}

func githubWebhookDestinationAllowlisted(attributes map[string]string) bool {
	return findingAttributeBool(
		attributes,
		"allowlisted_destination",
		"destination_allowlisted",
		"hook_destination_allowlisted",
		"hook_url_allowlisted",
		"url_allowlisted",
		"webhook_destination_allowlisted",
		"webhook_url_allowlisted",
	) || githubAttributeExplicitlyFalse(
		attributes,
		"destination_non_allowlisted",
		"hook_destination_non_allowlisted",
		"hook_url_non_allowlisted",
		"non_allowlisted_destination",
		"url_non_allowlisted",
		"webhook_destination_non_allowlisted",
		"webhook_url_non_allowlisted",
	)
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

func githubOrgAuthControlWeakening(attributes map[string]string) bool {
	return len(githubWeakenedAuthControls(attributes)) > 0
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

func githubIPAllowListWeakeningOrExpansion(attributes map[string]string) bool {
	if findingAttributeBool(attributes, "ip_allow_list_disabled") || githubAttributeExplicitlyFalse(attributes, "ip_allow_list_enabled") {
		return true
	}
	if githubAttributeExplicitlyFalse(attributes, "allowed_cidrs_compliant", "ip_allow_list_entries_compliant") {
		return true
	}
	return githubNonEmptyListAttribute(attributes, "non_allowlisted_cidrs") || githubPositiveCountAttribute(attributes, "non_allowlisted_cidr_count")
}

func githubPrivateRepositoryForkingEnabled(attributes map[string]string) bool {
	_, scopeID := githubPrivateRepositoryForkingScope(attributes)
	if scopeID == "" {
		return false
	}
	return findingAttributeBool(attributes, "private_repository_forking_enabled", "private_forking_enabled")
}

func githubPrivateRepositoryForkingAnchor(attributes map[string]string) string {
	scopeID := strings.TrimSpace(attributes["posture_scope_id"])
	if scopeID == "" {
		_, scopeID = githubPrivateRepositoryForkingScope(attributes)
	}
	return githubCounterEventAnchor(map[string]string{"scope": scopeID}, "scope")
}

func githubPrivateRepositoryForkingCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !githubPrivateRepositoryForkingDisabled(attributes) {
		return "", false
	}
	return githubPrivateRepositoryForkingAnchor(attributes), true
}

func githubPrivateRepositoryForkingDisabled(attributes map[string]string) bool {
	if githubPrivateRepositoryForkingEnabled(attributes) {
		return false
	}
	switch strings.TrimSpace(attributes["action"]) {
	case "org.private_repository_forking_disable",
		"private_repository_forking.disable",
		"private_repository_forking.disabled",
		"repo.private_repository_forking_disable",
		"repository.private_repository_forking_disabled":
		return true
	}
	return githubAttributeExplicitlyFalse(attributes, "private_repository_forking_enabled", "private_forking_enabled")
}

func githubPrivateRepositoryForkingFingerprintInputs(event *cerebrov1.EventEnvelope, _ RuleDefinition) []string {
	_, scopeID := githubPrivateRepositoryForkingScope(eventAttributes(event))
	if scopeID == "" {
		return nil
	}
	return []string{scopeID}
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

func githubNonEmptyListAttribute(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(attributes[key]))
		switch value {
		case "", "[]", "{}", "none", "null":
			continue
		default:
			return true
		}
	}
	return false
}

func githubPositiveCountAttribute(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		value := strings.TrimSpace(attributes[key])
		if value != "" && value != "0" {
			return true
		}
	}
	return false
}

func githubRepositoryRulesetWeakening(attributes map[string]string) bool {
	action := strings.TrimSpace(attributes["action"])
	if action == "repository_ruleset.destroy" {
		return true
	}
	if action != "repository_ruleset.update" {
		return false
	}
	if containsAny(strings.ToLower(firstNonEmpty(attributes["operation_type"], attributes["change_type"], attributes["changes"])), "disable", "remove", "delete", "downgrade", "bypass") {
		return true
	}
	enforcement := strings.ToLower(firstNonEmpty(attributes["new_enforcement"], attributes["enforcement"], attributes["ruleset_enforcement"]))
	if enforcement == "disabled" || enforcement == "evaluate" {
		return true
	}
	return findingAttributeBool(attributes, "bypass_actor_added", "required_review_removed", "required_status_check_removed", "force_pushes_allowed", "deletions_allowed")
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
