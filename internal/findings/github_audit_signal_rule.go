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
	githubSecretScanningDisabledRuleID      = "github-secret-scanning-disabled"
	githubPushProtectionDisabledRuleID      = "github-push-protection-disabled"
	githubBranchProtectionDisabledRuleID    = "github-branch-protection-disabled"
	githubRepositoryMadePublicRuleID        = "github-repository-made-public"
	githubSecretScanningAlertCreatedRuleID  = "github-secret-scanning-alert-created"
	githubSelfHostedRunnerChangeRuleID      = "github-self-hosted-runner-change"
	githubRepositoryCollaboratorAddedRuleID = "github-repository-collaborator-added"
	githubOrganizationOwnerAddedRuleID      = "github-organization-owner-added"
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
		"event_id":             strings.TrimSpace(event.GetId()),
		"operation_type":       strings.TrimSpace(eventAttrs["operation_type"]),
		"org":                  strings.TrimSpace(eventAttrs["org"]),
		"permission":           strings.TrimSpace(eventAttrs["permission"]),
		"previous_visibility":  strings.TrimSpace(eventAttrs["previous_visibility"]),
		"primary_actor_urn":    actorURN,
		"primary_resource_urn": resourceURN,
		"repo":                 strings.TrimSpace(eventAttrs["repo"]),
		"resource_id":          strings.TrimSpace(eventAttrs["resource_id"]),
		"resource_type":        strings.TrimSpace(eventAttrs["resource_type"]),
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
