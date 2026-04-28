package findings

// RulePack groups built-in finding rules by source or domain.
type RulePack struct {
	ID          string
	Name        string
	Description string
	Rules       []Rule
}

func builtinRulePacks() []RulePack {
	return []RulePack{
		{
			ID:          "github",
			Name:        "GitHub",
			Description: "GitHub security and repository findings.",
			Rules: []Rule{
				newGitHubAppIntegrationInstalledRule(),
				newGitHubBranchProtectionDisabledRule(),
				newGitHubCodeSecurityControlsDisabledRule(),
				newGitHubCriticalResourceDeletedRule(),
				newGitHubDependabotOpenAlertRule(),
				newGitHubOrganizationOwnerAddedRule(),
				newGitHubOrgAuthControlModifiedRule(),
				newGitHubOrgIPAllowListModifiedRule(),
				newGitHubPersonalAccessTokenCreatedRule(),
				newGitHubPrivateRepositoryForkingEnabledRule(),
				newGitHubProtectedBranchPolicyOverrideRule(),
				newGitHubPushProtectionDisabledRule(),
				newGitHubRepositoryCollaboratorAddedRule(),
				newGitHubRepositoryMadePublicRule(),
				newGitHubRepositoryRulesetModifiedRule(),
				newGitHubSecretScanningAlertCreatedRule(),
				newGitHubSecretScanningDisabledRule(),
				newGitHubSelfHostedRunnerChangeRule(),
				newGitHubWebhookModifiedRule(),
			},
		},
		{
			ID:          "identity",
			Name:        "Identity",
			Description: "Identity platform control-plane findings.",
			Rules: append([]Rule{
				newOktaPolicyRuleLifecycleTamperingRule(),
			}, newIdentitySignalRules()...),
		},
	}
}

func flattenRulePacks(packs []RulePack) []Rule {
	rules := []Rule{}
	for _, pack := range packs {
		rules = append(rules, pack.Rules...)
	}
	return rules
}
