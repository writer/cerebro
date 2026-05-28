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
				newGitHubProgrammaticCredentialReviewRule(),
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
				newGitHubSelfHostedRunnerReviewRule(),
				newGitHubWebhookModifiedRule(),
			},
		},
		{
			ID:          "identity",
			Name:        "Identity",
			Description: "Identity platform control-plane findings.",
			Rules: append([]Rule{
				newOktaPolicyRuleLifecycleTamperingRule(),
				newDeprovisionedOktaActiveGitHubRule(),
				newGitHubActiveWithoutOktaLinkRule(),
				newOktaOAuthPublicClientReviewRule(),
				newIdentityPrivilegedNoMFAAccessRule(),
			}, newIdentitySignalRules()...),
		},
		{
			ID:          "cloud",
			Name:        "Cloud",
			Description: "Cloud resource exposure and privilege path findings.",
			Rules:       newCloudSignalRules(),
		},
		{
			ID:          "runtime",
			Name:        "Runtime",
			Description: "Runtime evidence findings.",
			Rules:       []Rule{newRuntimeActiveThreatEvidenceRule()},
		},
		{
			ID:          "grc",
			Name:        "GRC",
			Description: "Provider-neutral GRC control, vulnerability, and vendor-risk findings.",
			Rules: append([]Rule{
				newGRCControlTestNeedsAttentionRule(),
				newGRCVulnerabilitySLAOverdueRule(),
				newGRCVendorReviewOverdueRule(),
				newGRCInactiveIdentityActiveAccessRule(),
				newGRCPrivilegedAccountMissingPersonRule(),
				newGRCOverdueVulnerabilityLiveOnAssetsRule(),
				newGRCFailingControlOpenOperationalFindingsRule(),
			}, newCoordinationGraphRules()...),
		},
		{
			ID:          "sentinelone",
			Name:        "SentinelOne",
			Description: "SentinelOne endpoint posture, response, and protection-control findings.",
			Rules: []Rule{
				newSentinelOneEndpointActiveInfectionRule(),
				newSentinelOneMitigationFailedRule(),
				newSentinelOneAgentStaleRule(),
				newSentinelOneAgentNotUpToDateRule(),
				newSentinelOneAgentDetectOnlyModeRule(),
				newSentinelOneProtectionControlTamperingRule(),
				newSentinelOneRiskyExclusionRule(),
				newSentinelOneUnmitigatedThreatRule(),
				newRetiredSentinelOneRule(sentinelOneRetiredUnresolvedThreatRuleID, "Retired SentinelOne Unresolved Threat", "finding.sentinelone_unresolved_threat"),
				newRetiredSentinelOneRule(sentinelOneRetiredMaliciousOrFilelessRuleID, "Retired SentinelOne Malicious Or Fileless Threat", "finding.sentinelone_malicious_or_fileless_threat"),
				newRetiredSentinelOneRule(sentinelOneRetiredInfectedEndpointRuleID, "Retired SentinelOne Infected Endpoint", "finding.sentinelone_infected_endpoint"),
			},
		},
		{
			ID:          "vulnview",
			Name:        "VulnView",
			Description: "VulnView external attack-surface findings.",
			Rules: []Rule{
				newVulnViewActionableExternalFindingRule(),
				newVulnViewExternalAssetConcentratedSignalRule(),
			},
		},
		{
			ID:          "data",
			Name:        "Data",
			Description: "Sensitive data and crown-jewel findings.",
			Rules:       []Rule{newDataSensitiveAssetRiskRule()},
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
