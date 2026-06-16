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
				newGitHubCodeSecurityControlsDisabledRule(),
				newGitHubDependabotOpenAlertRule(),
				newGitHubOrganizationOwnerAddedRule(),
				newGitHubProgrammaticCredentialReviewRule(),
				newGitHubOrgAuthControlModifiedRule(),
				newGitHubOrgIPAllowListModifiedRule(),
				newGitHubPersonalAccessTokenCreatedRule(),
				newGitHubPrivateRepositoryForkingEnabledRule(),
				newGitHubRepositoryCollaboratorAddedRule(),
				newGitHubRepositoryRulesetModifiedRule(),
				newGitHubSecretScanningAlertCreatedRule(),
				newGitHubSelfHostedRunnerReviewRule(),
				newGitHubOrgOwnerConcentrationRule(),
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
				newDeprovisionedOktaActiveCloudAccessRule(),
				newGitHubActiveWithoutOktaLinkRule(),
				newOktaOAuthPublicClientReviewRule(),
				newOktaAuthenticatorWeakFactorRule(),
				newOktaThreatInsightNotBlockingRule(),
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
			ID:          "panopticon",
			Name:        "Panopticon",
			Description: "Panopticon curated security operations cases.",
			Rules:       []Rule{newPanopticonCuratedCaseRule()},
		},
		{
			ID:          "security_reviewer",
			Name:        "Security Reviewer",
			Description: "Security-reviewer reported code and workflow findings.",
			Rules:       []Rule{newSecurityReviewerFindingRule()},
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
				newSentinelOneInfectedPrivilegedOwnerRule(),
				newSentinelOneMitigationFailedRule(),
				newSentinelOneAgentStaleRule(),
				newSentinelOneAgentNotUpToDateRule(),
				newSentinelOneAgentDetectOnlyModeRule(),
				newSentinelOneProtectionControlTamperingRule(),
				newSentinelOneRiskyExclusionRule(),
				newSentinelOneUnmitigatedThreatRule(),
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
		{
			ID:          "email_domain",
			Name:        "Email Domain",
			Description: "SPF, DKIM, and DMARC posture findings on tenant mail domains.",
			Rules: []Rule{
				newEmailDomainAuthenticationMisconfiguredRule(),
			},
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
