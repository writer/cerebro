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
		{
			ID:          "cloudflare",
			Name:        "Cloudflare",
			Description: "Cloudflare edge, zone, and DNS posture findings.",
			Rules: []Rule{
				newCloudflareZoneProtectionPausedRule(),
			},
		},
		{
			ID:          "trivy",
			Name:        "Trivy",
			Description: "Container image vulnerability posture findings from Trivy scans.",
			Rules: []Rule{
				newTrivyImageVulnerabilityActiveRule(),
			},
		},
		{
			ID:          "tailscale",
			Name:        "Tailscale",
			Description: "Tailscale tailnet, device, and access posture findings.",
			Rules: []Rule{
				newTailscaleTailnetDeviceApprovalDisabledRule(),
			},
		},
		{
			ID:          "kandji",
			Name:        "Kandji",
			Description: "Kandji Apple endpoint device posture findings.",
			Rules: []Rule{
				newKandjiEndpointDiskEncryptionDisabledRule(),
			},
		},
		{
			ID:          "kolide",
			Name:        "Kolide",
			Description: "Kolide/osquery endpoint host compliance posture findings.",
			Rules: []Rule{
				newKolideHostFailingComplianceChecksRule(),
			},
		},
		{
			ID:          "duo",
			Name:        "Duo",
			Description: "Duo identity and MFA posture findings.",
			Rules: []Rule{
				newDuoActiveUserMFANotEnforcedRule(),
			},
		},
		{
			ID:          "openai",
			Name:        "OpenAI",
			Description: "OpenAI organization credential and privileged-access posture findings.",
			Rules: []Rule{
				newOpenAIOrphanedPrivilegedAPIKeyRule(),
			},
		},
		{
			ID:          "slack",
			Name:        "Slack",
			Description: "Slack workspace identity and privileged-access posture findings.",
			Rules: []Rule{
				newSlackPrivilegedUserWithoutMFARule(),
			},
		},
		{
			ID:          "pagerduty",
			Name:        "PagerDuty",
			Description: "PagerDuty responder topology and incident-response coverage findings.",
			Rules: []Rule{
				newPagerDutyServiceWithoutEscalationRule(),
			},
		},
		{
			ID:          "trusted_endpoint",
			Name:        "Trusted Endpoint",
			Description: "Trusted Endpoint workstation posture and trust-gate findings.",
			Rules: []Rule{
				newTrustedEndpointActiveTrustGateFailureRule(),
			},
		},
		{
			ID:          "policy",
			Name:        "Policy",
			Description: "Generated compliance policy checks and evidence mappings.",
			Rules:       newPolicyCatalogRules(),
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
