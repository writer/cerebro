package app

import "strconv"

// ProviderAwareConfig is a nested provider-centric view derived from Config's
// flat env-backed fields. It keeps compatibility while offering grouped access.
type ProviderAwareConfig struct {
	Identity map[string]map[string]string
	Cloud    map[string]map[string]string
	SaaS     map[string]map[string]string
	Endpoint map[string]map[string]string
	Network  map[string]map[string]string
	Security map[string]map[string]string
}

func (c *Config) BuildProviderAwareConfig() ProviderAwareConfig {
	out := ProviderAwareConfig{
		Identity: make(map[string]map[string]string),
		Cloud:    make(map[string]map[string]string),
		SaaS:     make(map[string]map[string]string),
		Endpoint: make(map[string]map[string]string),
		Network:  make(map[string]map[string]string),
		Security: make(map[string]map[string]string),
	}

	add := func(bucket map[string]map[string]string, name string, values map[string]string) {
		filtered := make(map[string]string)
		for k, v := range values {
			if v != "" {
				filtered[k] = v
			}
		}
		if len(filtered) > 0 {
			bucket[name] = filtered
		}
	}

	add(out.Endpoint, "crowdstrike", map[string]string{"client_id": c.CrowdStrikeClientID, "client_secret": c.CrowdStrikeClientSecret})
	add(out.Identity, "okta", map[string]string{"domain": c.OktaDomain, "api_token": c.OktaAPIToken})
	add(out.Identity, "entra_id", map[string]string{"tenant_id": c.EntraTenantID, "client_id": c.EntraClientID, "client_secret": c.EntraClientSecret})
	add(out.Cloud, "azure", map[string]string{"tenant_id": c.AzureTenantID, "client_id": c.AzureClientID, "client_secret": c.AzureClientSecret, "subscription_id": c.AzureSubscriptionID})

	add(out.Security, "snyk", map[string]string{"api_token": c.SnykAPIToken, "org_id": c.SnykOrgID})
	add(out.SaaS, "zoom", map[string]string{"account_id": c.ZoomAccountID, "client_id": c.ZoomClientID, "client_secret": c.ZoomClientSecret, "base_url": c.ZoomAPIURL, "token_url": c.ZoomTokenURL})
	add(out.Security, "wiz", map[string]string{"client_id": c.WizClientID, "client_secret": c.WizClientSecret, "api_url": c.WizAPIURL, "token_url": c.WizTokenURL, "audience": c.WizAudience})
	add(out.Security, "datadog", map[string]string{"api_key": c.DatadogAPIKey, "app_key": c.DatadogAppKey, "site": c.DatadogSite})

	add(out.SaaS, "github", map[string]string{"token": c.GitHubToken, "org": c.GitHubOrg})
	add(out.SaaS, "gitlab", map[string]string{"token": c.GitLabToken, "base_url": c.GitLabBaseURL})
	add(out.SaaS, "figma", map[string]string{"api_token": c.FigmaAPIToken, "team_id": c.FigmaTeamID, "base_url": c.FigmaBaseURL})
	add(out.SaaS, "socket", map[string]string{"api_token": c.SocketAPIToken, "org_slug": c.SocketOrgSlug, "api_url": c.SocketAPIURL})
	add(out.SaaS, "ramp", map[string]string{"client_id": c.RampClientID, "client_secret": c.RampClientSecret, "base_url": c.RampAPIURL, "token_url": c.RampTokenURL})
	add(out.SaaS, "gong", map[string]string{"access_key": c.GongAccessKey, "access_secret": c.GongAccessSecret, "base_url": c.GongBaseURL})
	add(out.SaaS, "vanta", map[string]string{"api_token": c.VantaAPIToken, "base_url": c.VantaBaseURL})
	add(out.Security, "panther", map[string]string{"api_token": c.PantherAPIToken, "base_url": c.PantherBaseURL})
	add(out.Endpoint, "kolide", map[string]string{"api_token": c.KolideAPIToken, "base_url": c.KolideBaseURL})
	add(out.SaaS, "atlassian", map[string]string{"base_url": c.JiraBaseURL, "email": c.JiraEmail, "api_token": c.JiraAPIToken})

	add(out.SaaS, "google_workspace", map[string]string{"domain": c.GoogleWorkspaceDomain, "admin_email": c.GoogleWorkspaceAdminEmail, "impersonator_email": c.GoogleWorkspaceImpersonatorEmail, "credentials_file": c.GoogleWorkspaceCredentialsFile, "credentials_json": c.GoogleWorkspaceCredentialsJSON})
	add(out.Network, "tailscale", map[string]string{"api_key": c.TailscaleAPIKey, "tailnet": c.TailscaleTailnet})
	add(out.Endpoint, "sentinelone", map[string]string{"api_token": c.SentinelOneAPIToken, "base_url": c.SentinelOneBaseURL})
	add(out.Security, "tenable", map[string]string{"access_key": c.TenableAccessKey, "secret_key": c.TenableSecretKey})
	add(out.Security, "qualys", map[string]string{"username": c.QualysUsername, "password": c.QualysPassword, "platform": c.QualysPlatform})
	add(out.Security, "semgrep", map[string]string{"api_token": c.SemgrepAPIToken})

	add(out.SaaS, "servicenow", map[string]string{"url": c.ServiceNowURL, "api_token": c.ServiceNowAPIToken, "username": c.ServiceNowUsername, "password": c.ServiceNowPassword})
	add(out.SaaS, "workday", map[string]string{"url": c.WorkdayURL, "api_token": c.WorkdayAPIToken})
	add(out.SaaS, "bamboohr", map[string]string{"url": c.BambooHRURL, "api_token": c.BambooHRAPIToken})
	add(out.Identity, "onelogin", map[string]string{"url": c.OneLoginURL, "client_id": c.OneLoginClientID, "client_secret": c.OneLoginClientSecret})
	add(out.Identity, "jumpcloud", map[string]string{"url": c.JumpCloudURL, "api_token": c.JumpCloudAPIToken, "org_id": c.JumpCloudOrgID})
	add(out.Identity, "duo", map[string]string{"url": c.DuoURL, "integration_key": c.DuoIntegrationKey, "secret_key": c.DuoSecretKey})
	add(out.Identity, "pingidentity", map[string]string{"environment_id": c.PingIdentityEnvironmentID, "client_id": c.PingIdentityClientID, "client_secret": c.PingIdentityClientSecret, "api_url": c.PingIdentityAPIURL, "auth_url": c.PingIdentityAuthURL})

	add(out.Security, "cyberark", map[string]string{"url": c.CyberArkURL, "api_token": c.CyberArkAPIToken})
	add(out.Identity, "sailpoint", map[string]string{"url": c.SailPointURL, "api_token": c.SailPointAPIToken})
	add(out.Identity, "saviynt", map[string]string{"url": c.SaviyntURL, "api_token": c.SaviyntAPIToken})
	add(out.Identity, "forgerock", map[string]string{"url": c.ForgeRockURL, "api_token": c.ForgeRockAPIToken})
	add(out.Identity, "oracle_idcs", map[string]string{"url": c.OracleIDCSURL, "api_token": c.OracleIDCSAPIToken})

	add(out.SaaS, "terraform_cloud", map[string]string{"token": c.TerraformCloudToken})
	add(out.Identity, "auth0", map[string]string{"domain": c.Auth0Domain, "client_id": c.Auth0ClientID, "client_secret": c.Auth0ClientSecret})
	add(out.Security, "splunk", map[string]string{"url": c.SplunkURL, "token": c.SplunkToken})
	add(out.Network, "cloudflare", map[string]string{"api_token": c.CloudflareAPIToken})
	add(out.SaaS, "salesforce", map[string]string{"instance_url": c.SalesforceInstanceURL, "client_id": c.SalesforceClientID, "client_secret": c.SalesforceClientSecret, "username": c.SalesforceUsername, "password": c.SalesforcePassword, "security_token": c.SalesforceSecurityToken})
	add(out.Security, "vault", map[string]string{"address": c.VaultAddress, "token": c.VaultToken, "namespace": c.VaultNamespace})

	add(out.SaaS, "slack", map[string]string{"token": c.SlackAPIToken})
	add(out.Identity, "rippling", map[string]string{"api_url": c.RipplingAPIURL, "api_token": c.RipplingAPIToken})
	add(out.Endpoint, "jamf", map[string]string{"base_url": c.JamfBaseURL, "client_id": c.JamfClientID, "client_secret": c.JamfClientSecret})
	add(out.Identity, "intune", map[string]string{"tenant_id": firstNonEmpty(c.IntuneTenantID, c.EntraTenantID), "client_id": firstNonEmpty(c.IntuneClientID, c.EntraClientID), "client_secret": firstNonEmpty(c.IntuneClientSecret, c.EntraClientSecret)})
	add(out.Endpoint, "kandji", map[string]string{"api_url": c.KandjiAPIURL, "api_token": c.KandjiAPIToken})

	s3Values := map[string]string{"bucket": c.S3InputBucket, "prefix": c.S3InputPrefix, "region": c.S3InputRegion, "format": c.S3InputFormat}
	if c.S3InputMaxObjects > 0 {
		s3Values["max_objects"] = strconv.Itoa(c.S3InputMaxObjects)
	}
	add(out.Cloud, "s3", s3Values)

	add(out.Cloud, "cloudtrail", map[string]string{"region": c.CloudTrailRegion, "trail_arn": c.CloudTrailTrailARN})

	return out
}

func (c *Config) RefreshProviderAwareConfig() {
	if c == nil {
		return
	}
	c.Providers = c.BuildProviderAwareConfig()
}

func (c *Config) ProviderValues(name string) map[string]string {
	if c == nil || name == "" {
		return nil
	}

	providers := c.Providers
	if len(providers.Identity) == 0 && len(providers.Cloud) == 0 && len(providers.SaaS) == 0 && len(providers.Endpoint) == 0 && len(providers.Network) == 0 && len(providers.Security) == 0 {
		providers = c.BuildProviderAwareConfig()
	}

	buckets := []map[string]map[string]string{
		providers.Identity,
		providers.Cloud,
		providers.SaaS,
		providers.Endpoint,
		providers.Network,
		providers.Security,
	}

	for _, bucket := range buckets {
		if values, ok := bucket[name]; ok {
			out := make(map[string]string, len(values))
			for key, value := range values {
				out[key] = value
			}
			return out
		}
	}

	return nil
}
