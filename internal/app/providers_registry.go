package app

import (
	"context"
	"reflect"
	"strings"

	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/snowflake"
)

type providerRegistration struct {
	name        string
	constructor func() providers.Provider
	enabled     func(*Config) bool
	buildConfig func(*Config) map[string]interface{}
}

func (a *App) initProviders(ctx context.Context) {
	a.Providers = a.buildProviders(ctx, a.Config)
	metrics.SetProviderCountMetrics(len(a.Providers.List()), len(providers.ImplementedProviderNames()))
}

func (a *App) rebuildProviders(ctx context.Context, cfg *Config) {
	a.Providers = a.buildProviders(ctx, cfg)
	metrics.SetProviderCountMetrics(len(a.Providers.List()), len(providers.ImplementedProviderNames()))
}

func (a *App) buildProviders(ctx context.Context, cfg *Config) *providers.Registry {
	registry := providers.NewRegistry()
	a.registerConfiguredProviders(ctx, cfg, registry)
	return registry
}

func (a *App) registerConfiguredProviders(ctx context.Context, cfg *Config, registry *providers.Registry) {
	if cfg != nil {
		cfg.RefreshProviderAwareConfig()
	}

	registerProvider := func(name string, p providers.Provider, config map[string]interface{}) {
		metadata := providers.ProviderMetadataFor(name)
		if providers.IsProviderIncomplete(name) {
			a.Logger.Info("provider marked as incomplete, skipping registration",
				"provider", name,
				"maturity", metadata.Maturity)
			return
		}

		if setter, ok := p.(interface{ SetSnowflakeClient(*snowflake.Client) }); ok {
			setter.SetSnowflakeClient(a.Snowflake)
		}
		if err := p.Configure(ctx, config); err != nil {
			a.Logger.Warn("provider configuration failed, skipping registration",
				"provider", name,
				"error", err)
			return
		}
		registeredProvider := p
		if p.Type() == providers.ProviderTypeEndpoint {
			registeredProvider = providers.WithSyncHook(p, a.endpointProviderSyncHook)
		}
		registry.Register(registeredProvider)
		a.Logger.Info("provider registered", "provider", name, "maturity", metadata.Maturity)
	}

	for _, registration := range providerRegistrations() {
		if !registration.enabled(cfg) {
			continue
		}
		providerConfig := registration.buildConfig(cfg)
		var providerValues map[string]string
		if cfg != nil {
			providerValues = cfg.ProviderValues(registration.name)
		}
		providerConfig = mergeProviderAwareConfig(providerConfig, providerValues)
		registerProvider(registration.name, registration.constructor(), providerConfig)
	}

	a.registerS3Sources(ctx, registerProvider)
}

func (a *App) registerS3Sources(ctx context.Context, registerProvider func(string, providers.Provider, map[string]interface{})) {
	if a.Config == nil {
		return
	}
	for _, src := range a.Config.S3Sources {
		cfg := map[string]interface{}{
			"bucket":                 src.Bucket,
			"prefixes":               src.Prefixes,
			"region":                 src.Region,
			"format":                 src.Format,
			"role_arn":               src.RoleARN,
			"external_id":            src.ExternalID,
			"max_objects":            src.MaxObjects,
			"max_records_per_object": src.MaxRecordsPerObject,
		}
		p := providers.NewS3SourceProvider(src.Name)
		registerProvider(p.Name(), p, cfg)
	}
}

func providerConfigsChanged(current, next *Config) bool {
	return !reflect.DeepEqual(providerConfigsSnapshot(current), providerConfigsSnapshot(next))
}

func providerConfigsSnapshot(cfg *Config) map[string]map[string]interface{} {
	snapshot := make(map[string]map[string]interface{})
	if cfg == nil {
		return snapshot
	}
	cfg.RefreshProviderAwareConfig()
	for _, registration := range providerRegistrations() {
		if !registration.enabled(cfg) {
			continue
		}
		providerConfig := registration.buildConfig(cfg)
		providerValues := cfg.ProviderValues(registration.name)
		providerConfig = mergeProviderAwareConfig(providerConfig, providerValues)
		snapshot[registration.name] = providerConfig
	}
	return snapshot
}

func mergeProviderAwareConfig(base map[string]interface{}, providerValues map[string]string) map[string]interface{} {
	if len(base) == 0 && len(providerValues) == 0 {
		return nil
	}

	out := make(map[string]interface{}, len(base))
	for key, value := range base {
		out[key] = value
	}

	for key, value := range providerValues {
		if strings.TrimSpace(value) == "" {
			continue
		}
		current, exists := out[key]
		if !exists {
			continue
		}
		if isEmptyProviderConfigValue(current) {
			out[key] = value
		}
	}

	return out
}

func isEmptyProviderConfigValue(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	}
	return false
}

func providerRegistrations() []providerRegistration {
	return []providerRegistration{
		{
			name:        "crowdstrike",
			constructor: func() providers.Provider { return providers.NewCrowdStrikeProvider() },
			enabled:     func(c *Config) bool { return c.CrowdStrikeClientID != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"client_id": c.CrowdStrikeClientID, "client_secret": c.CrowdStrikeClientSecret}
			},
		},
		{
			name:        "okta",
			constructor: func() providers.Provider { return providers.NewOktaProvider() },
			enabled:     func(c *Config) bool { return c.OktaDomain != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"domain": c.OktaDomain, "api_token": c.OktaAPIToken}
			},
		},
		{
			name:        "entra_id",
			constructor: func() providers.Provider { return providers.NewEntraIDProvider() },
			enabled: func(c *Config) bool {
				return c.EntraTenantID != "" && c.EntraClientID != "" && c.EntraClientSecret != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"tenant_id": c.EntraTenantID, "client_id": c.EntraClientID, "client_secret": c.EntraClientSecret}
			},
		},
		{
			name:        "azure",
			constructor: func() providers.Provider { return providers.NewAzureProvider() },
			enabled:     func(c *Config) bool { return c.AzureTenantID != "" && c.AzureClientID != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"tenant_id": c.AzureTenantID, "client_id": c.AzureClientID, "client_secret": c.AzureClientSecret, "subscription_id": c.AzureSubscriptionID}
			},
		},
		{
			name:        "snyk",
			constructor: func() providers.Provider { return providers.NewSnykProvider() },
			enabled:     func(c *Config) bool { return c.SnykAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.SnykAPIToken, "org_id": c.SnykOrgID}
			},
		},
		{
			name:        "zoom",
			constructor: func() providers.Provider { return providers.NewZoomProvider() },
			enabled: func(c *Config) bool {
				return c.ZoomAccountID != "" && c.ZoomClientID != "" && c.ZoomClientSecret != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"account_id": c.ZoomAccountID, "client_id": c.ZoomClientID, "client_secret": c.ZoomClientSecret, "base_url": c.ZoomAPIURL, "token_url": c.ZoomTokenURL}
			},
		},
		{
			name:        "wiz",
			constructor: func() providers.Provider { return providers.NewWizProvider() },
			enabled: func(c *Config) bool {
				return c.WizClientID != "" && c.WizClientSecret != "" && c.WizAPIURL != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				cfg := map[string]interface{}{"client_id": c.WizClientID, "client_secret": c.WizClientSecret, "api_url": c.WizAPIURL}
				if c.WizTokenURL != "" {
					cfg["token_url"] = c.WizTokenURL
				}
				if c.WizAudience != "" {
					cfg["audience"] = c.WizAudience
				}
				return cfg
			},
		},
		{
			name:        "datadog",
			constructor: func() providers.Provider { return providers.NewDatadogProvider() },
			enabled:     func(c *Config) bool { return c.DatadogAPIKey != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_key": c.DatadogAPIKey, "app_key": c.DatadogAppKey, "site": c.DatadogSite}
			},
		},
		{
			name:        "github",
			constructor: func() providers.Provider { return providers.NewGitHubProvider() },
			enabled:     func(c *Config) bool { return c.GitHubToken != "" && c.GitHubOrg != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"token": c.GitHubToken, "org": c.GitHubOrg}
			},
		},
		{
			name:        "figma",
			constructor: func() providers.Provider { return providers.NewFigmaProvider() },
			enabled:     func(c *Config) bool { return c.FigmaAPIToken != "" && c.FigmaTeamID != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.FigmaAPIToken, "team_id": c.FigmaTeamID, "base_url": c.FigmaBaseURL}
			},
		},
		{
			name:        "socket",
			constructor: func() providers.Provider { return providers.NewSocketProvider() },
			enabled:     func(c *Config) bool { return c.SocketAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.SocketAPIToken, "org_slug": c.SocketOrgSlug, "api_url": c.SocketAPIURL}
			},
		},
		{
			name:        "ramp",
			constructor: func() providers.Provider { return providers.NewRampProvider() },
			enabled:     func(c *Config) bool { return c.RampClientID != "" && c.RampClientSecret != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"client_id": c.RampClientID, "client_secret": c.RampClientSecret, "base_url": c.RampAPIURL, "token_url": c.RampTokenURL}
			},
		},
		{
			name:        "gong",
			constructor: func() providers.Provider { return providers.NewGongProvider() },
			enabled:     func(c *Config) bool { return c.GongAccessKey != "" && c.GongAccessSecret != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"access_key": c.GongAccessKey, "access_secret": c.GongAccessSecret, "base_url": c.GongBaseURL}
			},
		},
		{
			name:        "vanta",
			constructor: func() providers.Provider { return providers.NewVantaProvider() },
			enabled:     func(c *Config) bool { return c.VantaAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.VantaAPIToken, "base_url": c.VantaBaseURL}
			},
		},
		{
			name:        "panther",
			constructor: func() providers.Provider { return providers.NewPantherProvider() },
			enabled:     func(c *Config) bool { return c.PantherAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.PantherAPIToken, "base_url": c.PantherBaseURL}
			},
		},
		{
			name:        "kolide",
			constructor: func() providers.Provider { return providers.NewKolideProvider() },
			enabled:     func(c *Config) bool { return c.KolideAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.KolideAPIToken, "base_url": c.KolideBaseURL}
			},
		},
		{
			name:        "atlassian",
			constructor: func() providers.Provider { return providers.NewAtlassianProvider() },
			enabled:     func(c *Config) bool { return c.JiraBaseURL != "" && c.JiraEmail != "" && c.JiraAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"base_url": c.JiraBaseURL, "email": c.JiraEmail, "api_token": c.JiraAPIToken}
			},
		},
		{
			name:        "google_workspace",
			constructor: func() providers.Provider { return providers.NewGoogleWorkspaceProvider() },
			enabled: func(c *Config) bool {
				return c.GoogleWorkspaceCredentialsJSON != "" || c.GoogleWorkspaceCredentialsFile != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"domain": c.GoogleWorkspaceDomain, "admin_email": c.GoogleWorkspaceAdminEmail, "impersonator_email": c.GoogleWorkspaceImpersonatorEmail, "credentials_file": c.GoogleWorkspaceCredentialsFile, "credentials_json": c.GoogleWorkspaceCredentialsJSON}
			},
		},
		{
			name:        "tailscale",
			constructor: func() providers.Provider { return providers.NewTailscaleProvider() },
			enabled:     func(c *Config) bool { return c.TailscaleAPIKey != "" && c.TailscaleTailnet != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_key": c.TailscaleAPIKey, "tailnet": c.TailscaleTailnet}
			},
		},
		{
			name:        "sentinelone",
			constructor: func() providers.Provider { return providers.NewSentinelOneProvider() },
			enabled:     func(c *Config) bool { return c.SentinelOneAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.SentinelOneAPIToken, "base_url": c.SentinelOneBaseURL}
			},
		},
		{
			name:        "tenable",
			constructor: func() providers.Provider { return providers.NewTenableProvider() },
			enabled:     func(c *Config) bool { return c.TenableAccessKey != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"access_key": c.TenableAccessKey, "secret_key": c.TenableSecretKey}
			},
		},
		{
			name:        "qualys",
			constructor: func() providers.Provider { return providers.NewQualysProvider() },
			enabled:     func(c *Config) bool { return c.QualysUsername != "" && c.QualysPassword != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"username": c.QualysUsername, "password": c.QualysPassword, "platform": c.QualysPlatform}
			},
		},
		{
			name:        "semgrep",
			constructor: func() providers.Provider { return providers.NewSemgrepProvider() },
			enabled:     func(c *Config) bool { return c.SemgrepAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} { return map[string]interface{}{"api_token": c.SemgrepAPIToken} },
		},
		{
			name:        "servicenow",
			constructor: func() providers.Provider { return providers.NewServiceNowProvider() },
			enabled: func(c *Config) bool {
				return c.ServiceNowURL != "" && (c.ServiceNowAPIToken != "" || (c.ServiceNowUsername != "" && c.ServiceNowPassword != ""))
			},
			buildConfig: func(c *Config) map[string]interface{} {
				cfg := map[string]interface{}{"url": c.ServiceNowURL}
				if c.ServiceNowAPIToken != "" {
					cfg["api_token"] = c.ServiceNowAPIToken
				} else {
					cfg["username"] = c.ServiceNowUsername
					cfg["password"] = c.ServiceNowPassword
				}
				return cfg
			},
		},
		{
			name:        "workday",
			constructor: func() providers.Provider { return providers.NewWorkdayProvider() },
			enabled:     func(c *Config) bool { return c.WorkdayURL != "" && c.WorkdayAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.WorkdayURL, "api_token": c.WorkdayAPIToken}
			},
		},
		{
			name:        "bamboohr",
			constructor: func() providers.Provider { return providers.NewBambooHRProvider() },
			enabled:     func(c *Config) bool { return c.BambooHRURL != "" && c.BambooHRAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.BambooHRURL, "api_token": c.BambooHRAPIToken}
			},
		},
		{
			name:        "onelogin",
			constructor: func() providers.Provider { return providers.NewOneLoginProvider() },
			enabled: func(c *Config) bool {
				return c.OneLoginURL != "" && c.OneLoginClientID != "" && c.OneLoginClientSecret != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.OneLoginURL, "client_id": c.OneLoginClientID, "client_secret": c.OneLoginClientSecret}
			},
		},
		{
			name:        "jumpcloud",
			constructor: func() providers.Provider { return providers.NewJumpCloudProvider() },
			enabled:     func(c *Config) bool { return c.JumpCloudAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				cfg := map[string]interface{}{"url": c.JumpCloudURL, "api_token": c.JumpCloudAPIToken}
				if c.JumpCloudOrgID != "" {
					cfg["org_id"] = c.JumpCloudOrgID
				}
				return cfg
			},
		},
		{
			name:        "duo",
			constructor: func() providers.Provider { return providers.NewDuoProvider() },
			enabled:     func(c *Config) bool { return c.DuoURL != "" && c.DuoIntegrationKey != "" && c.DuoSecretKey != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.DuoURL, "integration_key": c.DuoIntegrationKey, "secret_key": c.DuoSecretKey}
			},
		},
		{
			name:        "pingidentity",
			constructor: func() providers.Provider { return providers.NewPingIdentityProvider() },
			enabled: func(c *Config) bool {
				return c.PingIdentityEnvironmentID != "" && c.PingIdentityClientID != "" && c.PingIdentityClientSecret != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				cfg := map[string]interface{}{"environment_id": c.PingIdentityEnvironmentID, "client_id": c.PingIdentityClientID, "client_secret": c.PingIdentityClientSecret}
				if c.PingIdentityAPIURL != "" {
					cfg["api_url"] = c.PingIdentityAPIURL
				}
				if c.PingIdentityAuthURL != "" {
					cfg["auth_url"] = c.PingIdentityAuthURL
				}
				return cfg
			},
		},
		{
			name:        "cyberark",
			constructor: func() providers.Provider { return providers.NewCyberArkProvider() },
			enabled:     func(c *Config) bool { return c.CyberArkURL != "" && c.CyberArkAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.CyberArkURL, "api_token": c.CyberArkAPIToken}
			},
		},
		{
			name:        "sailpoint",
			constructor: func() providers.Provider { return providers.NewSailPointProvider() },
			enabled:     func(c *Config) bool { return c.SailPointURL != "" && c.SailPointAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.SailPointURL, "api_token": c.SailPointAPIToken}
			},
		},
		{
			name:        "saviynt",
			constructor: func() providers.Provider { return providers.NewSaviyntProvider() },
			enabled:     func(c *Config) bool { return c.SaviyntURL != "" && c.SaviyntAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.SaviyntURL, "api_token": c.SaviyntAPIToken}
			},
		},
		{
			name:        "forgerock",
			constructor: func() providers.Provider { return providers.NewForgeRockProvider() },
			enabled:     func(c *Config) bool { return c.ForgeRockURL != "" && c.ForgeRockAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.ForgeRockURL, "api_token": c.ForgeRockAPIToken}
			},
		},
		{
			name:        "oracle_idcs",
			constructor: func() providers.Provider { return providers.NewOracleIDCSProvider() },
			enabled:     func(c *Config) bool { return c.OracleIDCSURL != "" && c.OracleIDCSAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.OracleIDCSURL, "api_token": c.OracleIDCSAPIToken}
			},
		},
		{
			name:        "gitlab",
			constructor: func() providers.Provider { return providers.NewGitLabProvider() },
			enabled:     func(c *Config) bool { return c.GitLabToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"token": c.GitLabToken, "base_url": c.GitLabBaseURL}
			},
		},
		{
			name:        "auth0",
			constructor: func() providers.Provider { return providers.NewAuth0Provider() },
			enabled:     func(c *Config) bool { return c.Auth0Domain != "" && c.Auth0ClientID != "" && c.Auth0ClientSecret != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"domain": c.Auth0Domain, "client_id": c.Auth0ClientID, "client_secret": c.Auth0ClientSecret}
			},
		},
		{
			name:        "terraform_cloud",
			constructor: func() providers.Provider { return providers.NewTerraformCloudProvider() },
			enabled:     func(c *Config) bool { return c.TerraformCloudToken != "" },
			buildConfig: func(c *Config) map[string]interface{} { return map[string]interface{}{"token": c.TerraformCloudToken} },
		},
		{
			name:        "splunk",
			constructor: func() providers.Provider { return providers.NewSplunkProvider() },
			enabled:     func(c *Config) bool { return c.SplunkURL != "" && c.SplunkToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"url": c.SplunkURL, "token": c.SplunkToken}
			},
		},
		{
			name:        "cloudflare",
			constructor: func() providers.Provider { return providers.NewCloudflareProvider() },
			enabled:     func(c *Config) bool { return c.CloudflareAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_token": c.CloudflareAPIToken}
			},
		},
		{
			name:        "salesforce",
			constructor: func() providers.Provider { return providers.NewSalesforceProvider() },
			enabled: func(c *Config) bool {
				return c.SalesforceInstanceURL != "" && c.SalesforceClientID != "" && c.SalesforceClientSecret != "" && c.SalesforceUsername != "" && c.SalesforcePassword != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"instance_url": c.SalesforceInstanceURL, "client_id": c.SalesforceClientID, "client_secret": c.SalesforceClientSecret, "username": c.SalesforceUsername, "password": c.SalesforcePassword, "security_token": c.SalesforceSecurityToken}
			},
		},
		{
			name:        "vault",
			constructor: func() providers.Provider { return providers.NewVaultProvider() },
			enabled:     func(c *Config) bool { return c.VaultAddress != "" && c.VaultToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"address": c.VaultAddress, "token": c.VaultToken, "namespace": c.VaultNamespace}
			},
		},
		{
			name:        "slack",
			constructor: func() providers.Provider { return providers.NewSlackProvider() },
			enabled:     func(c *Config) bool { return c.SlackAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} { return map[string]interface{}{"token": c.SlackAPIToken} },
		},
		{
			name:        "rippling",
			constructor: func() providers.Provider { return providers.NewRipplingProvider() },
			enabled:     func(c *Config) bool { return c.RipplingAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_url": c.RipplingAPIURL, "api_token": c.RipplingAPIToken}
			},
		},
		{
			name:        "jamf",
			constructor: func() providers.Provider { return providers.NewJamfProvider() },
			enabled:     func(c *Config) bool { return c.JamfBaseURL != "" && c.JamfClientID != "" && c.JamfClientSecret != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"base_url": c.JamfBaseURL, "client_id": c.JamfClientID, "client_secret": c.JamfClientSecret}
			},
		},
		{
			name:        "intune",
			constructor: func() providers.Provider { return providers.NewIntuneProvider() },
			enabled: func(c *Config) bool {
				return firstNonEmpty(c.IntuneTenantID, c.EntraTenantID) != "" && firstNonEmpty(c.IntuneClientID, c.EntraClientID) != "" && firstNonEmpty(c.IntuneClientSecret, c.EntraClientSecret) != ""
			},
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{
					"tenant_id":     firstNonEmpty(c.IntuneTenantID, c.EntraTenantID),
					"client_id":     firstNonEmpty(c.IntuneClientID, c.EntraClientID),
					"client_secret": firstNonEmpty(c.IntuneClientSecret, c.EntraClientSecret),
				}
			},
		},
		{
			name:        "kandji",
			constructor: func() providers.Provider { return providers.NewKandjiProvider() },
			enabled:     func(c *Config) bool { return c.KandjiAPIToken != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{"api_url": c.KandjiAPIURL, "api_token": c.KandjiAPIToken}
			},
		},
		{
			name:        "s3",
			constructor: func() providers.Provider { return providers.NewS3Provider() },
			enabled:     func(c *Config) bool { return c.S3InputBucket != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				return map[string]interface{}{
					"bucket":      c.S3InputBucket,
					"prefix":      c.S3InputPrefix,
					"region":      c.S3InputRegion,
					"format":      c.S3InputFormat,
					"max_objects": c.S3InputMaxObjects,
				}
			},
		},
		{
			name:        "cloudtrail",
			constructor: func() providers.Provider { return providers.NewCloudTrailProvider() },
			enabled:     func(c *Config) bool { return c.CloudTrailRegion != "" || c.CloudTrailTrailARN != "" },
			buildConfig: func(c *Config) map[string]interface{} {
				cfg := map[string]interface{}{}
				if c.CloudTrailRegion != "" {
					cfg["region"] = c.CloudTrailRegion
				}
				if c.CloudTrailTrailARN != "" {
					cfg["trail_arn"] = c.CloudTrailTrailARN
				}
				if c.CloudTrailLookbackDays > 0 {
					cfg["lookback_days"] = c.CloudTrailLookbackDays
				}
				return cfg
			},
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
