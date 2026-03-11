package app

import (
	"path/filepath"
	"time"

	"github.com/evalops/cerebro/internal/apiauth"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/snowflake"
)

// Config holds all application configuration
type Config struct {
	// Server
	Port                 int
	LogLevel             string
	TracingEnabled       bool
	TracingServiceName   string
	TracingOTLPEndpoint  string
	TracingOTLPInsecure  bool
	TracingOTLPHeaders   map[string]string
	TracingSampleRatio   float64
	TracingExportTimeout time.Duration

	// Snowflake (key-pair auth only)
	SnowflakeAccount    string
	SnowflakeUser       string
	SnowflakePrivateKey string
	SnowflakeDatabase   string
	SnowflakeSchema     string
	SnowflakeWarehouse  string
	SnowflakeRole       string

	// Policies
	PoliciesPath        string
	QueryPolicyRowLimit int

	// LLM Providers
	AnthropicAPIKey string
	OpenAIAPIKey    string

	// Ticketing
	JiraBaseURL          string
	JiraEmail            string
	JiraAPIToken         string
	JiraProject          string
	JiraCloseTransitions []string
	LinearAPIKey         string
	LinearTeamID         string

	// Custom Providers
	CrowdStrikeClientID     string
	CrowdStrikeClientSecret string
	OktaDomain              string
	OktaAPIToken            string

	// Entra ID Provider
	EntraTenantID     string
	EntraClientID     string
	EntraClientSecret string

	// Azure Provider
	AzureTenantID       string
	AzureClientID       string
	AzureClientSecret   string
	AzureSubscriptionID string

	// Snyk Provider
	SnykAPIToken string
	SnykOrgID    string

	// Zoom Provider
	ZoomAccountID    string
	ZoomClientID     string
	ZoomClientSecret string
	ZoomAPIURL       string
	ZoomTokenURL     string

	// Wiz Provider
	WizClientID     string
	WizClientSecret string
	WizAPIURL       string
	WizTokenURL     string
	WizAudience     string

	// Datadog Provider
	DatadogAPIKey string
	DatadogAppKey string
	DatadogSite   string

	// GitHub Provider
	GitHubToken string
	GitHubOrg   string

	// Figma Provider
	FigmaAPIToken string
	FigmaTeamID   string
	FigmaBaseURL  string

	// Socket Provider
	SocketAPIToken string
	SocketOrgSlug  string
	SocketAPIURL   string

	// Ramp Provider
	RampClientID     string
	RampClientSecret string
	RampAPIURL       string
	RampTokenURL     string

	// Gong Provider
	GongAccessKey    string
	GongAccessSecret string
	GongBaseURL      string

	// Vanta Provider
	VantaAPIToken string
	VantaBaseURL  string

	// Panther Provider
	PantherAPIToken string
	PantherBaseURL  string

	// Kolide Provider
	KolideAPIToken string
	KolideBaseURL  string

	// Google Workspace Provider
	GoogleWorkspaceDomain            string
	GoogleWorkspaceAdminEmail        string
	GoogleWorkspaceImpersonatorEmail string
	GoogleWorkspaceCredentialsFile   string
	GoogleWorkspaceCredentialsJSON   string

	// Tailscale Provider
	TailscaleAPIKey  string
	TailscaleTailnet string

	// SentinelOne Provider
	SentinelOneAPIToken string
	SentinelOneBaseURL  string

	// Tenable Provider
	TenableAccessKey string
	TenableSecretKey string

	// Qualys Provider
	QualysUsername string
	QualysPassword string
	QualysPlatform string

	// Semgrep Provider
	SemgrepAPIToken string

	// ServiceNow Provider
	ServiceNowURL      string
	ServiceNowAPIToken string
	ServiceNowUsername string
	ServiceNowPassword string

	// Workday Provider
	WorkdayURL      string
	WorkdayAPIToken string

	// BambooHR Provider
	BambooHRURL      string
	BambooHRAPIToken string

	// OneLogin Provider
	OneLoginURL          string
	OneLoginClientID     string
	OneLoginClientSecret string

	// JumpCloud Provider
	JumpCloudURL      string
	JumpCloudAPIToken string
	JumpCloudOrgID    string

	// Duo Provider
	DuoURL            string
	DuoIntegrationKey string
	DuoSecretKey      string

	// PingIdentity Provider
	PingIdentityEnvironmentID string
	PingIdentityClientID      string
	PingIdentityClientSecret  string
	PingIdentityAPIURL        string
	PingIdentityAuthURL       string

	// CyberArk Provider
	CyberArkURL      string
	CyberArkAPIToken string

	// SailPoint Provider
	SailPointURL      string
	SailPointAPIToken string

	// Saviynt Provider
	SaviyntURL      string
	SaviyntAPIToken string

	// ForgeRock Provider
	ForgeRockURL      string
	ForgeRockAPIToken string

	// Oracle IDCS Provider
	OracleIDCSURL      string
	OracleIDCSAPIToken string

	// GitLab Provider
	GitLabToken   string
	GitLabBaseURL string

	// Terraform Cloud Provider
	TerraformCloudToken string

	// Splunk Provider
	SplunkURL   string
	SplunkToken string

	// Auth0 Provider
	Auth0Domain       string
	Auth0ClientID     string
	Auth0ClientSecret string

	// Cloudflare Provider
	CloudflareAPIToken string

	// Salesforce Provider
	SalesforceInstanceURL   string
	SalesforceClientID      string
	SalesforceClientSecret  string
	SalesforceUsername      string
	SalesforcePassword      string
	SalesforceSecurityToken string

	// Vault Provider
	VaultAddress   string
	VaultToken     string
	VaultNamespace string

	// Slack Provider (data source sync)
	SlackAPIToken string

	// Rippling Provider
	RipplingAPIURL   string
	RipplingAPIToken string

	// Jamf Provider
	JamfBaseURL      string
	JamfClientID     string
	JamfClientSecret string

	// Intune Provider
	IntuneTenantID     string
	IntuneClientID     string
	IntuneClientSecret string

	// Kandji Provider
	KandjiAPIURL   string
	KandjiAPIToken string

	// S3 Input Provider
	S3InputBucket     string
	S3InputPrefix     string
	S3InputRegion     string
	S3InputFormat     string
	S3InputMaxObjects int

	// CloudTrail Provider
	CloudTrailRegion       string
	CloudTrailTrailARN     string
	CloudTrailLookbackDays int

	// Webhooks
	WebhookURLs []string

	// NATS JetStream event publishing
	NATSJetStreamEnabled               bool
	NATSJetStreamURLs                  []string
	NATSJetStreamStream                string
	NATSJetStreamSubjectPrefix         string
	NATSJetStreamSource                string
	NATSJetStreamOutboxPath            string
	NATSJetStreamOutboxDLQPath         string
	NATSJetStreamOutboxMaxAge          time.Duration
	NATSJetStreamOutboxMaxItems        int
	NATSJetStreamOutboxMaxRetry        int
	NATSJetStreamOutboxWarnPercent     int
	NATSJetStreamOutboxCriticalPercent int
	NATSJetStreamOutboxWarnAge         time.Duration
	NATSJetStreamOutboxCriticalAge     time.Duration
	NATSJetStreamPublishTimeout        time.Duration
	NATSJetStreamRetryAttempts         int
	NATSJetStreamRetryBackoff          time.Duration
	NATSJetStreamFlushInterval         time.Duration
	NATSJetStreamConnectTimeout        time.Duration
	NATSJetStreamAuthMode              string
	NATSJetStreamUsername              string
	NATSJetStreamPassword              string
	NATSJetStreamNKeySeed              string
	NATSJetStreamUserJWT               string
	NATSJetStreamTLSEnabled            bool
	NATSJetStreamTLSCAFile             string
	NATSJetStreamTLSCertFile           string
	NATSJetStreamTLSKeyFile            string
	NATSJetStreamTLSServerName         string
	NATSJetStreamTLSInsecure           bool

	// NATS JetStream consumer for ensemble-tap ingestion
	NATSConsumerEnabled             bool
	NATSConsumerStream              string
	NATSConsumerSubjects            []string
	NATSConsumerDurable             string
	NATSConsumerBatchSize           int
	NATSConsumerAckWait             time.Duration
	NATSConsumerFetchTimeout        time.Duration
	NATSConsumerDeadLetterPath      string
	NATSConsumerDropHealthLookback  time.Duration
	NATSConsumerDropHealthThreshold int

	// Event alert routing to Ensemble channels/DMs
	AlertRouterEnabled      bool
	AlertRouterConfigPath   string
	AlertRouterNotifyPrefix string

	// Remote tool proxy for AI agents (Ensemble tools via NATS request/reply)
	AgentRemoteToolsEnabled         bool
	AgentRemoteToolsManifestSubject string
	AgentRemoteToolsRequestPrefix   string
	AgentRemoteToolsDiscoverTimeout time.Duration
	AgentRemoteToolsRequestTimeout  time.Duration
	AgentRemoteToolsMaxTools        int

	// Cerebro tool publisher for external orchestrators (for example Ensemble)
	AgentToolPublisherEnabled         bool
	AgentToolPublisherManifestSubject string
	AgentToolPublisherRequestPrefix   string
	AgentToolPublisherRequestTimeout  time.Duration

	// Tool-specific approval policy for published Cerebro tools
	CerebroSimulateNeedsApproval     bool
	CerebroAccessReviewNeedsApproval bool

	// Notifications
	SlackWebhookURL    string
	SlackSigningSecret string
	PagerDutyKey       string

	// Scheduler
	ScanInterval              string // e.g., "1h", "30m"
	SecurityDigestInterval    string // e.g., "24h", "168h"
	ScanTables                string // comma-separated list of tables to scan
	RetentionJobInterval      time.Duration
	AuditRetentionDays        int
	SessionRetentionDays      int
	GraphRetentionDays        int
	AccessReviewRetentionDays int
	ScanTableTimeout          time.Duration
	ScanMaxConcurrent         int
	ScanMinConcurrent         int
	ScanAdaptiveConcurrency   bool
	ScanRetryAttempts         int
	ScanRetryBackoff          time.Duration
	ScanRetryMaxBackoff       time.Duration

	// Finding attestation chain
	FindingAttestationEnabled          bool
	FindingAttestationSigningKey       string
	FindingAttestationKeyID            string
	FindingAttestationLogURL           string
	FindingAttestationTimeout          time.Duration
	FindingAttestationAttestReobserved bool

	// Distributed jobs
	JobQueueURL             string
	JobTableName            string
	JobRegion               string
	JobWorkerConcurrency    int
	JobVisibilityTimeout    time.Duration
	JobPollWait             time.Duration
	JobMaxAttempts          int
	JobIdempotencyTableName string

	// Rate Limiting
	RateLimitEnabled        bool
	RateLimitRequests       int
	RateLimitWindow         time.Duration
	RateLimitTrustedProxies []string
	CORSAllowedOrigins      []string

	// API Authentication
	APIAuthEnabled                      bool
	APIKeys                             map[string]string
	APICredentials                      map[string]apiauth.Credential
	APICredentialStateFile              string
	APIAuthorizationServers             []string
	SecretsReloadInterval               time.Duration
	RBACStateFile                       string
	PlatformReportRunStateFile          string
	PlatformReportSnapshotPath          string
	GraphCrossTenantRequireSignedIngest bool
	GraphCrossTenantSigningKey          string
	GraphCrossTenantSignatureSkew       time.Duration
	GraphCrossTenantReplayTTL           time.Duration
	GraphCrossTenantMinTenants          int
	GraphCrossTenantMinSupport          int
	GraphSchemaValidationMode           string
	GraphEventMapperValidationMode      string
	GraphEventMapperDeadLetterPath      string
	GraphMigrateLegacyActivityOnStart   bool
	GraphOntologyFallbackWarnPct        float64
	GraphOntologyFallbackCriticalPct    float64
	GraphOntologySchemaValidWarnPct     float64
	GraphOntologySchemaValidCriticalPct float64

	// Nested provider-aware view (derived from flat env-backed fields)
	Providers ProviderAwareConfig
}

func LoadConfig() *Config {
	apiKeys := parseAPIKeys(getEnv("API_KEYS", ""))
	apiCredentials, err := apiauth.ParseCredentialsJSON(getEnv("API_CREDENTIALS_JSON", ""))
	if err != nil {
		apiCredentials = map[string]apiauth.Credential{}
	}
	if len(apiCredentials) == 0 {
		apiCredentials = make(map[string]apiauth.Credential, len(apiKeys))
		for key, userID := range apiKeys {
			apiCredentials[key] = apiauth.DefaultCredentialForAPIKey(key, userID)
		}
	}
	apiKeys = apiauth.CredentialsToUserMap(apiCredentials)
	apiAuthEnabled := getEnvBool("API_AUTH_ENABLED", len(apiKeys) > 0)

	cfg := &Config{
		Port:                                getEnvInt("API_PORT", 8080),
		LogLevel:                            getEnv("LOG_LEVEL", "info"),
		TracingEnabled:                      getEnvBool("CEREBRO_OTEL_ENABLED", false),
		TracingServiceName:                  getEnv("CEREBRO_OTEL_SERVICE_NAME", "cerebro"),
		TracingOTLPEndpoint:                 getEnv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")),
		TracingOTLPInsecure:                 getEnvBool("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false)),
		TracingOTLPHeaders:                  parseKeyValueCSV(getEnv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", getEnv("OTEL_EXPORTER_OTLP_HEADERS", ""))),
		TracingSampleRatio:                  getEnvFloat("CEREBRO_OTEL_SAMPLE_RATIO", 1.0),
		TracingExportTimeout:                getEnvDuration("CEREBRO_OTEL_EXPORT_TIMEOUT", 5*time.Second),
		SnowflakeAccount:                    getEnv("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:                       getEnv("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey:                 normalizePrivateKey(getEnv("SNOWFLAKE_PRIVATE_KEY", "")),
		SnowflakeDatabase:                   getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:                     getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeWarehouse:                  getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeRole:                       getEnv("SNOWFLAKE_ROLE", ""),
		PoliciesPath:                        getEnv("POLICIES_PATH", "policies"),
		QueryPolicyRowLimit:                 getEnvInt("QUERY_POLICY_ROW_LIMIT", snowflake.MaxReadOnlyQueryLimit),
		AnthropicAPIKey:                     getEnv("ANTHROPIC_API_KEY", ""),
		OpenAIAPIKey:                        getEnv("OPENAI_API_KEY", ""),
		JiraBaseURL:                         getEnv("JIRA_BASE_URL", ""),
		JiraEmail:                           getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:                        getEnv("JIRA_API_TOKEN", ""),
		JiraProject:                         getEnv("JIRA_PROJECT", "SEC"),
		JiraCloseTransitions:                splitCSV(getEnv("JIRA_CLOSE_TRANSITIONS", "Done,Closed,Resolve Issue")),
		LinearAPIKey:                        getEnv("LINEAR_API_KEY", ""),
		LinearTeamID:                        getEnv("LINEAR_TEAM_ID", ""),
		CrowdStrikeClientID:                 getEnv("CROWDSTRIKE_CLIENT_ID", ""),
		CrowdStrikeClientSecret:             getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
		OktaDomain:                          getEnv("OKTA_DOMAIN", ""),
		OktaAPIToken:                        getEnv("OKTA_API_TOKEN", ""),
		EntraTenantID:                       getEnv("ENTRA_TENANT_ID", ""),
		EntraClientID:                       getEnv("ENTRA_CLIENT_ID", ""),
		EntraClientSecret:                   getEnv("ENTRA_CLIENT_SECRET", ""),
		AzureTenantID:                       getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:                       getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret:                   getEnv("AZURE_CLIENT_SECRET", ""),
		AzureSubscriptionID:                 getEnv("AZURE_SUBSCRIPTION_ID", ""),
		SnykAPIToken:                        getEnv("SNYK_API_TOKEN", ""),
		SnykOrgID:                           getEnv("SNYK_ORG_ID", ""),
		ZoomAccountID:                       getEnv("ZOOM_ACCOUNT_ID", ""),
		ZoomClientID:                        getEnv("ZOOM_CLIENT_ID", ""),
		ZoomClientSecret:                    getEnv("ZOOM_CLIENT_SECRET", ""),
		ZoomAPIURL:                          getEnv("ZOOM_API_URL", "https://api.zoom.us/v2"),
		ZoomTokenURL:                        getEnv("ZOOM_TOKEN_URL", "https://zoom.us/oauth/token"),
		WizClientID:                         getEnv("WIZ_CLIENT_ID", ""),
		WizClientSecret:                     getEnv("WIZ_CLIENT_SECRET", ""),
		WizAPIURL:                           getEnv("WIZ_API_URL", ""),
		WizTokenURL:                         getEnv("WIZ_TOKEN_URL", "https://auth.app.wiz.io/oauth/token"),
		WizAudience:                         getEnv("WIZ_AUDIENCE", "wiz-api"),
		DatadogAPIKey:                       getEnv("DATADOG_API_KEY", ""),
		DatadogAppKey:                       getEnv("DATADOG_APP_KEY", ""),
		DatadogSite:                         getEnv("DATADOG_SITE", "datadoghq.com"),
		GitHubToken:                         getEnv("GITHUB_TOKEN", ""),
		GitHubOrg:                           getEnv("GITHUB_ORG", ""),
		FigmaAPIToken:                       getEnv("FIGMA_API_TOKEN", ""),
		FigmaTeamID:                         getEnv("FIGMA_TEAM_ID", ""),
		FigmaBaseURL:                        getEnv("FIGMA_BASE_URL", "https://api.figma.com"),
		SocketAPIToken:                      getEnv("SOCKET_API_TOKEN", ""),
		SocketOrgSlug:                       getEnv("SOCKET_ORG", ""),
		SocketAPIURL:                        getEnv("SOCKET_API_URL", "https://api.socket.dev/v0"),
		RampClientID:                        getEnv("RAMP_CLIENT_ID", ""),
		RampClientSecret:                    getEnv("RAMP_CLIENT_SECRET", ""),
		RampAPIURL:                          getEnv("RAMP_API_URL", "https://api.ramp.com/developer/v1"),
		RampTokenURL:                        getEnv("RAMP_TOKEN_URL", "https://api.ramp.com/developer/v1/token"),
		GongAccessKey:                       getEnv("GONG_ACCESS_KEY", ""),
		GongAccessSecret:                    getEnv("GONG_ACCESS_SECRET", ""),
		GongBaseURL:                         getEnv("GONG_BASE_URL", "https://api.gong.io"),
		VantaAPIToken:                       getEnv("VANTA_API_TOKEN", ""),
		VantaBaseURL:                        getEnv("VANTA_BASE_URL", "https://api.vanta.com"),
		PantherAPIToken:                     getEnv("PANTHER_API_TOKEN", ""),
		PantherBaseURL:                      getEnv("PANTHER_BASE_URL", "https://api.runpanther.io/public_api/v1"),
		KolideAPIToken:                      getEnv("KOLIDE_API_TOKEN", ""),
		KolideBaseURL:                       getEnv("KOLIDE_BASE_URL", "https://api.kolide.com/v1"),
		GoogleWorkspaceDomain:               getEnv("GOOGLE_WORKSPACE_DOMAIN", ""),
		GoogleWorkspaceAdminEmail:           getEnv("GOOGLE_WORKSPACE_ADMIN_EMAIL", ""),
		GoogleWorkspaceImpersonatorEmail:    getEnv("GOOGLE_WORKSPACE_IMPERSONATOR_EMAIL", ""),
		GoogleWorkspaceCredentialsFile:      getEnv("GOOGLE_WORKSPACE_CREDENTIALS_FILE", ""),
		GoogleWorkspaceCredentialsJSON:      getEnv("GOOGLE_WORKSPACE_CREDENTIALS_JSON", ""),
		TailscaleAPIKey:                     getEnv("TAILSCALE_API_KEY", ""),
		TailscaleTailnet:                    getEnv("TAILSCALE_TAILNET", ""),
		SentinelOneAPIToken:                 getEnv("SENTINELONE_API_TOKEN", ""),
		SentinelOneBaseURL:                  getEnv("SENTINELONE_BASE_URL", ""),
		TenableAccessKey:                    getEnv("TENABLE_ACCESS_KEY", ""),
		TenableSecretKey:                    getEnv("TENABLE_SECRET_KEY", ""),
		QualysUsername:                      getEnv("QUALYS_USERNAME", ""),
		QualysPassword:                      getEnv("QUALYS_PASSWORD", ""),
		QualysPlatform:                      getEnv("QUALYS_PLATFORM", "US1"),
		SemgrepAPIToken:                     getEnv("SEMGREP_API_TOKEN", ""),
		ServiceNowURL:                       getEnv("SERVICENOW_URL", ""),
		ServiceNowAPIToken:                  getEnv("SERVICENOW_API_TOKEN", ""),
		ServiceNowUsername:                  getEnv("SERVICENOW_USERNAME", ""),
		ServiceNowPassword:                  getEnv("SERVICENOW_PASSWORD", ""),
		WorkdayURL:                          getEnv("WORKDAY_URL", ""),
		WorkdayAPIToken:                     getEnv("WORKDAY_API_TOKEN", ""),
		BambooHRURL:                         getEnv("BAMBOOHR_URL", ""),
		BambooHRAPIToken:                    getEnv("BAMBOOHR_API_TOKEN", ""),
		OneLoginURL:                         getEnv("ONELOGIN_URL", ""),
		OneLoginClientID:                    getEnv("ONELOGIN_CLIENT_ID", ""),
		OneLoginClientSecret:                getEnv("ONELOGIN_CLIENT_SECRET", ""),
		JumpCloudURL:                        getEnv("JUMPCLOUD_URL", "https://console.jumpcloud.com"),
		JumpCloudAPIToken:                   getEnv("JUMPCLOUD_API_TOKEN", ""),
		JumpCloudOrgID:                      getEnv("JUMPCLOUD_ORG_ID", ""),
		DuoURL:                              getEnv("DUO_URL", getEnv("DUO_API_HOSTNAME", "")),
		DuoIntegrationKey:                   getEnv("DUO_INTEGRATION_KEY", getEnv("DUO_IKEY", "")),
		DuoSecretKey:                        getEnv("DUO_SECRET_KEY", getEnv("DUO_SKEY", "")),
		PingIdentityEnvironmentID:           getEnv("PINGIDENTITY_ENVIRONMENT_ID", getEnv("PINGONE_ENVIRONMENT_ID", "")),
		PingIdentityClientID:                getEnv("PINGIDENTITY_CLIENT_ID", getEnv("PINGONE_CLIENT_ID", "")),
		PingIdentityClientSecret:            getEnv("PINGIDENTITY_CLIENT_SECRET", getEnv("PINGONE_CLIENT_SECRET", "")),
		PingIdentityAPIURL:                  getEnv("PINGIDENTITY_API_URL", "https://api.pingone.com"),
		PingIdentityAuthURL:                 getEnv("PINGIDENTITY_AUTH_URL", "https://auth.pingone.com"),
		CyberArkURL:                         getEnv("CYBERARK_URL", ""),
		CyberArkAPIToken:                    getEnv("CYBERARK_API_TOKEN", ""),
		SailPointURL:                        getEnv("SAILPOINT_URL", ""),
		SailPointAPIToken:                   getEnv("SAILPOINT_API_TOKEN", ""),
		SaviyntURL:                          getEnv("SAVIYNT_URL", ""),
		SaviyntAPIToken:                     getEnv("SAVIYNT_API_TOKEN", ""),
		ForgeRockURL:                        getEnv("FORGEROCK_URL", ""),
		ForgeRockAPIToken:                   getEnv("FORGEROCK_API_TOKEN", ""),
		OracleIDCSURL:                       getEnv("ORACLE_IDCS_URL", ""),
		OracleIDCSAPIToken:                  getEnv("ORACLE_IDCS_API_TOKEN", ""),
		GitLabToken:                         getEnv("GITLAB_TOKEN", ""),
		GitLabBaseURL:                       getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
		TerraformCloudToken:                 getEnv("TFC_TOKEN", ""),
		SplunkURL:                           getEnv("SPLUNK_URL", ""),
		SplunkToken:                         getEnv("SPLUNK_TOKEN", ""),
		Auth0Domain:                         getEnv("AUTH0_DOMAIN", ""),
		Auth0ClientID:                       getEnv("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:                   getEnv("AUTH0_CLIENT_SECRET", ""),
		CloudflareAPIToken:                  getEnv("CLOUDFLARE_API_TOKEN", ""),
		SalesforceInstanceURL:               getEnv("SALESFORCE_INSTANCE_URL", ""),
		SalesforceClientID:                  getEnv("SALESFORCE_CLIENT_ID", ""),
		SalesforceClientSecret:              getEnv("SALESFORCE_CLIENT_SECRET", ""),
		SalesforceUsername:                  getEnv("SALESFORCE_USERNAME", ""),
		SalesforcePassword:                  getEnv("SALESFORCE_PASSWORD", ""),
		SalesforceSecurityToken:             getEnv("SALESFORCE_SECURITY_TOKEN", ""),
		VaultAddress:                        getEnv("VAULT_ADDRESS", ""),
		VaultToken:                          getEnv("VAULT_TOKEN", ""),
		VaultNamespace:                      getEnv("VAULT_NAMESPACE", ""),
		SlackAPIToken:                       getEnv("SLACK_API_TOKEN", ""),
		RipplingAPIURL:                      getEnv("RIPPLING_API_URL", ""),
		RipplingAPIToken:                    getEnv("RIPPLING_API_TOKEN", ""),
		JamfBaseURL:                         getEnv("JAMF_BASE_URL", ""),
		JamfClientID:                        getEnv("JAMF_CLIENT_ID", ""),
		JamfClientSecret:                    getEnv("JAMF_CLIENT_SECRET", ""),
		IntuneTenantID:                      getEnv("INTUNE_TENANT_ID", ""),
		IntuneClientID:                      getEnv("INTUNE_CLIENT_ID", ""),
		IntuneClientSecret:                  getEnv("INTUNE_CLIENT_SECRET", ""),
		KandjiAPIURL:                        getEnv("KANDJI_API_URL", ""),
		KandjiAPIToken:                      getEnv("KANDJI_API_TOKEN", ""),
		S3InputBucket:                       getEnv("S3_INPUT_BUCKET", ""),
		S3InputPrefix:                       getEnv("S3_INPUT_PREFIX", ""),
		S3InputRegion:                       getEnv("S3_INPUT_REGION", getEnv("AWS_REGION", "us-east-1")),
		S3InputFormat:                       getEnv("S3_INPUT_FORMAT", "auto"),
		S3InputMaxObjects:                   getEnvInt("S3_INPUT_MAX_OBJECTS", 200),
		CloudTrailRegion:                    getEnv("CLOUDTRAIL_REGION", ""),
		CloudTrailTrailARN:                  getEnv("CLOUDTRAIL_TRAIL_ARN", ""),
		CloudTrailLookbackDays:              getEnvInt("CLOUDTRAIL_LOOKBACK_DAYS", 7),
		WebhookURLs:                         splitCSV(getEnv("WEBHOOK_URLS", "")),
		NATSJetStreamEnabled:                getEnvBool("NATS_JETSTREAM_ENABLED", false),
		NATSJetStreamURLs:                   splitCSV(getEnv("NATS_URLS", "nats://127.0.0.1:4222")),
		NATSJetStreamStream:                 getEnv("NATS_JETSTREAM_STREAM", "CEREBRO_EVENTS"),
		NATSJetStreamSubjectPrefix:          getEnv("NATS_JETSTREAM_SUBJECT_PREFIX", "cerebro.events"),
		NATSJetStreamSource:                 getEnv("NATS_JETSTREAM_SOURCE", "cerebro"),
		NATSJetStreamOutboxPath:             getEnv("NATS_JETSTREAM_OUTBOX_PATH", filepath.Join(findings.DefaultFilePath(), "jetstream-outbox.jsonl")),
		NATSJetStreamOutboxDLQPath:          getEnv("NATS_JETSTREAM_OUTBOX_DLQ_PATH", ""),
		NATSJetStreamOutboxMaxAge:           getEnvDuration("NATS_JETSTREAM_OUTBOX_MAX_AGE", 7*24*time.Hour),
		NATSJetStreamOutboxMaxItems:         getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_ITEMS", 10000),
		NATSJetStreamOutboxMaxRetry:         getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_RETRY", 10),
		NATSJetStreamOutboxWarnPercent:      getEnvInt("NATS_JETSTREAM_OUTBOX_WARN_PERCENT", 70),
		NATSJetStreamOutboxCriticalPercent:  getEnvInt("NATS_JETSTREAM_OUTBOX_CRITICAL_PERCENT", 90),
		NATSJetStreamOutboxWarnAge:          getEnvDuration("NATS_JETSTREAM_OUTBOX_WARN_AGE", time.Hour),
		NATSJetStreamOutboxCriticalAge:      getEnvDuration("NATS_JETSTREAM_OUTBOX_CRITICAL_AGE", 6*time.Hour),
		NATSJetStreamPublishTimeout:         getEnvDuration("NATS_JETSTREAM_PUBLISH_TIMEOUT", 3*time.Second),
		NATSJetStreamRetryAttempts:          getEnvInt("NATS_JETSTREAM_RETRY_ATTEMPTS", 3),
		NATSJetStreamRetryBackoff:           getEnvDuration("NATS_JETSTREAM_RETRY_BACKOFF", 500*time.Millisecond),
		NATSJetStreamFlushInterval:          getEnvDuration("NATS_JETSTREAM_FLUSH_INTERVAL", 10*time.Second),
		NATSJetStreamConnectTimeout:         getEnvDuration("NATS_JETSTREAM_CONNECT_TIMEOUT", 5*time.Second),
		NATSJetStreamAuthMode:               getEnv("NATS_JETSTREAM_AUTH_MODE", "none"),
		NATSJetStreamUsername:               getEnv("NATS_JETSTREAM_USERNAME", ""),
		NATSJetStreamPassword:               getEnv("NATS_JETSTREAM_PASSWORD", ""),
		NATSJetStreamNKeySeed:               getEnv("NATS_JETSTREAM_NKEY_SEED", ""),
		NATSJetStreamUserJWT:                getEnv("NATS_JETSTREAM_USER_JWT", ""),
		NATSJetStreamTLSEnabled:             getEnvBool("NATS_JETSTREAM_TLS_ENABLED", false),
		NATSJetStreamTLSCAFile:              getEnv("NATS_JETSTREAM_TLS_CA_FILE", ""),
		NATSJetStreamTLSCertFile:            getEnv("NATS_JETSTREAM_TLS_CERT_FILE", ""),
		NATSJetStreamTLSKeyFile:             getEnv("NATS_JETSTREAM_TLS_KEY_FILE", ""),
		NATSJetStreamTLSServerName:          getEnv("NATS_JETSTREAM_TLS_SERVER_NAME", ""),
		NATSJetStreamTLSInsecure:            getEnvBool("NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY", false),
		NATSConsumerEnabled:                 getEnvBool("NATS_CONSUMER_ENABLED", false),
		NATSConsumerStream:                  getEnv("NATS_CONSUMER_STREAM", "ENSEMBLE_TAP"),
		NATSConsumerSubjects:                splitCSV(getEnv("NATS_CONSUMER_SUBJECTS", "ensemble.tap.>")),
		NATSConsumerDurable:                 getEnv("NATS_CONSUMER_DURABLE", "cerebro_graph_builder"),
		NATSConsumerBatchSize:               getEnvInt("NATS_CONSUMER_BATCH_SIZE", 50),
		NATSConsumerAckWait:                 getEnvDuration("NATS_CONSUMER_ACK_WAIT", 30*time.Second),
		NATSConsumerFetchTimeout:            getEnvDuration("NATS_CONSUMER_FETCH_TIMEOUT", 2*time.Second),
		NATSConsumerDeadLetterPath:          getEnv("NATS_CONSUMER_DEAD_LETTER_PATH", filepath.Join(findings.DefaultFilePath(), "nats-consumer.dlq.jsonl")),
		NATSConsumerDropHealthLookback:      getEnvDuration("NATS_CONSUMER_DROP_HEALTH_LOOKBACK", 5*time.Minute),
		NATSConsumerDropHealthThreshold:     getEnvInt("NATS_CONSUMER_DROP_HEALTH_THRESHOLD", 1),
		AlertRouterEnabled:                  getEnvBool("ALERT_ROUTER_ENABLED", true),
		AlertRouterConfigPath:               getEnv("ALERT_ROUTER_CONFIG_PATH", ""),
		AlertRouterNotifyPrefix:             getEnv("ALERT_ROUTER_NOTIFY_PREFIX", "ensemble.notify"),
		AgentRemoteToolsEnabled:             getEnvBool("AGENT_REMOTE_TOOLS_ENABLED", false),
		AgentRemoteToolsManifestSubject:     getEnv("AGENT_REMOTE_TOOLS_MANIFEST_SUBJECT", "ensemble.tools.manifest"),
		AgentRemoteToolsRequestPrefix:       getEnv("AGENT_REMOTE_TOOLS_REQUEST_PREFIX", "ensemble.tools.request"),
		AgentRemoteToolsDiscoverTimeout:     getEnvDuration("AGENT_REMOTE_TOOLS_DISCOVER_TIMEOUT", 5*time.Second),
		AgentRemoteToolsRequestTimeout:      getEnvDuration("AGENT_REMOTE_TOOLS_REQUEST_TIMEOUT", 30*time.Second),
		AgentRemoteToolsMaxTools:            getEnvInt("AGENT_REMOTE_TOOLS_MAX_TOOLS", 200),
		AgentToolPublisherEnabled:           getEnvBool("AGENT_TOOL_PUBLISHER_ENABLED", false),
		AgentToolPublisherManifestSubject:   getEnv("AGENT_TOOL_PUBLISHER_MANIFEST_SUBJECT", "cerebro.tools.manifest"),
		AgentToolPublisherRequestPrefix:     getEnv("AGENT_TOOL_PUBLISHER_REQUEST_PREFIX", "cerebro.tools.request"),
		AgentToolPublisherRequestTimeout:    getEnvDuration("AGENT_TOOL_PUBLISHER_REQUEST_TIMEOUT", 30*time.Second),
		CerebroSimulateNeedsApproval:        getEnvBool("CEREBRO_TOOL_SIMULATE_REQUIRES_APPROVAL", true),
		CerebroAccessReviewNeedsApproval:    getEnvBool("CEREBRO_TOOL_ACCESS_REVIEW_REQUIRES_APPROVAL", true),
		SlackWebhookURL:                     getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:                  getEnv("SLACK_SIGNING_SECRET", ""),
		PagerDutyKey:                        getEnv("PAGERDUTY_ROUTING_KEY", ""),
		ScanInterval:                        getEnv("SCAN_INTERVAL", ""),
		SecurityDigestInterval:              getEnv("SECURITY_DIGEST_INTERVAL", ""),
		ScanTables:                          getEnv("SCAN_TABLES", ""),
		RetentionJobInterval:                getEnvDuration("CEREBRO_RETENTION_JOB_INTERVAL", 24*time.Hour),
		AuditRetentionDays:                  getEnvInt("CEREBRO_AUDIT_RETENTION_DAYS", 0),
		SessionRetentionDays:                getEnvInt("CEREBRO_SESSION_RETENTION_DAYS", 0),
		GraphRetentionDays:                  getEnvInt("CEREBRO_GRAPH_RETENTION_DAYS", 0),
		AccessReviewRetentionDays:           getEnvInt("CEREBRO_ACCESS_REVIEW_RETENTION_DAYS", 0),
		ScanTableTimeout:                    getEnvDuration("SCAN_TABLE_TIMEOUT", 30*time.Minute),
		ScanMaxConcurrent:                   getEnvInt("SCAN_MAX_CONCURRENCY", 6),
		ScanMinConcurrent:                   getEnvInt("SCAN_MIN_CONCURRENCY", 2),
		ScanAdaptiveConcurrency:             getEnvBool("SCAN_ADAPTIVE_CONCURRENCY", true),
		ScanRetryAttempts:                   getEnvInt("SCAN_RETRY_ATTEMPTS", 3),
		ScanRetryBackoff:                    getEnvDuration("SCAN_RETRY_BACKOFF", 2*time.Second),
		ScanRetryMaxBackoff:                 getEnvDuration("SCAN_RETRY_MAX_BACKOFF", 30*time.Second),
		FindingAttestationEnabled:           getEnvBool("FINDING_ATTESTATION_ENABLED", false),
		FindingAttestationSigningKey:        normalizePrivateKey(getEnv("FINDING_ATTESTATION_SIGNING_KEY", "")),
		FindingAttestationKeyID:             getEnv("FINDING_ATTESTATION_KEY_ID", ""),
		FindingAttestationLogURL:            getEnv("FINDING_ATTESTATION_LOG_URL", ""),
		FindingAttestationTimeout:           getEnvDuration("FINDING_ATTESTATION_TIMEOUT", 3*time.Second),
		FindingAttestationAttestReobserved:  getEnvBool("FINDING_ATTESTATION_ATTEST_REOBSERVED", false),
		JobQueueURL:                         getEnv("JOB_QUEUE_URL", ""),
		JobTableName:                        getEnv("JOB_TABLE_NAME", ""),
		JobRegion:                           getEnv("JOB_REGION", getEnv("AWS_REGION", "")),
		JobWorkerConcurrency:                getEnvInt("JOB_WORKER_CONCURRENCY", 4),
		JobVisibilityTimeout:                getEnvDuration("JOB_VISIBILITY_TIMEOUT", 30*time.Second),
		JobPollWait:                         getEnvDuration("JOB_POLL_WAIT", 10*time.Second),
		JobMaxAttempts:                      getEnvInt("JOB_MAX_ATTEMPTS", 3),
		JobIdempotencyTableName:             getEnv("JOB_IDEMPOTENCY_TABLE_NAME", ""),
		RateLimitEnabled:                    getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests:                   getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:                     getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
		RateLimitTrustedProxies:             splitCSV(getEnv("RATE_LIMIT_TRUSTED_PROXIES", "")),
		CORSAllowedOrigins:                  splitCSV(getEnv("API_CORS_ALLOWED_ORIGINS", "")),
		APIAuthEnabled:                      apiAuthEnabled,
		APIKeys:                             apiKeys,
		APICredentials:                      apiCredentials,
		APICredentialStateFile:              getEnv("API_CREDENTIAL_STATE_FILE", filepath.Join(".cerebro", "api-credentials", "state.json")),
		APIAuthorizationServers:             splitCSV(getEnv("API_AUTHORIZATION_SERVERS", "")),
		SecretsReloadInterval:               getEnvDuration("CEREBRO_SECRETS_RELOAD_INTERVAL", 0),
		RBACStateFile:                       getEnv("RBAC_STATE_FILE", ""),
		PlatformReportRunStateFile:          getEnv("PLATFORM_REPORT_RUN_STATE_FILE", filepath.Join(".cerebro", "report-runs", "state.json")),
		PlatformReportSnapshotPath:          getEnv("PLATFORM_REPORT_SNAPSHOT_PATH", filepath.Join(".cerebro", "report-runs", "snapshots")),
		GraphCrossTenantRequireSignedIngest: getEnvBool("GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST", false),
		GraphCrossTenantSigningKey:          getEnv("GRAPH_CROSS_TENANT_SIGNING_KEY", ""),
		GraphCrossTenantSignatureSkew:       getEnvDuration("GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW", 5*time.Minute),
		GraphCrossTenantReplayTTL:           getEnvDuration("GRAPH_CROSS_TENANT_REPLAY_TTL", 24*time.Hour),
		GraphCrossTenantMinTenants:          getEnvInt("GRAPH_CROSS_TENANT_MIN_TENANTS", 2),
		GraphCrossTenantMinSupport:          getEnvInt("GRAPH_CROSS_TENANT_MIN_SUPPORT", 2),
		GraphSchemaValidationMode:           getEnv("GRAPH_SCHEMA_VALIDATION_MODE", "warn"),
		GraphEventMapperValidationMode:      getEnv("GRAPH_EVENT_MAPPER_VALIDATION_MODE", "enforce"),
		GraphEventMapperDeadLetterPath:      getEnv("GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH", filepath.Join(findings.DefaultFilePath(), "graph-event-mapper.dlq.jsonl")),
		GraphMigrateLegacyActivityOnStart:   getEnvBool("GRAPH_MIGRATE_LEGACY_ACTIVITY_ON_START", false),
		GraphOntologyFallbackWarnPct:        getEnvFloat("GRAPH_ONTOLOGY_FALLBACK_WARN_PERCENT", 12),
		GraphOntologyFallbackCriticalPct:    getEnvFloat("GRAPH_ONTOLOGY_FALLBACK_CRITICAL_PERCENT", 25),
		GraphOntologySchemaValidWarnPct:     getEnvFloat("GRAPH_ONTOLOGY_SCHEMA_VALID_WARN_PERCENT", 98),
		GraphOntologySchemaValidCriticalPct: getEnvFloat("GRAPH_ONTOLOGY_SCHEMA_VALID_CRITICAL_PERCENT", 92),
	}

	cfg.RefreshProviderAwareConfig()
	return cfg
}
