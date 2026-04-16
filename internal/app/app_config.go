package app

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/secretsource"
	"github.com/writer/cerebro/internal/snowflake"
)

// Config holds all application configuration
type Config struct {
	// Server
	Port                 int
	LogLevel             string
	APIRequestTimeout    time.Duration
	APIReadTimeout       time.Duration
	APIWriteTimeout      time.Duration
	APIIdleTimeout       time.Duration
	APIMaxBodyBytes      int64
	HealthCheckTimeout   time.Duration
	TracingEnabled       bool
	TracingServiceName   string
	TracingOTLPEndpoint  string
	TracingOTLPInsecure  bool
	TracingOTLPHeaders   map[string]string
	TracingSampleRatio   float64
	TracingExportTimeout time.Duration

	// Credential source
	CredentialSource         string
	CredentialFileDir        string
	CredentialVaultAddress   string
	CredentialVaultToken     string
	CredentialVaultNamespace string
	CredentialVaultPath      string
	CredentialVaultKVVersion int

	// Warehouse backend selection
	WarehouseBackend     string
	WarehouseSQLitePath  string
	WarehousePostgresDSN string

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
	JiraBaseURL                      string
	JiraEmail                        string
	JiraAPIToken                     string
	JiraProject                      string
	JiraCloseTransitions             []string
	TicketingProviderValidateTimeout time.Duration
	LinearAPIKey                     string
	LinearTeamID                     string

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
	S3Sources         []providers.S3SourceConfig

	// CloudTrail Provider
	CloudTrailRegion       string
	CloudTrailTrailARN     string
	CloudTrailLookbackDays int

	// Webhooks
	WebhookURLs []string

	// Initialization
	InitTimeout     time.Duration
	ShutdownTimeout time.Duration

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
	NATSConsumerEnabled                 bool
	NATSConsumerStream                  string
	NATSConsumerSubjects                []string
	NATSConsumerDurable                 string
	NATSConsumerBatchSize               int
	NATSConsumerAckWait                 time.Duration
	NATSConsumerFetchTimeout            time.Duration
	NATSConsumerInProgressInterval      time.Duration
	NATSConsumerDrainTimeout            time.Duration
	NATSConsumerDeadLetterPath          string
	NATSConsumerDedupEnabled            bool
	NATSConsumerDedupStateFile          string
	NATSConsumerDedupTTL                time.Duration
	NATSConsumerDedupMaxRecords         int
	NATSConsumerDropHealthLookback      time.Duration
	NATSConsumerDropHealthThreshold     int
	NATSConsumerGraphStalenessThreshold time.Duration

	// Event alert routing to Ensemble channels/DMs
	AlertRouterEnabled      bool
	AlertRouterConfigPath   string
	AlertRouterNotifyPrefix string
	AlertRouterStateFile    string

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
	AgentPendingToolApprovalTTL       time.Duration

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

	// Agentless workload snapshot scanning
	ExecutionStoreFile                 string
	VulnDBStateFile                    string
	MalwareScanClamAVHost              string
	MalwareScanClamAVPort              int
	MalwareScanVirusTotalAPIKey        string
	WorkloadScanStateFile              string
	WorkloadScanMountBasePath          string
	WorkloadScanMaxConcurrentSnapshots int
	WorkloadScanCleanupTimeout         time.Duration
	WorkloadScanReconcileOlderThan     time.Duration
	WorkloadScanTrivyBinary            string
	WorkloadScanGitleaksBinary         string
	WorkloadScanClamAVBinary           string

	// Container image scanning
	ImageScanStateFile      string
	ImageScanRootFSBasePath string
	ImageScanCleanupTimeout time.Duration
	ImageScanTrivyBinary    string
	ImageScanGitleaksBinary string
	ImageScanClamAVBinary   string

	// Serverless function package scanning
	FunctionScanStateFile      string
	FunctionScanRootFSBasePath string
	FunctionScanCleanupTimeout time.Duration
	FunctionScanTrivyBinary    string
	FunctionScanGitleaksBinary string
	FunctionScanClamAVBinary   string
	ScanPoliciesPath           string

	// Finding attestation chain
	FindingsMaxInMemory                int
	FindingsResolvedRetention          time.Duration
	FindingsSemanticDedupEnabled       bool
	FindingAttestationEnabled          bool
	FindingAttestationSigningKey       string
	FindingAttestationKeyID            string
	FindingAttestationLogURL           string
	FindingAttestationTimeout          time.Duration
	FindingAttestationAttestReobserved bool

	// Distributed jobs
	JobDatabaseURL       string
	JobNATSStream        string
	JobNATSSubject       string
	JobNATSConsumer      string
	JobWorkerConcurrency int
	JobVisibilityTimeout time.Duration
	JobPollWait          time.Duration
	JobMaxAttempts       int

	// Rate Limiting
	DevMode                 bool
	DevModeAck              bool
	RateLimitEnabled        bool
	RateLimitRequests       int
	RateLimitWindow         time.Duration
	RateLimitTrustedProxies []string
	CORSAllowedOrigins      []string

	// API Authentication
	APIAuthEnabled                           bool
	APIKeys                                  map[string]string
	APICredentials                           map[string]apiauth.Credential
	APICredentialStateFile                   string
	APIAuthorizationServers                  []string
	SecretsReloadInterval                    time.Duration
	RBACStateFile                            string
	PlatformReportRunStateFile               string
	PlatformReportSnapshotPath               string
	GraphCrossTenantRequireSignedIngest      bool
	GraphCrossTenantSigningKey               string
	GraphCrossTenantSignatureSkew            time.Duration
	GraphCrossTenantReplayTTL                time.Duration
	GraphCrossTenantMinTenants               int
	GraphCrossTenantMinSupport               int
	GraphStoreBackend                        string
	GraphStoreNeptuneEndpoint                string
	GraphStoreNeptuneRegion                  string
	GraphStoreNeptunePoolSize                int
	GraphStoreNeptunePoolHealthCheckInterval time.Duration
	GraphStoreNeptunePoolHealthCheckTimeout  time.Duration
	GraphStoreNeptunePoolMaxClientLifetime   time.Duration
	GraphStoreNeptunePoolMaxClientUses       int
	GraphStoreNeptunePoolDrainTimeout        time.Duration
	GraphSearchBackend                       string
	GraphSearchOpenSearchEndpoint            string
	GraphSearchOpenSearchRegion              string
	GraphSearchOpenSearchIndex               string
	GraphSearchRequestTimeout                time.Duration
	GraphSearchMaxCandidates                 int
	GraphSnapshotPath                        string
	GraphSnapshotMaxRetained                 int
	GraphWriterLeaseEnabled                  bool
	GraphWriterLeaseBucket                   string
	GraphWriterLeaseName                     string
	GraphWriterLeaseOwnerID                  string
	GraphWriterLeaseTTL                      time.Duration
	GraphWriterLeaseHeartbeat                time.Duration
	GraphTenantShardIdleTTL                  time.Duration
	GraphTenantWarmShardTTL                  time.Duration
	GraphTenantWarmShardMaxRetained          int
	GraphPropertyHistoryMaxEntries           int
	GraphPropertyHistoryTTL                  time.Duration
	GraphSchemaValidationMode                string
	GraphEventMapperValidationMode           string
	GraphEventMapperDeadLetterPath           string
	GraphMigrateLegacyActivityOnStart        bool
	GraphConsistencyCheckEnabled             bool
	GraphConsistencyCheckInterval            time.Duration
	GraphConsistencyCheckTimeout             time.Duration
	GraphPostSyncUpdateTimeout               time.Duration
	GraphRiskEngineStateTimeout              time.Duration
	GraphFreshnessDefaultSLA                 time.Duration
	GraphFreshnessProviderSLAs               map[string]time.Duration
	GraphOntologyFallbackWarnPct             float64
	GraphOntologyFallbackCriticalPct         float64
	GraphOntologySchemaValidWarnPct          float64
	GraphOntologySchemaValidCriticalPct      float64

	// Threat intel background sync
	ThreatIntelSyncTimeout  time.Duration
	ThreatIntelSyncMaxAge   time.Duration
	ThreatIntelSyncAttempts int
	ThreatIntelSyncBackoff  time.Duration

	// Nested provider-aware view (derived from flat env-backed fields)
	Providers ProviderAwareConfig

	loadProblems []string
}

func LoadConfig() *Config {
	var cfg Config
	cfg.loadProblems = withConfigParseRecorder(func() {
		credentialSourceSettings := loadCredentialSourceSettings()
		source, err := newCredentialConfigSource(credentialSourceSettings)
		if err != nil {
			recordConfigProblem("%s", err.Error())
			source = secretsource.EnvSource{}
		}
		withConfigValueSource(source, func() {
			apiKeys := parseAPIKeys(getEnv("API_KEYS", ""))
			apiCredentials, err := apiauth.ParseCredentialsJSON(getEnv("API_CREDENTIALS_JSON", ""))
			if err != nil {
				recordConfigProblem("%s", err.Error())
				apiCredentials = map[string]apiauth.Credential{}
			}
			if len(apiCredentials) == 0 {
				apiCredentials = make(map[string]apiauth.Credential, len(apiKeys))
				for key, userID := range apiKeys {
					apiCredentials[key] = apiauth.DefaultCredentialForAPIKey(key, userID)
				}
			}
			apiKeys = apiauth.CredentialsToUserMap(apiCredentials)
			devMode := getEnvBool("CEREBRO_DEV_MODE", false)
			devModeAck := getEnvBool("CEREBRO_DEV_MODE_ACK", false)
			apiAuthEnabled := getEnvBool("API_AUTH_ENABLED", true)
			rateLimitEnabled := getEnvBool("RATE_LIMIT_ENABLED", true)
			if devMode {
				apiAuthEnabled = false
				rateLimitEnabled = false
			}
			snowflakeAccount := getEnv("SNOWFLAKE_ACCOUNT", "")
			snowflakeUser := getEnv("SNOWFLAKE_USER", "")
			snowflakePrivateKey := normalizePrivateKey(getEnv("SNOWFLAKE_PRIVATE_KEY", ""))
			defaultWarehouseBackend := "sqlite"
			if strings.TrimSpace(snowflakeAccount) != "" || strings.TrimSpace(snowflakeUser) != "" || strings.TrimSpace(snowflakePrivateKey) != "" {
				defaultWarehouseBackend = "snowflake"
			}
			defaultWarehouseSQLitePath := filepath.Join(filepath.Dir(findings.DefaultFilePath()), "warehouse.db")
			defaultNeptunePool := graph.DefaultNeptuneDataExecutorPoolConfig()

			cfg = Config{
				Port:                                     getEnvInt("API_PORT", 8080),
				LogLevel:                                 getEnv("LOG_LEVEL", "info"),
				APIRequestTimeout:                        getEnvDuration("API_REQUEST_TIMEOUT", defaultAPIRequestTimeout),
				APIReadTimeout:                           getEnvDuration("API_READ_TIMEOUT", defaultAPIReadTimeout),
				APIWriteTimeout:                          getEnvDuration("API_WRITE_TIMEOUT", defaultAPIWriteTimeout),
				APIIdleTimeout:                           getEnvDuration("API_IDLE_TIMEOUT", defaultAPIIdleTimeout),
				APIMaxBodyBytes:                          int64(getEnvInt("API_MAX_BODY_BYTES", int(defaultAPIMaxBodyBytes))),
				HealthCheckTimeout:                       getEnvDuration("CEREBRO_HEALTH_CHECK_TIMEOUT", defaultHealthCheckTimeout),
				TracingEnabled:                           getEnvBool("CEREBRO_OTEL_ENABLED", false),
				TracingServiceName:                       getEnv("CEREBRO_OTEL_SERVICE_NAME", "cerebro"),
				TracingOTLPEndpoint:                      getEnv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")),
				TracingOTLPInsecure:                      getEnvBool("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false)),
				TracingOTLPHeaders:                       parseKeyValueCSV(getEnv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", getEnv("OTEL_EXPORTER_OTLP_HEADERS", ""))),
				TracingSampleRatio:                       getEnvFloat("CEREBRO_OTEL_SAMPLE_RATIO", 1.0),
				TracingExportTimeout:                     getEnvDuration("CEREBRO_OTEL_EXPORT_TIMEOUT", 5*time.Second),
				CredentialSource:                         strings.ToLower(strings.TrimSpace(bootstrapConfigValue("CEREBRO_CREDENTIAL_SOURCE", secretsource.KindEnv))),
				CredentialFileDir:                        bootstrapConfigValue("CEREBRO_CREDENTIAL_FILE_DIR", ""),
				CredentialVaultAddress:                   bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_ADDRESS", ""),
				CredentialVaultToken:                     bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_TOKEN", ""),
				CredentialVaultNamespace:                 bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_NAMESPACE", ""),
				CredentialVaultPath:                      bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_PATH", ""),
				CredentialVaultKVVersion:                 bootstrapConfigInt("CEREBRO_CREDENTIAL_VAULT_KV_VERSION", 2),
				WarehouseBackend:                         strings.ToLower(strings.TrimSpace(getEnv("WAREHOUSE_BACKEND", defaultWarehouseBackend))),
				WarehouseSQLitePath:                      getEnv("WAREHOUSE_SQLITE_PATH", defaultWarehouseSQLitePath),
				WarehousePostgresDSN:                     getEnv("WAREHOUSE_POSTGRES_DSN", ""),
				SnowflakeAccount:                         snowflakeAccount,
				SnowflakeUser:                            snowflakeUser,
				SnowflakePrivateKey:                      snowflakePrivateKey,
				SnowflakeDatabase:                        getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
				SnowflakeSchema:                          getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
				SnowflakeWarehouse:                       getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
				SnowflakeRole:                            getEnv("SNOWFLAKE_ROLE", ""),
				PoliciesPath:                             getEnv("POLICIES_PATH", "policies"),
				QueryPolicyRowLimit:                      getEnvInt("QUERY_POLICY_ROW_LIMIT", snowflake.MaxReadOnlyQueryLimit),
				AnthropicAPIKey:                          getEnv("ANTHROPIC_API_KEY", ""),
				OpenAIAPIKey:                             getEnv("OPENAI_API_KEY", ""),
				JiraBaseURL:                              getEnv("JIRA_BASE_URL", ""),
				JiraEmail:                                getEnv("JIRA_EMAIL", ""),
				JiraAPIToken:                             getEnv("JIRA_API_TOKEN", ""),
				JiraProject:                              getEnv("JIRA_PROJECT", "SEC"),
				JiraCloseTransitions:                     splitCSV(getEnv("JIRA_CLOSE_TRANSITIONS", "Done,Closed,Resolve Issue")),
				TicketingProviderValidateTimeout:         getEnvDuration("CEREBRO_TICKETING_PROVIDER_VALIDATE_TIMEOUT", defaultTicketingProviderValidateTimeout),
				LinearAPIKey:                             getEnv("LINEAR_API_KEY", ""),
				LinearTeamID:                             getEnv("LINEAR_TEAM_ID", ""),
				CrowdStrikeClientID:                      getEnv("CROWDSTRIKE_CLIENT_ID", ""),
				CrowdStrikeClientSecret:                  getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
				OktaDomain:                               getEnv("OKTA_DOMAIN", ""),
				OktaAPIToken:                             getEnv("OKTA_API_TOKEN", ""),
				EntraTenantID:                            getEnv("ENTRA_TENANT_ID", ""),
				EntraClientID:                            getEnv("ENTRA_CLIENT_ID", ""),
				EntraClientSecret:                        getEnv("ENTRA_CLIENT_SECRET", ""),
				AzureTenantID:                            getEnv("AZURE_TENANT_ID", ""),
				AzureClientID:                            getEnv("AZURE_CLIENT_ID", ""),
				AzureClientSecret:                        getEnv("AZURE_CLIENT_SECRET", ""),
				AzureSubscriptionID:                      getEnv("AZURE_SUBSCRIPTION_ID", ""),
				SnykAPIToken:                             getEnv("SNYK_API_TOKEN", ""),
				SnykOrgID:                                getEnv("SNYK_ORG_ID", ""),
				ZoomAccountID:                            getEnv("ZOOM_ACCOUNT_ID", ""),
				ZoomClientID:                             getEnv("ZOOM_CLIENT_ID", ""),
				ZoomClientSecret:                         getEnv("ZOOM_CLIENT_SECRET", ""),
				ZoomAPIURL:                               getEnv("ZOOM_API_URL", "https://api.zoom.us/v2"),
				ZoomTokenURL:                             getEnv("ZOOM_TOKEN_URL", "https://zoom.us/oauth/token"),
				WizClientID:                              getEnv("WIZ_CLIENT_ID", ""),
				WizClientSecret:                          getEnv("WIZ_CLIENT_SECRET", ""),
				WizAPIURL:                                getEnv("WIZ_API_URL", ""),
				WizTokenURL:                              getEnv("WIZ_TOKEN_URL", "https://auth.app.wiz.io/oauth/token"),
				WizAudience:                              getEnv("WIZ_AUDIENCE", "wiz-api"),
				DatadogAPIKey:                            getEnv("DATADOG_API_KEY", ""),
				DatadogAppKey:                            getEnv("DATADOG_APP_KEY", ""),
				DatadogSite:                              getEnv("DATADOG_SITE", "datadoghq.com"),
				GitHubToken:                              getEnv("GITHUB_TOKEN", ""),
				GitHubOrg:                                getEnv("GITHUB_ORG", ""),
				FigmaAPIToken:                            getEnv("FIGMA_API_TOKEN", ""),
				FigmaTeamID:                              getEnv("FIGMA_TEAM_ID", ""),
				FigmaBaseURL:                             getEnv("FIGMA_BASE_URL", "https://api.figma.com"),
				SocketAPIToken:                           getEnv("SOCKET_API_TOKEN", ""),
				SocketOrgSlug:                            getEnv("SOCKET_ORG", ""),
				SocketAPIURL:                             getEnv("SOCKET_API_URL", "https://api.socket.dev/v0"),
				RampClientID:                             getEnv("RAMP_CLIENT_ID", ""),
				RampClientSecret:                         getEnv("RAMP_CLIENT_SECRET", ""),
				RampAPIURL:                               getEnv("RAMP_API_URL", "https://api.ramp.com/developer/v1"),
				RampTokenURL:                             getEnv("RAMP_TOKEN_URL", "https://api.ramp.com/developer/v1/token"),
				GongAccessKey:                            getEnv("GONG_ACCESS_KEY", ""),
				GongAccessSecret:                         getEnv("GONG_ACCESS_SECRET", ""),
				GongBaseURL:                              getEnv("GONG_BASE_URL", "https://api.gong.io"),
				VantaAPIToken:                            getEnv("VANTA_API_TOKEN", ""),
				VantaBaseURL:                             getEnv("VANTA_BASE_URL", "https://api.vanta.com"),
				PantherAPIToken:                          getEnv("PANTHER_API_TOKEN", ""),
				PantherBaseURL:                           getEnv("PANTHER_BASE_URL", "https://api.runpanther.io/public_api/v1"),
				KolideAPIToken:                           getEnv("KOLIDE_API_TOKEN", ""),
				KolideBaseURL:                            getEnv("KOLIDE_BASE_URL", "https://api.kolide.com/v1"),
				GoogleWorkspaceDomain:                    getEnv("GOOGLE_WORKSPACE_DOMAIN", ""),
				GoogleWorkspaceAdminEmail:                getEnv("GOOGLE_WORKSPACE_ADMIN_EMAIL", ""),
				GoogleWorkspaceImpersonatorEmail:         getEnv("GOOGLE_WORKSPACE_IMPERSONATOR_EMAIL", ""),
				GoogleWorkspaceCredentialsFile:           getEnv("GOOGLE_WORKSPACE_CREDENTIALS_FILE", ""),
				GoogleWorkspaceCredentialsJSON:           getEnv("GOOGLE_WORKSPACE_CREDENTIALS_JSON", ""),
				TailscaleAPIKey:                          getEnv("TAILSCALE_API_KEY", ""),
				TailscaleTailnet:                         getEnv("TAILSCALE_TAILNET", ""),
				SentinelOneAPIToken:                      getEnv("SENTINELONE_API_TOKEN", ""),
				SentinelOneBaseURL:                       getEnv("SENTINELONE_BASE_URL", ""),
				TenableAccessKey:                         getEnv("TENABLE_ACCESS_KEY", ""),
				TenableSecretKey:                         getEnv("TENABLE_SECRET_KEY", ""),
				QualysUsername:                           getEnv("QUALYS_USERNAME", ""),
				QualysPassword:                           getEnv("QUALYS_PASSWORD", ""),
				QualysPlatform:                           getEnv("QUALYS_PLATFORM", "US1"),
				SemgrepAPIToken:                          getEnv("SEMGREP_API_TOKEN", ""),
				ServiceNowURL:                            getEnv("SERVICENOW_URL", ""),
				ServiceNowAPIToken:                       getEnv("SERVICENOW_API_TOKEN", ""),
				ServiceNowUsername:                       getEnv("SERVICENOW_USERNAME", ""),
				ServiceNowPassword:                       getEnv("SERVICENOW_PASSWORD", ""),
				WorkdayURL:                               getEnv("WORKDAY_URL", ""),
				WorkdayAPIToken:                          getEnv("WORKDAY_API_TOKEN", ""),
				BambooHRURL:                              getEnv("BAMBOOHR_URL", ""),
				BambooHRAPIToken:                         getEnv("BAMBOOHR_API_TOKEN", ""),
				OneLoginURL:                              getEnv("ONELOGIN_URL", ""),
				OneLoginClientID:                         getEnv("ONELOGIN_CLIENT_ID", ""),
				OneLoginClientSecret:                     getEnv("ONELOGIN_CLIENT_SECRET", ""),
				JumpCloudURL:                             getEnv("JUMPCLOUD_URL", "https://console.jumpcloud.com"),
				JumpCloudAPIToken:                        getEnv("JUMPCLOUD_API_TOKEN", ""),
				JumpCloudOrgID:                           getEnv("JUMPCLOUD_ORG_ID", ""),
				DuoURL:                                   getEnv("DUO_URL", getEnv("DUO_API_HOSTNAME", "")),
				DuoIntegrationKey:                        getEnv("DUO_INTEGRATION_KEY", getEnv("DUO_IKEY", "")),
				DuoSecretKey:                             getEnv("DUO_SECRET_KEY", getEnv("DUO_SKEY", "")),
				PingIdentityEnvironmentID:                getEnv("PINGIDENTITY_ENVIRONMENT_ID", getEnv("PINGONE_ENVIRONMENT_ID", "")),
				PingIdentityClientID:                     getEnv("PINGIDENTITY_CLIENT_ID", getEnv("PINGONE_CLIENT_ID", "")),
				PingIdentityClientSecret:                 getEnv("PINGIDENTITY_CLIENT_SECRET", getEnv("PINGONE_CLIENT_SECRET", "")),
				PingIdentityAPIURL:                       getEnv("PINGIDENTITY_API_URL", "https://api.pingone.com"),
				PingIdentityAuthURL:                      getEnv("PINGIDENTITY_AUTH_URL", "https://auth.pingone.com"),
				CyberArkURL:                              getEnv("CYBERARK_URL", ""),
				CyberArkAPIToken:                         getEnv("CYBERARK_API_TOKEN", ""),
				SailPointURL:                             getEnv("SAILPOINT_URL", ""),
				SailPointAPIToken:                        getEnv("SAILPOINT_API_TOKEN", ""),
				SaviyntURL:                               getEnv("SAVIYNT_URL", ""),
				SaviyntAPIToken:                          getEnv("SAVIYNT_API_TOKEN", ""),
				ForgeRockURL:                             getEnv("FORGEROCK_URL", ""),
				ForgeRockAPIToken:                        getEnv("FORGEROCK_API_TOKEN", ""),
				OracleIDCSURL:                            getEnv("ORACLE_IDCS_URL", ""),
				OracleIDCSAPIToken:                       getEnv("ORACLE_IDCS_API_TOKEN", ""),
				GitLabToken:                              getEnv("GITLAB_TOKEN", ""),
				GitLabBaseURL:                            getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
				TerraformCloudToken:                      getEnv("TFC_TOKEN", ""),
				SplunkURL:                                getEnv("SPLUNK_URL", ""),
				SplunkToken:                              getEnv("SPLUNK_TOKEN", ""),
				Auth0Domain:                              getEnv("AUTH0_DOMAIN", ""),
				Auth0ClientID:                            getEnv("AUTH0_CLIENT_ID", ""),
				Auth0ClientSecret:                        getEnv("AUTH0_CLIENT_SECRET", ""),
				CloudflareAPIToken:                       getEnv("CLOUDFLARE_API_TOKEN", ""),
				SalesforceInstanceURL:                    getEnv("SALESFORCE_INSTANCE_URL", ""),
				SalesforceClientID:                       getEnv("SALESFORCE_CLIENT_ID", ""),
				SalesforceClientSecret:                   getEnv("SALESFORCE_CLIENT_SECRET", ""),
				SalesforceUsername:                       getEnv("SALESFORCE_USERNAME", ""),
				SalesforcePassword:                       getEnv("SALESFORCE_PASSWORD", ""),
				SalesforceSecurityToken:                  getEnv("SALESFORCE_SECURITY_TOKEN", ""),
				VaultAddress:                             getEnv("VAULT_ADDRESS", ""),
				VaultToken:                               getEnv("VAULT_TOKEN", ""),
				VaultNamespace:                           getEnv("VAULT_NAMESPACE", ""),
				SlackAPIToken:                            getEnv("SLACK_API_TOKEN", ""),
				RipplingAPIURL:                           getEnv("RIPPLING_API_URL", ""),
				RipplingAPIToken:                         getEnv("RIPPLING_API_TOKEN", ""),
				JamfBaseURL:                              getEnv("JAMF_BASE_URL", ""),
				JamfClientID:                             getEnv("JAMF_CLIENT_ID", ""),
				JamfClientSecret:                         getEnv("JAMF_CLIENT_SECRET", ""),
				IntuneTenantID:                           getEnv("INTUNE_TENANT_ID", ""),
				IntuneClientID:                           getEnv("INTUNE_CLIENT_ID", ""),
				IntuneClientSecret:                       getEnv("INTUNE_CLIENT_SECRET", ""),
				KandjiAPIURL:                             getEnv("KANDJI_API_URL", ""),
				KandjiAPIToken:                           getEnv("KANDJI_API_TOKEN", ""),
				S3InputBucket:                            getEnv("S3_INPUT_BUCKET", ""),
				S3InputPrefix:                            getEnv("S3_INPUT_PREFIX", ""),
				S3InputRegion:                            getEnv("S3_INPUT_REGION", getEnv("AWS_REGION", "us-east-1")),
				S3InputFormat:                            getEnv("S3_INPUT_FORMAT", "auto"),
				S3InputMaxObjects:                        getEnvInt("S3_INPUT_MAX_OBJECTS", 200),
				CloudTrailRegion:                         getEnv("CLOUDTRAIL_REGION", ""),
				CloudTrailTrailARN:                       getEnv("CLOUDTRAIL_TRAIL_ARN", ""),
				CloudTrailLookbackDays:                   getEnvInt("CLOUDTRAIL_LOOKBACK_DAYS", 7),
				WebhookURLs:                              splitCSV(getEnv("WEBHOOK_URLS", "")),
				InitTimeout:                              getEnvDuration("CEREBRO_INIT_TIMEOUT", 2*time.Minute),
				ShutdownTimeout:                          getEnvDuration("CEREBRO_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
				NATSJetStreamEnabled:                     getEnvBool("NATS_JETSTREAM_ENABLED", false),
				NATSJetStreamURLs:                        splitCSV(getEnv("NATS_URLS", "nats://127.0.0.1:4222")),
				NATSJetStreamStream:                      getEnv("NATS_JETSTREAM_STREAM", "CEREBRO_EVENTS"),
				NATSJetStreamSubjectPrefix:               getEnv("NATS_JETSTREAM_SUBJECT_PREFIX", "cerebro.events"),
				NATSJetStreamSource:                      getEnv("NATS_JETSTREAM_SOURCE", "cerebro"),
				NATSJetStreamOutboxPath:                  getEnv("NATS_JETSTREAM_OUTBOX_PATH", filepath.Join(findings.DefaultFilePath(), "jetstream-outbox.jsonl")),
				NATSJetStreamOutboxDLQPath:               getEnv("NATS_JETSTREAM_OUTBOX_DLQ_PATH", ""),
				NATSJetStreamOutboxMaxAge:                getEnvDuration("NATS_JETSTREAM_OUTBOX_MAX_AGE", 7*24*time.Hour),
				NATSJetStreamOutboxMaxItems:              getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_ITEMS", 10000),
				NATSJetStreamOutboxMaxRetry:              getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_RETRY", 10),
				NATSJetStreamOutboxWarnPercent:           getEnvInt("NATS_JETSTREAM_OUTBOX_WARN_PERCENT", 70),
				NATSJetStreamOutboxCriticalPercent:       getEnvInt("NATS_JETSTREAM_OUTBOX_CRITICAL_PERCENT", 90),
				NATSJetStreamOutboxWarnAge:               getEnvDuration("NATS_JETSTREAM_OUTBOX_WARN_AGE", time.Hour),
				NATSJetStreamOutboxCriticalAge:           getEnvDuration("NATS_JETSTREAM_OUTBOX_CRITICAL_AGE", 6*time.Hour),
				NATSJetStreamPublishTimeout:              getEnvDuration("NATS_JETSTREAM_PUBLISH_TIMEOUT", 3*time.Second),
				NATSJetStreamRetryAttempts:               getEnvInt("NATS_JETSTREAM_RETRY_ATTEMPTS", 3),
				NATSJetStreamRetryBackoff:                getEnvDuration("NATS_JETSTREAM_RETRY_BACKOFF", 500*time.Millisecond),
				NATSJetStreamFlushInterval:               getEnvDuration("NATS_JETSTREAM_FLUSH_INTERVAL", 10*time.Second),
				NATSJetStreamConnectTimeout:              getEnvDuration("NATS_JETSTREAM_CONNECT_TIMEOUT", 5*time.Second),
				NATSJetStreamAuthMode:                    getEnv("NATS_JETSTREAM_AUTH_MODE", "none"),
				NATSJetStreamUsername:                    getEnv("NATS_JETSTREAM_USERNAME", ""),
				NATSJetStreamPassword:                    getEnv("NATS_JETSTREAM_PASSWORD", ""),
				NATSJetStreamNKeySeed:                    getEnv("NATS_JETSTREAM_NKEY_SEED", ""),
				NATSJetStreamUserJWT:                     getEnv("NATS_JETSTREAM_USER_JWT", ""),
				NATSJetStreamTLSEnabled:                  getEnvBool("NATS_JETSTREAM_TLS_ENABLED", false),
				NATSJetStreamTLSCAFile:                   getEnv("NATS_JETSTREAM_TLS_CA_FILE", ""),
				NATSJetStreamTLSCertFile:                 getEnv("NATS_JETSTREAM_TLS_CERT_FILE", ""),
				NATSJetStreamTLSKeyFile:                  getEnv("NATS_JETSTREAM_TLS_KEY_FILE", ""),
				NATSJetStreamTLSServerName:               getEnv("NATS_JETSTREAM_TLS_SERVER_NAME", ""),
				NATSJetStreamTLSInsecure:                 getEnvBool("NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY", false),
				NATSConsumerEnabled:                      getEnvBool("NATS_CONSUMER_ENABLED", false),
				NATSConsumerStream:                       getEnv("NATS_CONSUMER_STREAM", "ENSEMBLE_TAP"),
				NATSConsumerSubjects:                     splitCSV(getEnv("NATS_CONSUMER_SUBJECTS", "ensemble.tap.>")),
				NATSConsumerDurable:                      getEnv("NATS_CONSUMER_DURABLE", "cerebro_graph_builder"),
				NATSConsumerBatchSize:                    getEnvInt("NATS_CONSUMER_BATCH_SIZE", 50),
				NATSConsumerAckWait:                      getEnvDuration("NATS_CONSUMER_ACK_WAIT", 120*time.Second),
				NATSConsumerFetchTimeout:                 getEnvDuration("NATS_CONSUMER_FETCH_TIMEOUT", 2*time.Second),
				NATSConsumerInProgressInterval:           getEnvDuration("NATS_CONSUMER_IN_PROGRESS_INTERVAL", 15*time.Second),
				NATSConsumerDrainTimeout:                 getEnvDuration("NATS_CONSUMER_DRAIN_TIMEOUT", 30*time.Second),
				NATSConsumerDeadLetterPath:               getEnv("NATS_CONSUMER_DEAD_LETTER_PATH", filepath.Join(findings.DefaultFilePath(), "nats-consumer.dlq.jsonl")),
				NATSConsumerDedupEnabled:                 getEnvBool("NATS_CONSUMER_DEDUP_ENABLED", true),
				NATSConsumerDedupStateFile:               getEnv("NATS_CONSUMER_DEDUP_STATE_FILE", getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))),
				NATSConsumerDedupTTL:                     getEnvDuration("NATS_CONSUMER_DEDUP_TTL", 24*time.Hour),
				NATSConsumerDedupMaxRecords:              getEnvInt("NATS_CONSUMER_DEDUP_MAX_RECORDS", 100000),
				NATSConsumerDropHealthLookback:           getEnvDuration("NATS_CONSUMER_DROP_HEALTH_LOOKBACK", 5*time.Minute),
				NATSConsumerDropHealthThreshold:          getEnvInt("NATS_CONSUMER_DROP_HEALTH_THRESHOLD", 1),
				NATSConsumerGraphStalenessThreshold:      getEnvDuration("NATS_CONSUMER_GRAPH_STALENESS_THRESHOLD", 15*time.Minute),
				AlertRouterEnabled:                       getEnvBool("ALERT_ROUTER_ENABLED", true),
				AlertRouterConfigPath:                    getEnv("ALERT_ROUTER_CONFIG_PATH", ""),
				AlertRouterNotifyPrefix:                  getEnv("ALERT_ROUTER_NOTIFY_PREFIX", "ensemble.notify"),
				AlertRouterStateFile:                     getEnv("ALERT_ROUTER_STATE_FILE", filepath.Join(".cerebro", "alert-router", "state.db")),
				AgentRemoteToolsEnabled:                  getEnvBool("AGENT_REMOTE_TOOLS_ENABLED", false),
				AgentRemoteToolsManifestSubject:          getEnv("AGENT_REMOTE_TOOLS_MANIFEST_SUBJECT", "ensemble.tools.manifest"),
				AgentRemoteToolsRequestPrefix:            getEnv("AGENT_REMOTE_TOOLS_REQUEST_PREFIX", "ensemble.tools.request"),
				AgentRemoteToolsDiscoverTimeout:          getEnvDuration("AGENT_REMOTE_TOOLS_DISCOVER_TIMEOUT", 5*time.Second),
				AgentRemoteToolsRequestTimeout:           getEnvDuration("AGENT_REMOTE_TOOLS_REQUEST_TIMEOUT", 30*time.Second),
				AgentRemoteToolsMaxTools:                 getEnvInt("AGENT_REMOTE_TOOLS_MAX_TOOLS", 200),
				AgentToolPublisherEnabled:                getEnvBool("AGENT_TOOL_PUBLISHER_ENABLED", false),
				AgentToolPublisherManifestSubject:        getEnv("AGENT_TOOL_PUBLISHER_MANIFEST_SUBJECT", "cerebro.tools.manifest"),
				AgentToolPublisherRequestPrefix:          getEnv("AGENT_TOOL_PUBLISHER_REQUEST_PREFIX", "cerebro.tools.request"),
				AgentToolPublisherRequestTimeout:         getEnvDuration("AGENT_TOOL_PUBLISHER_REQUEST_TIMEOUT", 30*time.Second),
				AgentPendingToolApprovalTTL:              getEnvDuration("AGENT_PENDING_TOOL_APPROVAL_TTL", defaultAgentPendingToolApprovalTTL),
				CerebroSimulateNeedsApproval:             getEnvBool("CEREBRO_TOOL_SIMULATE_REQUIRES_APPROVAL", true),
				CerebroAccessReviewNeedsApproval:         getEnvBool("CEREBRO_TOOL_ACCESS_REVIEW_REQUIRES_APPROVAL", true),
				SlackWebhookURL:                          getEnv("SLACK_WEBHOOK_URL", ""),
				SlackSigningSecret:                       getEnv("SLACK_SIGNING_SECRET", ""),
				PagerDutyKey:                             getEnv("PAGERDUTY_ROUTING_KEY", ""),
				ScanInterval:                             getEnv("SCAN_INTERVAL", ""),
				SecurityDigestInterval:                   getEnv("SECURITY_DIGEST_INTERVAL", ""),
				ScanTables:                               getEnv("SCAN_TABLES", ""),
				RetentionJobInterval:                     getEnvDuration("CEREBRO_RETENTION_JOB_INTERVAL", 24*time.Hour),
				AuditRetentionDays:                       getEnvInt("CEREBRO_AUDIT_RETENTION_DAYS", 90),
				SessionRetentionDays:                     getEnvInt("CEREBRO_SESSION_RETENTION_DAYS", 30),
				GraphRetentionDays:                       getEnvInt("CEREBRO_GRAPH_RETENTION_DAYS", 180),
				AccessReviewRetentionDays:                getEnvInt("CEREBRO_ACCESS_REVIEW_RETENTION_DAYS", 365),
				ScanTableTimeout:                         getEnvDuration("SCAN_TABLE_TIMEOUT", 30*time.Minute),
				ScanMaxConcurrent:                        getEnvInt("SCAN_MAX_CONCURRENCY", 6),
				ScanMinConcurrent:                        getEnvInt("SCAN_MIN_CONCURRENCY", 2),
				ScanAdaptiveConcurrency:                  getEnvBool("SCAN_ADAPTIVE_CONCURRENCY", true),
				ScanRetryAttempts:                        getEnvInt("SCAN_RETRY_ATTEMPTS", 3),
				ScanRetryBackoff:                         getEnvDuration("SCAN_RETRY_BACKOFF", 2*time.Second),
				ScanRetryMaxBackoff:                      getEnvDuration("SCAN_RETRY_MAX_BACKOFF", 30*time.Second),
				ExecutionStoreFile:                       getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db")),
				VulnDBStateFile:                          getEnv("VULNDB_STATE_FILE", filepath.Join(".cerebro", "vulndb.db")),
				MalwareScanClamAVHost:                    getEnv("MALWARE_SCAN_CLAMAV_HOST", ""),
				MalwareScanClamAVPort:                    getEnvInt("MALWARE_SCAN_CLAMAV_PORT", 0),
				MalwareScanVirusTotalAPIKey:              getEnv("MALWARE_SCAN_VIRUSTOTAL_API_KEY", ""),
				WorkloadScanStateFile:                    getEnv("WORKLOAD_SCAN_STATE_FILE", getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))),
				WorkloadScanMountBasePath:                getEnv("WORKLOAD_SCAN_MOUNT_BASE_PATH", filepath.Join(".cerebro", "workload-scan", "mounts")),
				WorkloadScanMaxConcurrentSnapshots:       getEnvInt("WORKLOAD_SCAN_MAX_CONCURRENT_SNAPSHOTS", 2),
				WorkloadScanCleanupTimeout:               getEnvDuration("WORKLOAD_SCAN_CLEANUP_TIMEOUT", 2*time.Minute),
				WorkloadScanReconcileOlderThan:           getEnvDuration("WORKLOAD_SCAN_RECONCILE_OLDER_THAN", 30*time.Minute),
				WorkloadScanTrivyBinary:                  getEnv("WORKLOAD_SCAN_TRIVY_BINARY", "trivy"),
				WorkloadScanGitleaksBinary:               getEnv("WORKLOAD_SCAN_GITLEAKS_BINARY", ""),
				WorkloadScanClamAVBinary:                 getEnv("WORKLOAD_SCAN_CLAMAV_BINARY", ""),
				ImageScanStateFile:                       getEnv("IMAGE_SCAN_STATE_FILE", getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))),
				ImageScanRootFSBasePath:                  getEnv("IMAGE_SCAN_ROOTFS_BASE_PATH", filepath.Join(".cerebro", "image-scan", "rootfs")),
				ImageScanCleanupTimeout:                  getEnvDuration("IMAGE_SCAN_CLEANUP_TIMEOUT", 2*time.Minute),
				ImageScanTrivyBinary:                     getEnv("IMAGE_SCAN_TRIVY_BINARY", "trivy"),
				ImageScanGitleaksBinary:                  getEnv("IMAGE_SCAN_GITLEAKS_BINARY", ""),
				ImageScanClamAVBinary:                    getEnv("IMAGE_SCAN_CLAMAV_BINARY", ""),
				FunctionScanStateFile:                    getEnv("FUNCTION_SCAN_STATE_FILE", getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))),
				FunctionScanRootFSBasePath:               getEnv("FUNCTION_SCAN_ROOTFS_BASE_PATH", filepath.Join(".cerebro", "function-scan", "rootfs")),
				FunctionScanCleanupTimeout:               getEnvDuration("FUNCTION_SCAN_CLEANUP_TIMEOUT", 2*time.Minute),
				FunctionScanTrivyBinary:                  getEnv("FUNCTION_SCAN_TRIVY_BINARY", "trivy"),
				FunctionScanGitleaksBinary:               getEnv("FUNCTION_SCAN_GITLEAKS_BINARY", ""),
				FunctionScanClamAVBinary:                 getEnv("FUNCTION_SCAN_CLAMAV_BINARY", ""),
				ScanPoliciesPath:                         getEnv("SCAN_POLICIES_PATH", ""),
				FindingsMaxInMemory:                      getEnvInt("FINDINGS_MAX_IN_MEMORY", findings.DefaultMaxFindings),
				FindingsResolvedRetention:                getEnvDuration("FINDINGS_RESOLVED_RETENTION", findings.DefaultResolvedRetention),
				FindingsSemanticDedupEnabled:             getEnvBool("FINDINGS_SEMANTIC_DEDUP_ENABLED", findings.DefaultSemanticDedupEnabled),
				FindingAttestationEnabled:                getEnvBool("FINDING_ATTESTATION_ENABLED", false),
				FindingAttestationSigningKey:             normalizePrivateKey(getEnv("FINDING_ATTESTATION_SIGNING_KEY", "")),
				FindingAttestationKeyID:                  getEnv("FINDING_ATTESTATION_KEY_ID", ""),
				FindingAttestationLogURL:                 getEnv("FINDING_ATTESTATION_LOG_URL", ""),
				FindingAttestationTimeout:                getEnvDuration("FINDING_ATTESTATION_TIMEOUT", 3*time.Second),
				FindingAttestationAttestReobserved:       getEnvBool("FINDING_ATTESTATION_ATTEST_REOBSERVED", false),
				JobDatabaseURL:                           getEnv("JOB_DATABASE_URL", ""),
				JobNATSStream:                            getEnv("JOB_NATS_STREAM", "CEREBRO_JOBS"),
				JobNATSSubject:                           getEnv("JOB_NATS_SUBJECT", "cerebro.jobs"),
				JobNATSConsumer:                          getEnv("JOB_NATS_CONSUMER", "job-worker"),
				JobWorkerConcurrency:                     getEnvInt("JOB_WORKER_CONCURRENCY", 4),
				JobVisibilityTimeout:                     getEnvDuration("JOB_VISIBILITY_TIMEOUT", 30*time.Second),
				JobPollWait:                              getEnvDuration("JOB_POLL_WAIT", 10*time.Second),
				JobMaxAttempts:                           getEnvInt("JOB_MAX_ATTEMPTS", 3),
				DevMode:                                  devMode,
				DevModeAck:                               devModeAck,
				RateLimitEnabled:                         rateLimitEnabled,
				RateLimitRequests:                        getEnvInt("RATE_LIMIT_REQUESTS", 1000),
				RateLimitWindow:                          getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
				RateLimitTrustedProxies:                  splitCSV(getEnv("RATE_LIMIT_TRUSTED_PROXIES", "")),
				CORSAllowedOrigins:                       splitCSV(getEnv("API_CORS_ALLOWED_ORIGINS", "")),
				APIAuthEnabled:                           apiAuthEnabled,
				APIKeys:                                  apiKeys,
				APICredentials:                           apiCredentials,
				APICredentialStateFile:                   getEnv("API_CREDENTIAL_STATE_FILE", filepath.Join(".cerebro", "api-credentials", "state.json")),
				APIAuthorizationServers:                  splitCSV(getEnv("API_AUTHORIZATION_SERVERS", "")),
				SecretsReloadInterval:                    getEnvDuration("CEREBRO_SECRETS_RELOAD_INTERVAL", 0),
				RBACStateFile:                            getEnv("RBAC_STATE_FILE", ""),
				PlatformReportRunStateFile:               getEnv("PLATFORM_REPORT_RUN_STATE_FILE", filepath.Join(".cerebro", "report-runs", "state.json")),
				PlatformReportSnapshotPath:               getEnv("PLATFORM_REPORT_SNAPSHOT_PATH", filepath.Join(".cerebro", "report-runs", "snapshots")),
				GraphCrossTenantRequireSignedIngest:      getEnvBool("GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST", false),
				GraphCrossTenantSigningKey:               getEnv("GRAPH_CROSS_TENANT_SIGNING_KEY", ""),
				GraphCrossTenantSignatureSkew:            getEnvDuration("GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW", 5*time.Minute),
				GraphCrossTenantReplayTTL:                getEnvDuration("GRAPH_CROSS_TENANT_REPLAY_TTL", 24*time.Hour),
				GraphCrossTenantMinTenants:               getEnvInt("GRAPH_CROSS_TENANT_MIN_TENANTS", 2),
				GraphCrossTenantMinSupport:               getEnvInt("GRAPH_CROSS_TENANT_MIN_SUPPORT", 2),
				GraphStoreBackend:                        getEnv("GRAPH_STORE_BACKEND", defaultGraphStoreBackend()),
				GraphStoreNeptuneEndpoint:                getEnv("GRAPH_STORE_NEPTUNE_ENDPOINT", ""),
				GraphStoreNeptuneRegion:                  getEnv("GRAPH_STORE_NEPTUNE_REGION", getEnv("AWS_REGION", "us-east-1")),
				GraphStoreNeptunePoolSize:                getEnvInt("GRAPH_STORE_NEPTUNE_POOL_SIZE", defaultNeptunePool.Size),
				GraphStoreNeptunePoolHealthCheckInterval: getEnvDuration("GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_INTERVAL", defaultNeptunePool.HealthCheckInterval),
				GraphStoreNeptunePoolHealthCheckTimeout:  getEnvDuration("GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_TIMEOUT", defaultNeptunePool.HealthCheckTimeout),
				GraphStoreNeptunePoolMaxClientLifetime:   getEnvDuration("GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_LIFETIME", defaultNeptunePool.MaxClientLifetime),
				GraphStoreNeptunePoolMaxClientUses:       getEnvInt("GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_USES", defaultNeptunePool.MaxClientUses),
				GraphStoreNeptunePoolDrainTimeout:        getEnvDuration("GRAPH_STORE_NEPTUNE_POOL_DRAIN_TIMEOUT", defaultNeptunePool.DrainTimeout),
				GraphSearchBackend:                       getEnv("GRAPH_SEARCH_BACKEND", defaultGraphSearchBackend()),
				GraphSearchOpenSearchEndpoint:            getEnv("GRAPH_SEARCH_OPENSEARCH_ENDPOINT", ""),
				GraphSearchOpenSearchRegion:              getEnv("GRAPH_SEARCH_OPENSEARCH_REGION", getEnv("AWS_REGION", "")),
				GraphSearchOpenSearchIndex:               getEnv("GRAPH_SEARCH_OPENSEARCH_INDEX", ""),
				GraphSearchRequestTimeout:                getEnvDuration("GRAPH_SEARCH_REQUEST_TIMEOUT", 5*time.Second),
				GraphSearchMaxCandidates:                 getEnvInt("GRAPH_SEARCH_MAX_CANDIDATES", 100),
				GraphSnapshotPath:                        getEnv("GRAPH_SNAPSHOT_PATH", filepath.Join(".cerebro", "graph-snapshots")),
				GraphSnapshotMaxRetained:                 getEnvInt("GRAPH_SNAPSHOT_MAX_RETAINED", 10),
				GraphWriterLeaseEnabled:                  getEnvBool("GRAPH_WRITER_LEASE_ENABLED", false),
				GraphWriterLeaseBucket:                   getEnv("GRAPH_WRITER_LEASE_BUCKET", defaultGraphWriterLeaseBucket),
				GraphWriterLeaseName:                     getEnv("GRAPH_WRITER_LEASE_NAME", defaultGraphWriterLeaseName),
				GraphWriterLeaseOwnerID:                  getEnv("GRAPH_WRITER_LEASE_OWNER_ID", defaultGraphWriterLeaseOwnerID()),
				GraphWriterLeaseTTL:                      getEnvDuration("GRAPH_WRITER_LEASE_TTL", 15*time.Second),
				GraphWriterLeaseHeartbeat:                getEnvDuration("GRAPH_WRITER_LEASE_HEARTBEAT", 5*time.Second),
				GraphTenantShardIdleTTL:                  getEnvDuration("GRAPH_TENANT_SHARD_IDLE_TTL", defaultGraphTenantShardIdleTTL),
				GraphTenantWarmShardTTL:                  getEnvDuration("GRAPH_TENANT_WARM_SHARD_TTL", defaultGraphTenantWarmShardTTL),
				GraphTenantWarmShardMaxRetained:          getEnvInt("GRAPH_TENANT_WARM_SHARD_MAX_RETAINED", defaultGraphTenantWarmShardMaxRetained),
				GraphPropertyHistoryMaxEntries:           getEnvInt("GRAPH_PROPERTY_HISTORY_MAX_ENTRIES", graph.DefaultTemporalHistoryMaxEntries),
				GraphPropertyHistoryTTL:                  getEnvDuration("GRAPH_PROPERTY_HISTORY_TTL", graph.DefaultTemporalHistoryTTL),
				GraphSchemaValidationMode:                getEnv("GRAPH_SCHEMA_VALIDATION_MODE", "warn"),
				GraphEventMapperValidationMode:           getEnv("GRAPH_EVENT_MAPPER_VALIDATION_MODE", "enforce"),
				GraphEventMapperDeadLetterPath:           getEnv("GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH", filepath.Join(findings.DefaultFilePath(), "graph-event-mapper.dlq.jsonl")),
				GraphMigrateLegacyActivityOnStart:        getEnvBool("GRAPH_MIGRATE_LEGACY_ACTIVITY_ON_START", false),
				GraphConsistencyCheckEnabled:             getEnvBool("GRAPH_CONSISTENCY_CHECK_ENABLED", false),
				GraphConsistencyCheckInterval:            getEnvDuration("GRAPH_CONSISTENCY_CHECK_INTERVAL", 6*time.Hour),
				GraphConsistencyCheckTimeout:             getEnvDuration("GRAPH_CONSISTENCY_CHECK_TIMEOUT", defaultGraphConsistencyCheckTimeout),
				GraphPostSyncUpdateTimeout:               getEnvDuration("GRAPH_POST_SYNC_UPDATE_TIMEOUT", defaultGraphPostSyncUpdateTimeout),
				GraphRiskEngineStateTimeout:              getEnvDuration("GRAPH_RISK_ENGINE_STATE_TIMEOUT", defaultGraphRiskEngineStateTimeout),
				GraphFreshnessDefaultSLA:                 getEnvDuration("CEREBRO_GRAPH_FRESHNESS_DEFAULT_SLA", 6*time.Hour),
				GraphFreshnessProviderSLAs:               parseDurationEnvMap("CEREBRO_FRESHNESS_SLA_"),
				GraphOntologyFallbackWarnPct:             getEnvFloat("GRAPH_ONTOLOGY_FALLBACK_WARN_PERCENT", 12),
				GraphOntologyFallbackCriticalPct:         getEnvFloat("GRAPH_ONTOLOGY_FALLBACK_CRITICAL_PERCENT", 25),
				GraphOntologySchemaValidWarnPct:          getEnvFloat("GRAPH_ONTOLOGY_SCHEMA_VALID_WARN_PERCENT", 98),
				GraphOntologySchemaValidCriticalPct:      getEnvFloat("GRAPH_ONTOLOGY_SCHEMA_VALID_CRITICAL_PERCENT", 92),
				ThreatIntelSyncTimeout:                   getEnvDuration("CEREBRO_THREAT_INTEL_SYNC_TIMEOUT", defaultThreatIntelSyncTimeout),
				ThreatIntelSyncMaxAge:                    getEnvDuration("CEREBRO_THREAT_INTEL_SYNC_MAX_AGE", defaultThreatIntelSyncMaxAge),
				ThreatIntelSyncAttempts:                  getEnvInt("CEREBRO_THREAT_INTEL_SYNC_ATTEMPTS", defaultThreatIntelSyncAttempts),
				ThreatIntelSyncBackoff:                   getEnvDuration("CEREBRO_THREAT_INTEL_SYNC_BACKOFF", defaultThreatIntelSyncBackoff),
			}
		})
	})

	cfg.RefreshProviderAwareConfig()
	return &cfg
}
