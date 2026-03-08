// Package app provides the main application container that wires together all
// Cerebro services and manages their lifecycle. This is the central dependency
// injection point for the application.
//
// The App struct holds references to all services organized into categories:
//
// Core Services:
//   - Snowflake: Data warehouse client for asset and findings storage
//   - Policy: Security policy engine for evaluating cloud resources
//   - Findings: In-memory findings store with deduplication
//   - Scanner: Asset scanner that applies policies to cloud resources
//   - Cache: Policy evaluation cache for performance
//
// Feature Services:
//   - Agents: AI-powered security investigation agents (Anthropic/OpenAI)
//   - Ticketing: Integration with Jira, Linear for finding tracking
//   - Identity: Stale access detection and identity analytics
//   - AttackPath: Attack path analysis and graph queries
//   - Providers: Custom data source integrations (CrowdStrike, Snyk, etc.)
//   - Notifications: Slack, PagerDuty, webhook notifications
//   - Scheduler: Periodic job scheduling for scans and syncs
//
// Security Services:
//   - RBAC: Role-based access control and multi-tenancy
//   - ThreatIntel: Threat intelligence feed management
//   - RuntimeDetect: Real-time threat detection engine
//   - RuntimeRespond: Automated response and containment
//   - Lineage: Deployment lineage tracking
//   - Remediation: Auto-remediation playbooks
//
// The New() function initializes all services based on environment configuration.
// Services gracefully handle missing configuration (e.g., no Snowflake connection).
//
//go:generate sh -c "cd ../.. && go run ./scripts/generate_config_docs/main.go"
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/cache"
	"github.com/evalops/cerebro/internal/compliance"
	"github.com/evalops/cerebro/internal/dspm"
	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/identity"
	"github.com/evalops/cerebro/internal/lineage"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/providers"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/scheduler"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/ticketing"
	"github.com/evalops/cerebro/internal/webhooks"

	"golang.org/x/sync/errgroup"
)

type retentionCleaner interface {
	CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupAgentData(ctx context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error)
	CleanupGraphData(ctx context.Context, olderThan time.Time) (pathsDeleted, edgesDeleted, nodesDeleted int64, err error)
	CleanupAccessReviewData(ctx context.Context, olderThan time.Time) (reviewsDeleted, itemsDeleted int64, err error)
}

// App is the main application container that holds references to all initialized
// services. Create a new App using the New() function which handles all service
// initialization and wiring based on environment configuration.
//
// Use the Close() method to gracefully shutdown all services when the application
// is terminating.
type App struct {
	Config *Config
	Logger *slog.Logger

	// Core services
	Snowflake *snowflake.Client
	Policy    *policy.Engine
	Findings  findings.FindingStore
	Scanner   *scanner.Scanner
	DSPM      *dspm.Scanner
	Cache     *cache.PolicyCache

	// Feature services
	Agents        *agents.AgentRegistry
	Ticketing     *ticketing.Service
	Identity      *identity.Service
	AttackPath    *attackpath.Graph
	Providers     *providers.Registry
	Webhooks      *webhooks.Service
	TapConsumer   *events.Consumer
	RemoteTools   *agents.RemoteToolProvider
	Notifications *notifications.Manager
	Scheduler     *scheduler.Scheduler

	// Repositories (for Snowflake persistence)
	FindingsRepo      *snowflake.FindingRepository
	TicketsRepo       *snowflake.TicketRepository
	AuditRepo         *snowflake.AuditRepository
	PolicyHistoryRepo *snowflake.PolicyHistoryRepository
	RetentionRepo     retentionCleaner

	// Snowflake-backed stores (when available)
	SnowflakeFindings *findings.SnowflakeStore

	// Incremental scanning
	ScanWatermarks *scanner.WatermarkStore

	// New services
	RBAC                *auth.RBAC
	ThreatIntel         *threatintel.ThreatIntelService
	Compliance          *compliance.ComplianceReport
	Health              *health.Registry
	Lineage             *lineage.LineageMapper
	Remediation         *remediation.Engine
	RemediationExecutor *remediation.Executor
	RuntimeDetect       *runtime.DetectionEngine
	RuntimeRespond      *runtime.ResponseEngine

	// Security Graph
	SecurityGraph        *graph.Graph
	SecurityGraphBuilder *graph.Builder
	Propagation          *graph.PropagationEngine
	graphReady           chan struct{} // closed when initial graph build completes
	graphCancel          context.CancelFunc
	traceShutdown        func(context.Context) error
	secretsReloadCancel  context.CancelFunc
	secretsReloadWG      sync.WaitGroup
	reloadMu             sync.Mutex
	apiKeys              atomic.Value // map[string]string
	secretsLoader        secretsLoader

	// Cached table list from Snowflake (shared by graph builder + policy coverage)
	AvailableTables []string
}

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
	NATSConsumerEnabled      bool
	NATSConsumerStream       string
	NATSConsumerSubjects     []string
	NATSConsumerDurable      string
	NATSConsumerBatchSize    int
	NATSConsumerAckWait      time.Duration
	NATSConsumerFetchTimeout time.Duration

	// Remote tool proxy for AI agents (Ensemble tools via NATS request/reply)
	AgentRemoteToolsEnabled         bool
	AgentRemoteToolsManifestSubject string
	AgentRemoteToolsRequestPrefix   string
	AgentRemoteToolsDiscoverTimeout time.Duration
	AgentRemoteToolsRequestTimeout  time.Duration
	AgentRemoteToolsMaxTools        int

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
	APIAuthEnabled        bool
	APIKeys               map[string]string
	SecretsReloadInterval time.Duration
	RBACStateFile         string

	// Nested provider-aware view (derived from flat env-backed fields)
	Providers ProviderAwareConfig
}

func LoadConfig() *Config {
	apiKeys := parseAPIKeys(getEnv("API_KEYS", ""))
	apiAuthEnabled := getEnvBool("API_AUTH_ENABLED", len(apiKeys) > 0)

	cfg := &Config{
		Port:                               getEnvInt("API_PORT", 8080),
		LogLevel:                           getEnv("LOG_LEVEL", "info"),
		TracingEnabled:                     getEnvBool("CEREBRO_OTEL_ENABLED", false),
		TracingServiceName:                 getEnv("CEREBRO_OTEL_SERVICE_NAME", "cerebro"),
		TracingOTLPEndpoint:                getEnv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")),
		TracingOTLPInsecure:                getEnvBool("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false)),
		TracingOTLPHeaders:                 parseKeyValueCSV(getEnv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", getEnv("OTEL_EXPORTER_OTLP_HEADERS", ""))),
		TracingSampleRatio:                 getEnvFloat("CEREBRO_OTEL_SAMPLE_RATIO", 1.0),
		TracingExportTimeout:               getEnvDuration("CEREBRO_OTEL_EXPORT_TIMEOUT", 5*time.Second),
		SnowflakeAccount:                   getEnv("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:                      getEnv("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey:                normalizePrivateKey(getEnv("SNOWFLAKE_PRIVATE_KEY", "")),
		SnowflakeDatabase:                  getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:                    getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeWarehouse:                 getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeRole:                      getEnv("SNOWFLAKE_ROLE", ""),
		PoliciesPath:                       getEnv("POLICIES_PATH", "policies"),
		QueryPolicyRowLimit:                getEnvInt("QUERY_POLICY_ROW_LIMIT", snowflake.MaxReadOnlyQueryLimit),
		AnthropicAPIKey:                    getEnv("ANTHROPIC_API_KEY", ""),
		OpenAIAPIKey:                       getEnv("OPENAI_API_KEY", ""),
		JiraBaseURL:                        getEnv("JIRA_BASE_URL", ""),
		JiraEmail:                          getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:                       getEnv("JIRA_API_TOKEN", ""),
		JiraProject:                        getEnv("JIRA_PROJECT", "SEC"),
		JiraCloseTransitions:               splitCSV(getEnv("JIRA_CLOSE_TRANSITIONS", "Done,Closed,Resolve Issue")),
		LinearAPIKey:                       getEnv("LINEAR_API_KEY", ""),
		LinearTeamID:                       getEnv("LINEAR_TEAM_ID", ""),
		CrowdStrikeClientID:                getEnv("CROWDSTRIKE_CLIENT_ID", ""),
		CrowdStrikeClientSecret:            getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
		OktaDomain:                         getEnv("OKTA_DOMAIN", ""),
		OktaAPIToken:                       getEnv("OKTA_API_TOKEN", ""),
		EntraTenantID:                      getEnv("ENTRA_TENANT_ID", ""),
		EntraClientID:                      getEnv("ENTRA_CLIENT_ID", ""),
		EntraClientSecret:                  getEnv("ENTRA_CLIENT_SECRET", ""),
		AzureTenantID:                      getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:                      getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret:                  getEnv("AZURE_CLIENT_SECRET", ""),
		AzureSubscriptionID:                getEnv("AZURE_SUBSCRIPTION_ID", ""),
		SnykAPIToken:                       getEnv("SNYK_API_TOKEN", ""),
		SnykOrgID:                          getEnv("SNYK_ORG_ID", ""),
		ZoomAccountID:                      getEnv("ZOOM_ACCOUNT_ID", ""),
		ZoomClientID:                       getEnv("ZOOM_CLIENT_ID", ""),
		ZoomClientSecret:                   getEnv("ZOOM_CLIENT_SECRET", ""),
		ZoomAPIURL:                         getEnv("ZOOM_API_URL", "https://api.zoom.us/v2"),
		ZoomTokenURL:                       getEnv("ZOOM_TOKEN_URL", "https://zoom.us/oauth/token"),
		WizClientID:                        getEnv("WIZ_CLIENT_ID", ""),
		WizClientSecret:                    getEnv("WIZ_CLIENT_SECRET", ""),
		WizAPIURL:                          getEnv("WIZ_API_URL", ""),
		WizTokenURL:                        getEnv("WIZ_TOKEN_URL", "https://auth.app.wiz.io/oauth/token"),
		WizAudience:                        getEnv("WIZ_AUDIENCE", "wiz-api"),
		DatadogAPIKey:                      getEnv("DATADOG_API_KEY", ""),
		DatadogAppKey:                      getEnv("DATADOG_APP_KEY", ""),
		DatadogSite:                        getEnv("DATADOG_SITE", "datadoghq.com"),
		GitHubToken:                        getEnv("GITHUB_TOKEN", ""),
		GitHubOrg:                          getEnv("GITHUB_ORG", ""),
		FigmaAPIToken:                      getEnv("FIGMA_API_TOKEN", ""),
		FigmaTeamID:                        getEnv("FIGMA_TEAM_ID", ""),
		FigmaBaseURL:                       getEnv("FIGMA_BASE_URL", "https://api.figma.com"),
		SocketAPIToken:                     getEnv("SOCKET_API_TOKEN", ""),
		SocketOrgSlug:                      getEnv("SOCKET_ORG", ""),
		SocketAPIURL:                       getEnv("SOCKET_API_URL", "https://api.socket.dev/v0"),
		RampClientID:                       getEnv("RAMP_CLIENT_ID", ""),
		RampClientSecret:                   getEnv("RAMP_CLIENT_SECRET", ""),
		RampAPIURL:                         getEnv("RAMP_API_URL", "https://api.ramp.com/developer/v1"),
		RampTokenURL:                       getEnv("RAMP_TOKEN_URL", "https://api.ramp.com/developer/v1/token"),
		GongAccessKey:                      getEnv("GONG_ACCESS_KEY", ""),
		GongAccessSecret:                   getEnv("GONG_ACCESS_SECRET", ""),
		GongBaseURL:                        getEnv("GONG_BASE_URL", "https://api.gong.io"),
		VantaAPIToken:                      getEnv("VANTA_API_TOKEN", ""),
		VantaBaseURL:                       getEnv("VANTA_BASE_URL", "https://api.vanta.com"),
		PantherAPIToken:                    getEnv("PANTHER_API_TOKEN", ""),
		PantherBaseURL:                     getEnv("PANTHER_BASE_URL", "https://api.runpanther.io/public_api/v1"),
		KolideAPIToken:                     getEnv("KOLIDE_API_TOKEN", ""),
		KolideBaseURL:                      getEnv("KOLIDE_BASE_URL", "https://api.kolide.com/v1"),
		GoogleWorkspaceDomain:              getEnv("GOOGLE_WORKSPACE_DOMAIN", ""),
		GoogleWorkspaceAdminEmail:          getEnv("GOOGLE_WORKSPACE_ADMIN_EMAIL", ""),
		GoogleWorkspaceImpersonatorEmail:   getEnv("GOOGLE_WORKSPACE_IMPERSONATOR_EMAIL", ""),
		GoogleWorkspaceCredentialsFile:     getEnv("GOOGLE_WORKSPACE_CREDENTIALS_FILE", ""),
		GoogleWorkspaceCredentialsJSON:     getEnv("GOOGLE_WORKSPACE_CREDENTIALS_JSON", ""),
		TailscaleAPIKey:                    getEnv("TAILSCALE_API_KEY", ""),
		TailscaleTailnet:                   getEnv("TAILSCALE_TAILNET", ""),
		SentinelOneAPIToken:                getEnv("SENTINELONE_API_TOKEN", ""),
		SentinelOneBaseURL:                 getEnv("SENTINELONE_BASE_URL", ""),
		TenableAccessKey:                   getEnv("TENABLE_ACCESS_KEY", ""),
		TenableSecretKey:                   getEnv("TENABLE_SECRET_KEY", ""),
		QualysUsername:                     getEnv("QUALYS_USERNAME", ""),
		QualysPassword:                     getEnv("QUALYS_PASSWORD", ""),
		QualysPlatform:                     getEnv("QUALYS_PLATFORM", "US1"),
		SemgrepAPIToken:                    getEnv("SEMGREP_API_TOKEN", ""),
		ServiceNowURL:                      getEnv("SERVICENOW_URL", ""),
		ServiceNowAPIToken:                 getEnv("SERVICENOW_API_TOKEN", ""),
		ServiceNowUsername:                 getEnv("SERVICENOW_USERNAME", ""),
		ServiceNowPassword:                 getEnv("SERVICENOW_PASSWORD", ""),
		WorkdayURL:                         getEnv("WORKDAY_URL", ""),
		WorkdayAPIToken:                    getEnv("WORKDAY_API_TOKEN", ""),
		BambooHRURL:                        getEnv("BAMBOOHR_URL", ""),
		BambooHRAPIToken:                   getEnv("BAMBOOHR_API_TOKEN", ""),
		OneLoginURL:                        getEnv("ONELOGIN_URL", ""),
		OneLoginClientID:                   getEnv("ONELOGIN_CLIENT_ID", ""),
		OneLoginClientSecret:               getEnv("ONELOGIN_CLIENT_SECRET", ""),
		JumpCloudURL:                       getEnv("JUMPCLOUD_URL", "https://console.jumpcloud.com"),
		JumpCloudAPIToken:                  getEnv("JUMPCLOUD_API_TOKEN", ""),
		JumpCloudOrgID:                     getEnv("JUMPCLOUD_ORG_ID", ""),
		DuoURL:                             getEnv("DUO_URL", getEnv("DUO_API_HOSTNAME", "")),
		DuoIntegrationKey:                  getEnv("DUO_INTEGRATION_KEY", getEnv("DUO_IKEY", "")),
		DuoSecretKey:                       getEnv("DUO_SECRET_KEY", getEnv("DUO_SKEY", "")),
		PingIdentityEnvironmentID:          getEnv("PINGIDENTITY_ENVIRONMENT_ID", getEnv("PINGONE_ENVIRONMENT_ID", "")),
		PingIdentityClientID:               getEnv("PINGIDENTITY_CLIENT_ID", getEnv("PINGONE_CLIENT_ID", "")),
		PingIdentityClientSecret:           getEnv("PINGIDENTITY_CLIENT_SECRET", getEnv("PINGONE_CLIENT_SECRET", "")),
		PingIdentityAPIURL:                 getEnv("PINGIDENTITY_API_URL", "https://api.pingone.com"),
		PingIdentityAuthURL:                getEnv("PINGIDENTITY_AUTH_URL", "https://auth.pingone.com"),
		CyberArkURL:                        getEnv("CYBERARK_URL", ""),
		CyberArkAPIToken:                   getEnv("CYBERARK_API_TOKEN", ""),
		SailPointURL:                       getEnv("SAILPOINT_URL", ""),
		SailPointAPIToken:                  getEnv("SAILPOINT_API_TOKEN", ""),
		SaviyntURL:                         getEnv("SAVIYNT_URL", ""),
		SaviyntAPIToken:                    getEnv("SAVIYNT_API_TOKEN", ""),
		ForgeRockURL:                       getEnv("FORGEROCK_URL", ""),
		ForgeRockAPIToken:                  getEnv("FORGEROCK_API_TOKEN", ""),
		OracleIDCSURL:                      getEnv("ORACLE_IDCS_URL", ""),
		OracleIDCSAPIToken:                 getEnv("ORACLE_IDCS_API_TOKEN", ""),
		GitLabToken:                        getEnv("GITLAB_TOKEN", ""),
		GitLabBaseURL:                      getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
		TerraformCloudToken:                getEnv("TFC_TOKEN", ""),
		SplunkURL:                          getEnv("SPLUNK_URL", ""),
		SplunkToken:                        getEnv("SPLUNK_TOKEN", ""),
		Auth0Domain:                        getEnv("AUTH0_DOMAIN", ""),
		Auth0ClientID:                      getEnv("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:                  getEnv("AUTH0_CLIENT_SECRET", ""),
		CloudflareAPIToken:                 getEnv("CLOUDFLARE_API_TOKEN", ""),
		SalesforceInstanceURL:              getEnv("SALESFORCE_INSTANCE_URL", ""),
		SalesforceClientID:                 getEnv("SALESFORCE_CLIENT_ID", ""),
		SalesforceClientSecret:             getEnv("SALESFORCE_CLIENT_SECRET", ""),
		SalesforceUsername:                 getEnv("SALESFORCE_USERNAME", ""),
		SalesforcePassword:                 getEnv("SALESFORCE_PASSWORD", ""),
		SalesforceSecurityToken:            getEnv("SALESFORCE_SECURITY_TOKEN", ""),
		VaultAddress:                       getEnv("VAULT_ADDRESS", ""),
		VaultToken:                         getEnv("VAULT_TOKEN", ""),
		VaultNamespace:                     getEnv("VAULT_NAMESPACE", ""),
		SlackAPIToken:                      getEnv("SLACK_API_TOKEN", ""),
		RipplingAPIURL:                     getEnv("RIPPLING_API_URL", ""),
		RipplingAPIToken:                   getEnv("RIPPLING_API_TOKEN", ""),
		JamfBaseURL:                        getEnv("JAMF_BASE_URL", ""),
		JamfClientID:                       getEnv("JAMF_CLIENT_ID", ""),
		JamfClientSecret:                   getEnv("JAMF_CLIENT_SECRET", ""),
		IntuneTenantID:                     getEnv("INTUNE_TENANT_ID", ""),
		IntuneClientID:                     getEnv("INTUNE_CLIENT_ID", ""),
		IntuneClientSecret:                 getEnv("INTUNE_CLIENT_SECRET", ""),
		KandjiAPIURL:                       getEnv("KANDJI_API_URL", ""),
		KandjiAPIToken:                     getEnv("KANDJI_API_TOKEN", ""),
		S3InputBucket:                      getEnv("S3_INPUT_BUCKET", ""),
		S3InputPrefix:                      getEnv("S3_INPUT_PREFIX", ""),
		S3InputRegion:                      getEnv("S3_INPUT_REGION", getEnv("AWS_REGION", "us-east-1")),
		S3InputFormat:                      getEnv("S3_INPUT_FORMAT", "auto"),
		S3InputMaxObjects:                  getEnvInt("S3_INPUT_MAX_OBJECTS", 200),
		CloudTrailRegion:                   getEnv("CLOUDTRAIL_REGION", ""),
		CloudTrailTrailARN:                 getEnv("CLOUDTRAIL_TRAIL_ARN", ""),
		CloudTrailLookbackDays:             getEnvInt("CLOUDTRAIL_LOOKBACK_DAYS", 7),
		WebhookURLs:                        splitCSV(getEnv("WEBHOOK_URLS", "")),
		NATSJetStreamEnabled:               getEnvBool("NATS_JETSTREAM_ENABLED", false),
		NATSJetStreamURLs:                  splitCSV(getEnv("NATS_URLS", "nats://127.0.0.1:4222")),
		NATSJetStreamStream:                getEnv("NATS_JETSTREAM_STREAM", "CEREBRO_EVENTS"),
		NATSJetStreamSubjectPrefix:         getEnv("NATS_JETSTREAM_SUBJECT_PREFIX", "cerebro.events"),
		NATSJetStreamSource:                getEnv("NATS_JETSTREAM_SOURCE", "cerebro"),
		NATSJetStreamOutboxPath:            getEnv("NATS_JETSTREAM_OUTBOX_PATH", filepath.Join(findings.DefaultFilePath(), "jetstream-outbox.jsonl")),
		NATSJetStreamOutboxDLQPath:         getEnv("NATS_JETSTREAM_OUTBOX_DLQ_PATH", ""),
		NATSJetStreamOutboxMaxAge:          getEnvDuration("NATS_JETSTREAM_OUTBOX_MAX_AGE", 7*24*time.Hour),
		NATSJetStreamOutboxMaxItems:        getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_ITEMS", 10000),
		NATSJetStreamOutboxMaxRetry:        getEnvInt("NATS_JETSTREAM_OUTBOX_MAX_RETRY", 10),
		NATSJetStreamOutboxWarnPercent:     getEnvInt("NATS_JETSTREAM_OUTBOX_WARN_PERCENT", 70),
		NATSJetStreamOutboxCriticalPercent: getEnvInt("NATS_JETSTREAM_OUTBOX_CRITICAL_PERCENT", 90),
		NATSJetStreamOutboxWarnAge:         getEnvDuration("NATS_JETSTREAM_OUTBOX_WARN_AGE", time.Hour),
		NATSJetStreamOutboxCriticalAge:     getEnvDuration("NATS_JETSTREAM_OUTBOX_CRITICAL_AGE", 6*time.Hour),
		NATSJetStreamPublishTimeout:        getEnvDuration("NATS_JETSTREAM_PUBLISH_TIMEOUT", 3*time.Second),
		NATSJetStreamRetryAttempts:         getEnvInt("NATS_JETSTREAM_RETRY_ATTEMPTS", 3),
		NATSJetStreamRetryBackoff:          getEnvDuration("NATS_JETSTREAM_RETRY_BACKOFF", 500*time.Millisecond),
		NATSJetStreamFlushInterval:         getEnvDuration("NATS_JETSTREAM_FLUSH_INTERVAL", 10*time.Second),
		NATSJetStreamConnectTimeout:        getEnvDuration("NATS_JETSTREAM_CONNECT_TIMEOUT", 5*time.Second),
		NATSJetStreamAuthMode:              getEnv("NATS_JETSTREAM_AUTH_MODE", "none"),
		NATSJetStreamUsername:              getEnv("NATS_JETSTREAM_USERNAME", ""),
		NATSJetStreamPassword:              getEnv("NATS_JETSTREAM_PASSWORD", ""),
		NATSJetStreamNKeySeed:              getEnv("NATS_JETSTREAM_NKEY_SEED", ""),
		NATSJetStreamUserJWT:               getEnv("NATS_JETSTREAM_USER_JWT", ""),
		NATSJetStreamTLSEnabled:            getEnvBool("NATS_JETSTREAM_TLS_ENABLED", false),
		NATSJetStreamTLSCAFile:             getEnv("NATS_JETSTREAM_TLS_CA_FILE", ""),
		NATSJetStreamTLSCertFile:           getEnv("NATS_JETSTREAM_TLS_CERT_FILE", ""),
		NATSJetStreamTLSKeyFile:            getEnv("NATS_JETSTREAM_TLS_KEY_FILE", ""),
		NATSJetStreamTLSServerName:         getEnv("NATS_JETSTREAM_TLS_SERVER_NAME", ""),
		NATSJetStreamTLSInsecure:           getEnvBool("NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY", false),
		NATSConsumerEnabled:                getEnvBool("NATS_CONSUMER_ENABLED", false),
		NATSConsumerStream:                 getEnv("NATS_CONSUMER_STREAM", "ENSEMBLE_TAP"),
		NATSConsumerSubjects:               splitCSV(getEnv("NATS_CONSUMER_SUBJECTS", "ensemble.tap.>")),
		NATSConsumerDurable:                getEnv("NATS_CONSUMER_DURABLE", "cerebro_graph_builder"),
		NATSConsumerBatchSize:              getEnvInt("NATS_CONSUMER_BATCH_SIZE", 50),
		NATSConsumerAckWait:                getEnvDuration("NATS_CONSUMER_ACK_WAIT", 30*time.Second),
		NATSConsumerFetchTimeout:           getEnvDuration("NATS_CONSUMER_FETCH_TIMEOUT", 2*time.Second),
		AgentRemoteToolsEnabled:            getEnvBool("AGENT_REMOTE_TOOLS_ENABLED", false),
		AgentRemoteToolsManifestSubject:    getEnv("AGENT_REMOTE_TOOLS_MANIFEST_SUBJECT", "ensemble.tools.manifest"),
		AgentRemoteToolsRequestPrefix:      getEnv("AGENT_REMOTE_TOOLS_REQUEST_PREFIX", "ensemble.tools.request"),
		AgentRemoteToolsDiscoverTimeout:    getEnvDuration("AGENT_REMOTE_TOOLS_DISCOVER_TIMEOUT", 5*time.Second),
		AgentRemoteToolsRequestTimeout:     getEnvDuration("AGENT_REMOTE_TOOLS_REQUEST_TIMEOUT", 30*time.Second),
		AgentRemoteToolsMaxTools:           getEnvInt("AGENT_REMOTE_TOOLS_MAX_TOOLS", 200),
		SlackWebhookURL:                    getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:                 getEnv("SLACK_SIGNING_SECRET", ""),
		PagerDutyKey:                       getEnv("PAGERDUTY_ROUTING_KEY", ""),
		ScanInterval:                       getEnv("SCAN_INTERVAL", ""),
		SecurityDigestInterval:             getEnv("SECURITY_DIGEST_INTERVAL", ""),
		ScanTables:                         getEnv("SCAN_TABLES", ""),
		RetentionJobInterval:               getEnvDuration("CEREBRO_RETENTION_JOB_INTERVAL", 24*time.Hour),
		AuditRetentionDays:                 getEnvInt("CEREBRO_AUDIT_RETENTION_DAYS", 0),
		SessionRetentionDays:               getEnvInt("CEREBRO_SESSION_RETENTION_DAYS", 0),
		GraphRetentionDays:                 getEnvInt("CEREBRO_GRAPH_RETENTION_DAYS", 0),
		AccessReviewRetentionDays:          getEnvInt("CEREBRO_ACCESS_REVIEW_RETENTION_DAYS", 0),
		ScanTableTimeout:                   getEnvDuration("SCAN_TABLE_TIMEOUT", 30*time.Minute),
		ScanMaxConcurrent:                  getEnvInt("SCAN_MAX_CONCURRENCY", 6),
		ScanMinConcurrent:                  getEnvInt("SCAN_MIN_CONCURRENCY", 2),
		ScanAdaptiveConcurrency:            getEnvBool("SCAN_ADAPTIVE_CONCURRENCY", true),
		ScanRetryAttempts:                  getEnvInt("SCAN_RETRY_ATTEMPTS", 3),
		ScanRetryBackoff:                   getEnvDuration("SCAN_RETRY_BACKOFF", 2*time.Second),
		ScanRetryMaxBackoff:                getEnvDuration("SCAN_RETRY_MAX_BACKOFF", 30*time.Second),
		FindingAttestationEnabled:          getEnvBool("FINDING_ATTESTATION_ENABLED", false),
		FindingAttestationSigningKey:       normalizePrivateKey(getEnv("FINDING_ATTESTATION_SIGNING_KEY", "")),
		FindingAttestationKeyID:            getEnv("FINDING_ATTESTATION_KEY_ID", ""),
		FindingAttestationLogURL:           getEnv("FINDING_ATTESTATION_LOG_URL", ""),
		FindingAttestationTimeout:          getEnvDuration("FINDING_ATTESTATION_TIMEOUT", 3*time.Second),
		FindingAttestationAttestReobserved: getEnvBool("FINDING_ATTESTATION_ATTEST_REOBSERVED", false),
		JobQueueURL:                        getEnv("JOB_QUEUE_URL", ""),
		JobTableName:                       getEnv("JOB_TABLE_NAME", ""),
		JobRegion:                          getEnv("JOB_REGION", getEnv("AWS_REGION", "")),
		JobWorkerConcurrency:               getEnvInt("JOB_WORKER_CONCURRENCY", 4),
		JobVisibilityTimeout:               getEnvDuration("JOB_VISIBILITY_TIMEOUT", 30*time.Second),
		JobPollWait:                        getEnvDuration("JOB_POLL_WAIT", 10*time.Second),
		JobMaxAttempts:                     getEnvInt("JOB_MAX_ATTEMPTS", 3),
		JobIdempotencyTableName:            getEnv("JOB_IDEMPOTENCY_TABLE_NAME", ""),
		RateLimitEnabled:                   getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests:                  getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:                    getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
		RateLimitTrustedProxies:            splitCSV(getEnv("RATE_LIMIT_TRUSTED_PROXIES", "")),
		CORSAllowedOrigins:                 splitCSV(getEnv("API_CORS_ALLOWED_ORIGINS", "")),
		APIAuthEnabled:                     apiAuthEnabled,
		APIKeys:                            apiKeys,
		SecretsReloadInterval:              getEnvDuration("CEREBRO_SECRETS_RELOAD_INTERVAL", 0),
		RBACStateFile:                      getEnv("RBAC_STATE_FILE", ""),
	}

	cfg.RefreshProviderAwareConfig()
	return cfg
}

// New creates and wires up the entire application using environment-backed config.
func New(ctx context.Context) (*App, error) {
	return NewWithConfig(ctx, LoadConfig())
}

// NewWithConfig creates and wires up the entire application from an explicit config.
// This enables deterministic integration tests and gradual container decomposition
// without relying on process-wide environment mutation.
func NewWithConfig(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		cfg = LoadConfig()
	}
	cfg.RefreshProviderAwareConfig()

	if cfg.APIAuthEnabled && len(cfg.APIKeys) == 0 {
		return nil, fmt.Errorf("api auth enabled but no API_KEYS configured")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))

	app := &App{
		Config: cfg,
		Logger: logger,
	}
	app.secretsLoader = envSecretsLoader{}
	app.setAPIKeys(cfg.APIKeys)

	if err := runInitErrorStep("telemetry", func() error { return app.initTelemetry(ctx) }); err != nil {
		logger.Warn("telemetry initialization failed", "error", err)
	}

	// Phase 1: Snowflake + policies (everything else depends on these)
	if err := runInitErrorStep("snowflake", func() error { return app.initSnowflake(ctx) }); err != nil {
		logger.Warn("snowflake initialization failed", "error", err)
	}
	if err := runInitErrorStep("policy", app.initPolicy); err != nil {
		return nil, err
	}

	// Phase 2a: independent services in parallel (no cross-dependencies)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return runInitStep("cache", app.initCache) })
	g.Go(func() error { return runInitStep("ticketing", app.initTicketing) })
	g.Go(func() error { return runInitStep("identity", app.initIdentity) })
	g.Go(func() error { return runInitStep("attackpath", app.initAttackPath) })
	g.Go(func() error { return runInitStep("webhooks", app.initWebhooks) })
	g.Go(func() error { return runInitStep("notifications", app.initNotifications) })
	g.Go(func() error { return runInitStep("rbac", app.initRBAC) })
	g.Go(func() error { return runInitStep("compliance", app.initCompliance) })
	g.Go(func() error { return runInitStep("health", app.initHealth) })
	g.Go(func() error { return runInitStep("lineage", app.initLineage) })
	g.Go(func() error { return runInitStep("runtime", app.initRuntime) })
	g.Go(func() error { return runInitStep("findings", app.initFindings) })
	g.Go(func() error {
		return runInitStep("providers", func() { app.initProviders(gctx) })
	})
	g.Go(func() error {
		return runInitStep("scheduler", func() { app.initScheduler(gctx) })
	})
	g.Go(func() error { return runInitStep("repositories", app.initRepositories) })
	g.Go(func() error {
		return runInitStep("snowflake_findings", func() { app.initSnowflakeFindings(gctx) })
	})
	g.Go(func() error {
		return runInitStep("scan_watermarks", func() { app.initScanWatermarks(gctx) })
	})
	g.Go(func() error { return runInitStep("threatintel", func() { app.initThreatIntel(ctx) }) })
	g.Go(func() error {
		return runInitStep("available_tables", func() { app.initAvailableTables(gctx) })
	})

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("phase 2a init failed: %w", err)
	}

	// Phase 2b: services that depend on Phase 2a outputs
	// initRemediation reads Ticketing, Notifications, Findings
	// initAgents reads Findings
	g2, _ := errgroup.WithContext(ctx)
	g2.Go(func() error { return runInitStep("remediation", app.initRemediation) })
	g2.Go(func() error { return runInitStep("agents", app.initAgents) })
	if err := g2.Wait(); err != nil {
		return nil, fmt.Errorf("phase 2b init failed: %w", err)
	}
	app.startEventRemediation(ctx)

	// Phase 3: depends on findings store being ready
	app.initScanner()
	if err := app.validateRequiredServices(); err != nil {
		return nil, err
	}

	// Phase 4: depends on AvailableTables being populated
	app.initSecurityGraph(ctx)
	app.initTapGraphConsumer(ctx)
	if err := app.validatePolicyCoverage(ctx); err != nil {
		logger.Warn("policy coverage validation failed", "error", err)
		if os.Getenv("CI") != "" {
			return nil, err
		}
	}

	logger.Info("application initialized",
		"snowflake", app.Snowflake != nil,
		"policies", len(app.Policy.ListPolicies()),
	)
	app.startSecretsReloader(ctx)

	return app, nil
}

func runInitStep(name string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	fn()
	return nil
}

func runInitErrorStep(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	return fn()
}

func (a *App) validateRequiredServices() error {
	required := map[string]bool{
		"policy_engine":   a.Policy != nil,
		"findings_store":  a.Findings != nil,
		"scanner":         a.Scanner != nil,
		"cache":           a.Cache != nil,
		"agent_registry":  a.Agents != nil,
		"ticketing":       a.Ticketing != nil,
		"identity":        a.Identity != nil,
		"attackpath":      a.AttackPath != nil,
		"providers":       a.Providers != nil,
		"webhooks":        a.Webhooks != nil,
		"notifications":   a.Notifications != nil,
		"scheduler":       a.Scheduler != nil,
		"rbac":            a.RBAC != nil,
		"threatintel":     a.ThreatIntel != nil,
		"health":          a.Health != nil,
		"lineage":         a.Lineage != nil,
		"remediation":     a.Remediation != nil,
		"runtime_detect":  a.RuntimeDetect != nil,
		"runtime_respond": a.RuntimeRespond != nil,
	}

	var missing []string
	for service, initialized := range required {
		if initialized {
			continue
		}
		missing = append(missing, service)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("required services not initialized: %s", strings.Join(missing, ", "))
	}
	return nil
}
