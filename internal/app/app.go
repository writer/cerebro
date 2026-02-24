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
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/writerinternal/cerebro/internal/agents"
	agentproviders "github.com/writerinternal/cerebro/internal/agents/providers"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/auth"
	"github.com/writerinternal/cerebro/internal/cache"
	"github.com/writerinternal/cerebro/internal/compliance"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/graph"
	"github.com/writerinternal/cerebro/internal/health"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/lineage"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/remediation"
	"github.com/writerinternal/cerebro/internal/runtime"
	"github.com/writerinternal/cerebro/internal/scanner"
	"github.com/writerinternal/cerebro/internal/scheduler"
	"github.com/writerinternal/cerebro/internal/scm"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
	"github.com/writerinternal/cerebro/internal/threatintel"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"

	"golang.org/x/sync/errgroup"
)

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
	Cache     *cache.PolicyCache

	// Feature services
	Agents        *agents.AgentRegistry
	Ticketing     *ticketing.Service
	Identity      *identity.Service
	AttackPath    *attackpath.Graph
	Providers     *providers.Registry
	Webhooks      *webhooks.Service
	Notifications *notifications.Manager
	Scheduler     *scheduler.Scheduler

	// Repositories (for Snowflake persistence)
	FindingsRepo *snowflake.FindingRepository
	TicketsRepo  *snowflake.TicketRepository
	AuditRepo    *snowflake.AuditRepository

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
	graphReady           chan struct{} // closed when initial graph build completes
	graphCancel          context.CancelFunc

	// Cached table list from Snowflake (shared by graph builder + policy coverage)
	AvailableTables []string
}

// Config holds all application configuration
type Config struct {
	// Server
	Port     int
	LogLevel string

	// Snowflake (key-pair auth only)
	SnowflakeAccount    string
	SnowflakeUser       string
	SnowflakePrivateKey string
	SnowflakeDatabase   string
	SnowflakeSchema     string
	SnowflakeWarehouse  string
	SnowflakeRole       string

	// Policies
	PoliciesPath string

	// LLM Providers
	AnthropicAPIKey string
	OpenAIAPIKey    string

	// Ticketing
	JiraBaseURL  string
	JiraEmail    string
	JiraAPIToken string
	JiraProject  string
	LinearAPIKey string
	LinearTeamID string

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

	// Datadog Provider
	DatadogAPIKey string
	DatadogAppKey string
	DatadogSite   string

	// GitHub Provider
	GitHubToken string
	GitHubOrg   string

	// Google Workspace Provider
	GoogleWorkspaceDomain            string
	GoogleWorkspaceAdminEmail        string
	GoogleWorkspaceImpersonatorEmail string
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

	// CloudTrail Provider
	CloudTrailRegion       string
	CloudTrailTrailARN     string
	CloudTrailLookbackDays int

	// Webhooks
	WebhookURLs []string

	// Notifications
	SlackWebhookURL    string
	SlackSigningSecret string
	PagerDutyKey       string

	// Scheduler
	ScanInterval            string // e.g., "1h", "30m"
	ScanTables              string // comma-separated list of tables to scan
	ScanTableTimeout        time.Duration
	ScanMaxConcurrent       int
	ScanMinConcurrent       int
	ScanAdaptiveConcurrency bool
	ScanRetryAttempts       int
	ScanRetryBackoff        time.Duration
	ScanRetryMaxBackoff     time.Duration

	// Distributed jobs
	JobQueueURL          string
	JobTableName         string
	JobRegion            string
	JobWorkerConcurrency int
	JobVisibilityTimeout time.Duration
	JobPollWait          time.Duration
	JobMaxAttempts       int

	// Rate Limiting
	RateLimitEnabled  bool
	RateLimitRequests int
	RateLimitWindow   time.Duration

	// API Authentication
	APIAuthEnabled bool
	APIKeys        map[string]string
	RBACStateFile  string
}

func LoadConfig() *Config {
	apiKeys := parseAPIKeys(getEnv("API_KEYS", ""))
	apiAuthEnabled := getEnvBool("API_AUTH_ENABLED", len(apiKeys) > 0)

	return &Config{
		Port:                             getEnvInt("API_PORT", 8080),
		LogLevel:                         getEnv("LOG_LEVEL", "info"),
		SnowflakeAccount:                 getEnv("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:                    getEnv("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey:              normalizePrivateKey(getEnv("SNOWFLAKE_PRIVATE_KEY", "")),
		SnowflakeDatabase:                getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:                  getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeWarehouse:               getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeRole:                    getEnv("SNOWFLAKE_ROLE", ""),
		PoliciesPath:                     getEnv("POLICIES_PATH", "policies"),
		AnthropicAPIKey:                  getEnv("ANTHROPIC_API_KEY", ""),
		OpenAIAPIKey:                     getEnv("OPENAI_API_KEY", ""),
		JiraBaseURL:                      getEnv("JIRA_BASE_URL", ""),
		JiraEmail:                        getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:                     getEnv("JIRA_API_TOKEN", ""),
		JiraProject:                      getEnv("JIRA_PROJECT", "SEC"),
		LinearAPIKey:                     getEnv("LINEAR_API_KEY", ""),
		LinearTeamID:                     getEnv("LINEAR_TEAM_ID", ""),
		CrowdStrikeClientID:              getEnv("CROWDSTRIKE_CLIENT_ID", ""),
		CrowdStrikeClientSecret:          getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
		OktaDomain:                       getEnv("OKTA_DOMAIN", ""),
		OktaAPIToken:                     getEnv("OKTA_API_TOKEN", ""),
		EntraTenantID:                    getEnv("ENTRA_TENANT_ID", ""),
		EntraClientID:                    getEnv("ENTRA_CLIENT_ID", ""),
		EntraClientSecret:                getEnv("ENTRA_CLIENT_SECRET", ""),
		AzureTenantID:                    getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:                    getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret:                getEnv("AZURE_CLIENT_SECRET", ""),
		AzureSubscriptionID:              getEnv("AZURE_SUBSCRIPTION_ID", ""),
		SnykAPIToken:                     getEnv("SNYK_API_TOKEN", ""),
		SnykOrgID:                        getEnv("SNYK_ORG_ID", ""),
		DatadogAPIKey:                    getEnv("DATADOG_API_KEY", ""),
		DatadogAppKey:                    getEnv("DATADOG_APP_KEY", ""),
		DatadogSite:                      getEnv("DATADOG_SITE", "datadoghq.com"),
		GitHubToken:                      getEnv("GITHUB_TOKEN", ""),
		GitHubOrg:                        getEnv("GITHUB_ORG", ""),
		GoogleWorkspaceDomain:            getEnv("GOOGLE_WORKSPACE_DOMAIN", ""),
		GoogleWorkspaceAdminEmail:        getEnv("GOOGLE_WORKSPACE_ADMIN_EMAIL", ""),
		GoogleWorkspaceImpersonatorEmail: getEnv("GOOGLE_WORKSPACE_IMPERSONATOR_EMAIL", ""),
		GoogleWorkspaceCredentialsJSON:   getEnv("GOOGLE_WORKSPACE_CREDENTIALS_JSON", ""),
		TailscaleAPIKey:                  getEnv("TAILSCALE_API_KEY", ""),
		TailscaleTailnet:                 getEnv("TAILSCALE_TAILNET", ""),
		SentinelOneAPIToken:              getEnv("SENTINELONE_API_TOKEN", ""),
		SentinelOneBaseURL:               getEnv("SENTINELONE_BASE_URL", ""),
		TenableAccessKey:                 getEnv("TENABLE_ACCESS_KEY", ""),
		TenableSecretKey:                 getEnv("TENABLE_SECRET_KEY", ""),
		QualysUsername:                   getEnv("QUALYS_USERNAME", ""),
		QualysPassword:                   getEnv("QUALYS_PASSWORD", ""),
		QualysPlatform:                   getEnv("QUALYS_PLATFORM", "US1"),
		SemgrepAPIToken:                  getEnv("SEMGREP_API_TOKEN", ""),
		GitLabToken:                      getEnv("GITLAB_TOKEN", ""),
		GitLabBaseURL:                    getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
		TerraformCloudToken:              getEnv("TFC_TOKEN", ""),
		SplunkURL:                        getEnv("SPLUNK_URL", ""),
		SplunkToken:                      getEnv("SPLUNK_TOKEN", ""),
		Auth0Domain:                      getEnv("AUTH0_DOMAIN", ""),
		Auth0ClientID:                    getEnv("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:                getEnv("AUTH0_CLIENT_SECRET", ""),
		CloudflareAPIToken:               getEnv("CLOUDFLARE_API_TOKEN", ""),
		SalesforceInstanceURL:            getEnv("SALESFORCE_INSTANCE_URL", ""),
		SalesforceClientID:               getEnv("SALESFORCE_CLIENT_ID", ""),
		SalesforceClientSecret:           getEnv("SALESFORCE_CLIENT_SECRET", ""),
		SalesforceUsername:               getEnv("SALESFORCE_USERNAME", ""),
		SalesforcePassword:               getEnv("SALESFORCE_PASSWORD", ""),
		SalesforceSecurityToken:          getEnv("SALESFORCE_SECURITY_TOKEN", ""),
		VaultAddress:                     getEnv("VAULT_ADDRESS", ""),
		VaultToken:                       getEnv("VAULT_TOKEN", ""),
		VaultNamespace:                   getEnv("VAULT_NAMESPACE", ""),
		SlackAPIToken:                    getEnv("SLACK_API_TOKEN", ""),
		RipplingAPIURL:                   getEnv("RIPPLING_API_URL", ""),
		RipplingAPIToken:                 getEnv("RIPPLING_API_TOKEN", ""),
		JamfBaseURL:                      getEnv("JAMF_BASE_URL", ""),
		JamfClientID:                     getEnv("JAMF_CLIENT_ID", ""),
		JamfClientSecret:                 getEnv("JAMF_CLIENT_SECRET", ""),
		IntuneTenantID:                   getEnv("INTUNE_TENANT_ID", ""),
		IntuneClientID:                   getEnv("INTUNE_CLIENT_ID", ""),
		IntuneClientSecret:               getEnv("INTUNE_CLIENT_SECRET", ""),
		KandjiAPIURL:                     getEnv("KANDJI_API_URL", ""),
		KandjiAPIToken:                   getEnv("KANDJI_API_TOKEN", ""),
		CloudTrailRegion:                 getEnv("CLOUDTRAIL_REGION", ""),
		CloudTrailTrailARN:               getEnv("CLOUDTRAIL_TRAIL_ARN", ""),
		CloudTrailLookbackDays:           getEnvInt("CLOUDTRAIL_LOOKBACK_DAYS", 7),
		WebhookURLs:                      splitCSV(getEnv("WEBHOOK_URLS", "")),
		SlackWebhookURL:                  getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:               getEnv("SLACK_SIGNING_SECRET", ""),
		PagerDutyKey:                     getEnv("PAGERDUTY_ROUTING_KEY", ""),
		ScanInterval:                     getEnv("SCAN_INTERVAL", ""),
		ScanTables:                       getEnv("SCAN_TABLES", ""),
		ScanTableTimeout:                 getEnvDuration("SCAN_TABLE_TIMEOUT", 30*time.Minute),
		ScanMaxConcurrent:                getEnvInt("SCAN_MAX_CONCURRENCY", 6),
		ScanMinConcurrent:                getEnvInt("SCAN_MIN_CONCURRENCY", 2),
		ScanAdaptiveConcurrency:          getEnvBool("SCAN_ADAPTIVE_CONCURRENCY", true),
		ScanRetryAttempts:                getEnvInt("SCAN_RETRY_ATTEMPTS", 3),
		ScanRetryBackoff:                 getEnvDuration("SCAN_RETRY_BACKOFF", 2*time.Second),
		ScanRetryMaxBackoff:              getEnvDuration("SCAN_RETRY_MAX_BACKOFF", 30*time.Second),
		JobQueueURL:                      getEnv("JOB_QUEUE_URL", ""),
		JobTableName:                     getEnv("JOB_TABLE_NAME", ""),
		JobRegion:                        getEnv("JOB_REGION", getEnv("AWS_REGION", "")),
		JobWorkerConcurrency:             getEnvInt("JOB_WORKER_CONCURRENCY", 4),
		JobVisibilityTimeout:             getEnvDuration("JOB_VISIBILITY_TIMEOUT", 30*time.Second),
		JobPollWait:                      getEnvDuration("JOB_POLL_WAIT", 10*time.Second),
		JobMaxAttempts:                   getEnvInt("JOB_MAX_ATTEMPTS", 3),
		RateLimitEnabled:                 getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests:                getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:                  getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
		APIAuthEnabled:                   apiAuthEnabled,
		APIKeys:                          apiKeys,
		RBACStateFile:                    getEnv("RBAC_STATE_FILE", ""),
	}
}

// New creates and wires up the entire application
func New(ctx context.Context) (*App, error) {
	cfg := LoadConfig()
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

	// Phase 1: Snowflake + policies (everything else depends on these)
	if err := app.initSnowflake(ctx); err != nil {
		logger.Warn("snowflake initialization failed", "error", err)
	}
	if err := app.initPolicy(); err != nil {
		return nil, err
	}

	// Phase 2a: independent services in parallel (no cross-dependencies)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { app.initCache(); return nil })
	g.Go(func() error { app.initTicketing(); return nil })
	g.Go(func() error { app.initIdentity(); return nil })
	g.Go(func() error { app.initAttackPath(); return nil })
	g.Go(func() error { app.initWebhooks(); return nil })
	g.Go(func() error { app.initNotifications(); return nil })
	g.Go(func() error { app.initRBAC(); return nil })
	g.Go(func() error { app.initCompliance(); return nil })
	g.Go(func() error { app.initHealth(); return nil })
	g.Go(func() error { app.initLineage(); return nil })
	g.Go(func() error { app.initRuntime(); return nil })
	g.Go(func() error { app.initFindings(); return nil })
	g.Go(func() error { app.initProviders(gctx); return nil })
	g.Go(func() error { app.initScheduler(gctx); return nil })
	g.Go(func() error { app.initRepositories(); return nil })
	g.Go(func() error { app.initSnowflakeFindings(gctx); return nil })
	g.Go(func() error { app.initScanWatermarks(gctx); return nil })
	g.Go(func() error { app.initThreatIntel(gctx); return nil })
	g.Go(func() error { app.initAvailableTables(gctx); return nil })

	_ = g.Wait()

	// Phase 2b: services that depend on Phase 2a outputs
	// initRemediation reads Ticketing, Notifications, Findings
	// initAgents reads Findings
	g2, _ := errgroup.WithContext(ctx)
	g2.Go(func() error { app.initRemediation(); return nil })
	g2.Go(func() error { app.initAgents(); return nil })
	_ = g2.Wait()

	// Phase 3: depends on findings store being ready
	app.initScanner()

	// Phase 4: depends on AvailableTables being populated
	app.initSecurityGraph(ctx)
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

	return app, nil
}

func (a *App) initSnowflake(ctx context.Context) error {
	// Require key-pair auth
	if a.Config.SnowflakePrivateKey == "" || a.Config.SnowflakeAccount == "" || a.Config.SnowflakeUser == "" {
		return fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
	}

	client, err := snowflake.NewClient(snowflake.ClientConfig{
		Account:    a.Config.SnowflakeAccount,
		User:       a.Config.SnowflakeUser,
		PrivateKey: a.Config.SnowflakePrivateKey,
		Database:   a.Config.SnowflakeDatabase,
		Schema:     a.Config.SnowflakeSchema,
		Warehouse:  a.Config.SnowflakeWarehouse,
		Role:       a.Config.SnowflakeRole,
	})
	if err != nil {
		return err
	}

	if err := client.Ping(ctx); err != nil {
		return err
	}

	a.Snowflake = client
	return nil
}

func (a *App) initPolicy() error {
	a.Policy = policy.NewEngine()
	if err := a.Policy.LoadPolicies(a.Config.PoliciesPath); err != nil {
		explicitOnly, explicitErr := policy.ExplicitMappingsOnlyFromEnv()
		if explicitErr != nil {
			return fmt.Errorf("invalid %s: %w", "CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", explicitErr)
		}
		if explicitOnly {
			return fmt.Errorf("policy initialization failed in explicit-mappings-only mode: %w", err)
		}
		a.Logger.Warn("failed to load policies", "error", err, "path", a.Config.PoliciesPath)
		return nil
	}
	return nil
}

func (a *App) initFindings() {
	// Use SQLite persistence when Snowflake is not available
	// This prevents data loss on restart in dev/test environments
	if a.Snowflake == nil {
		dbPath := filepath.Join(findings.DefaultFilePath(), "cerebro.db")
		if path := os.Getenv("CEREBRO_DB_PATH"); path != "" {
			dbPath = path
		}

		store, err := findings.NewSQLiteStore(dbPath)
		if err != nil {
			a.Logger.Warn("failed to initialize sqlite findings store, falling back to in-memory", "error", err)
			a.Findings = findings.NewStore()
			return
		}
		a.Findings = store
		a.Logger.Info("using sqlite findings store", "path", dbPath)
		return
	}
	// When Snowflake is available, create SnowflakeStore as primary
	// This will be loaded from Snowflake in initSnowflakeFindings
	snowflakeStore := findings.NewSnowflakeStore(
		a.Snowflake.DB(),
		a.Config.SnowflakeDatabase,
		a.Config.SnowflakeSchema,
	)
	a.Findings = snowflakeStore
	a.SnowflakeFindings = snowflakeStore
	a.Logger.Info("using snowflake findings store")
}

func (a *App) initScanner() {
	a.Scanner = scanner.NewScanner(a.Policy, scanner.ScanConfig{
		Workers:   10,
		BatchSize: 100,
	}, a.Logger)
	if a.Cache != nil {
		a.Scanner.SetCache(a.Cache)
	}
}

func (a *App) initCache() {
	a.Cache = cache.NewPolicyCache(10000, 0) // No TTL for policy cache
}

func (a *App) initAgents() {
	a.Agents = agents.NewAgentRegistry()

	// Initialize SCM client
	scmClient := scm.NewConfiguredClient(a.Config.GitHubToken, a.Config.GitLabToken, a.Config.GitLabBaseURL)

	// Create security tools for agents
	tools := agents.NewSecurityTools(a.Snowflake, a.Findings, a.Policy, scmClient)

	// Register Anthropic-based agent if configured
	if a.Config.AnthropicAPIKey != "" {
		provider := agentproviders.NewAnthropicProvider(agentproviders.AnthropicConfig{
			APIKey: a.Config.AnthropicAPIKey,
		})
		a.Agents.RegisterAgent(&agents.Agent{
			ID:          "security-analyst",
			Name:        "Security Analyst",
			Description: "AI-powered security analyst for investigating findings and incidents",
			Provider:    provider,
			Tools:       tools.GetTools(),
			Memory:      agents.NewMemory(100),
		})
	}

	// Register OpenAI-based agent if configured
	if a.Config.OpenAIAPIKey != "" {
		provider := agentproviders.NewOpenAIProvider(agentproviders.OpenAIConfig{
			APIKey: a.Config.OpenAIAPIKey,
		})
		a.Agents.RegisterAgent(&agents.Agent{
			ID:          "incident-responder",
			Name:        "Incident Responder",
			Description: "AI-powered incident responder for triage and remediation",
			Provider:    provider,
			Tools:       tools.GetTools(),
			Memory:      agents.NewMemory(100),
		})
	}
}

func (a *App) initTicketing() {
	a.Ticketing = ticketing.NewService()

	// Register Jira if configured
	if a.Config.JiraBaseURL != "" && a.Config.JiraAPIToken != "" {
		jira := ticketing.NewJiraProvider(ticketing.JiraConfig{
			BaseURL:  a.Config.JiraBaseURL,
			Email:    a.Config.JiraEmail,
			APIToken: a.Config.JiraAPIToken,
			Project:  a.Config.JiraProject,
		})
		a.Ticketing.RegisterProvider(jira)
	}

	// Register Linear if configured
	if a.Config.LinearAPIKey != "" {
		linear := ticketing.NewLinearProvider(ticketing.LinearConfig{
			APIKey: a.Config.LinearAPIKey,
			TeamID: a.Config.LinearTeamID,
		})
		a.Ticketing.RegisterProvider(linear)
	}
}

func (a *App) initIdentity() {
	a.Identity = identity.NewService()
}

func (a *App) initAttackPath() {
	a.AttackPath = attackpath.NewGraph()
}

func (a *App) initProviders(ctx context.Context) {
	a.Providers = providers.NewRegistry()

	// Helper to configure and register providers with error logging
	registerProvider := func(name string, p providers.Provider, config map[string]interface{}) {
		if setter, ok := p.(interface{ SetSnowflakeClient(*snowflake.Client) }); ok {
			setter.SetSnowflakeClient(a.Snowflake)
		}
		if err := p.Configure(ctx, config); err != nil {
			a.Logger.Warn("provider configuration failed, skipping registration",
				"provider", name,
				"error", err)
			return
		}
		a.Providers.Register(p)
		a.Logger.Info("provider registered", "provider", name)
	}

	firstNonEmpty := func(values ...string) string {
		for _, value := range values {
			if value != "" {
				return value
			}
		}
		return ""
	}

	// Register CrowdStrike if configured
	if a.Config.CrowdStrikeClientID != "" {
		registerProvider("crowdstrike", providers.NewCrowdStrikeProvider(), map[string]interface{}{
			"client_id":     a.Config.CrowdStrikeClientID,
			"client_secret": a.Config.CrowdStrikeClientSecret,
		})
	}

	// Register Okta if configured
	if a.Config.OktaDomain != "" {
		registerProvider("okta", providers.NewOktaProvider(), map[string]interface{}{
			"domain":    a.Config.OktaDomain,
			"api_token": a.Config.OktaAPIToken,
		})
	}

	// Register Entra ID if configured
	if a.Config.EntraTenantID != "" && a.Config.EntraClientID != "" && a.Config.EntraClientSecret != "" {
		registerProvider("entra_id", providers.NewEntraIDProvider(), map[string]interface{}{
			"tenant_id":     a.Config.EntraTenantID,
			"client_id":     a.Config.EntraClientID,
			"client_secret": a.Config.EntraClientSecret,
		})
	}

	// Register Azure if configured
	if a.Config.AzureTenantID != "" && a.Config.AzureClientID != "" {
		registerProvider("azure", providers.NewAzureProvider(), map[string]interface{}{
			"tenant_id":       a.Config.AzureTenantID,
			"client_id":       a.Config.AzureClientID,
			"client_secret":   a.Config.AzureClientSecret,
			"subscription_id": a.Config.AzureSubscriptionID,
		})
	}

	// Register Snyk if configured
	if a.Config.SnykAPIToken != "" {
		registerProvider("snyk", providers.NewSnykProvider(), map[string]interface{}{
			"api_token": a.Config.SnykAPIToken,
			"org_id":    a.Config.SnykOrgID,
		})
	}

	// Register Datadog if configured
	if a.Config.DatadogAPIKey != "" {
		registerProvider("datadog", providers.NewDatadogProvider(), map[string]interface{}{
			"api_key": a.Config.DatadogAPIKey,
			"app_key": a.Config.DatadogAppKey,
			"site":    a.Config.DatadogSite,
		})
	}

	// Register GitHub if configured
	if a.Config.GitHubToken != "" && a.Config.GitHubOrg != "" {
		registerProvider("github", providers.NewGitHubProvider(), map[string]interface{}{
			"token": a.Config.GitHubToken,
			"org":   a.Config.GitHubOrg,
		})
	}

	// Register Google Workspace if configured
	if a.Config.GoogleWorkspaceCredentialsJSON != "" {
		registerProvider("google_workspace", providers.NewGoogleWorkspaceProvider(), map[string]interface{}{
			"domain":             a.Config.GoogleWorkspaceDomain,
			"admin_email":        a.Config.GoogleWorkspaceAdminEmail,
			"impersonator_email": a.Config.GoogleWorkspaceImpersonatorEmail,
			"credentials_json":   a.Config.GoogleWorkspaceCredentialsJSON,
		})
	}

	// Register Tailscale if configured
	if a.Config.TailscaleAPIKey != "" && a.Config.TailscaleTailnet != "" {
		registerProvider("tailscale", providers.NewTailscaleProvider(), map[string]interface{}{
			"api_key": a.Config.TailscaleAPIKey,
			"tailnet": a.Config.TailscaleTailnet,
		})
	}

	// Register SentinelOne if configured
	if a.Config.SentinelOneAPIToken != "" {
		registerProvider("sentinelone", providers.NewSentinelOneProvider(), map[string]interface{}{
			"api_token": a.Config.SentinelOneAPIToken,
			"base_url":  a.Config.SentinelOneBaseURL,
		})
	}

	// Register Tenable if configured
	if a.Config.TenableAccessKey != "" {
		registerProvider("tenable", providers.NewTenableProvider(), map[string]interface{}{
			"access_key": a.Config.TenableAccessKey,
			"secret_key": a.Config.TenableSecretKey,
		})
	}

	// Register Qualys if configured
	if a.Config.QualysUsername != "" && a.Config.QualysPassword != "" {
		registerProvider("qualys", providers.NewQualysProvider(), map[string]interface{}{
			"username": a.Config.QualysUsername,
			"password": a.Config.QualysPassword,
			"platform": a.Config.QualysPlatform,
		})
	}

	// Register GitLab if configured
	if a.Config.GitLabToken != "" {
		registerProvider("gitlab", providers.NewGitLabProvider(), map[string]interface{}{
			"token":    a.Config.GitLabToken,
			"base_url": a.Config.GitLabBaseURL,
		})
	}

	// Register Cloudflare if configured
	if a.Config.CloudflareAPIToken != "" {
		registerProvider("cloudflare", providers.NewCloudflareProvider(), map[string]interface{}{
			"api_token": a.Config.CloudflareAPIToken,
		})
	}

	// Register Salesforce if configured
	if a.Config.SalesforceInstanceURL != "" && a.Config.SalesforceClientID != "" && a.Config.SalesforceClientSecret != "" && a.Config.SalesforceUsername != "" && a.Config.SalesforcePassword != "" {
		registerProvider("salesforce", providers.NewSalesforceProvider(), map[string]interface{}{
			"instance_url":   a.Config.SalesforceInstanceURL,
			"client_id":      a.Config.SalesforceClientID,
			"client_secret":  a.Config.SalesforceClientSecret,
			"username":       a.Config.SalesforceUsername,
			"password":       a.Config.SalesforcePassword,
			"security_token": a.Config.SalesforceSecurityToken,
		})
	}

	// Register Vault if configured
	if a.Config.VaultAddress != "" && a.Config.VaultToken != "" {
		registerProvider("vault", providers.NewVaultProvider(), map[string]interface{}{
			"address":   a.Config.VaultAddress,
			"token":     a.Config.VaultToken,
			"namespace": a.Config.VaultNamespace,
		})
	}

	// Register Slack provider if configured
	if a.Config.SlackAPIToken != "" {
		registerProvider("slack", providers.NewSlackProvider(), map[string]interface{}{
			"token": a.Config.SlackAPIToken,
		})
	}

	// Register Rippling if configured
	if a.Config.RipplingAPIToken != "" {
		registerProvider("rippling", providers.NewRipplingProvider(), map[string]interface{}{
			"api_url":   a.Config.RipplingAPIURL,
			"api_token": a.Config.RipplingAPIToken,
		})
	}

	// Register Jamf if configured
	if a.Config.JamfBaseURL != "" && a.Config.JamfClientID != "" && a.Config.JamfClientSecret != "" {
		registerProvider("jamf", providers.NewJamfProvider(), map[string]interface{}{
			"base_url":      a.Config.JamfBaseURL,
			"client_id":     a.Config.JamfClientID,
			"client_secret": a.Config.JamfClientSecret,
		})
	}

	// Register Intune if configured (falls back to Entra credentials when dedicated Intune vars are unset)
	intuneTenantID := firstNonEmpty(a.Config.IntuneTenantID, a.Config.EntraTenantID)
	intuneClientID := firstNonEmpty(a.Config.IntuneClientID, a.Config.EntraClientID)
	intuneClientSecret := firstNonEmpty(a.Config.IntuneClientSecret, a.Config.EntraClientSecret)
	if intuneTenantID != "" && intuneClientID != "" && intuneClientSecret != "" {
		registerProvider("intune", providers.NewIntuneProvider(), map[string]interface{}{
			"tenant_id":     intuneTenantID,
			"client_id":     intuneClientID,
			"client_secret": intuneClientSecret,
		})
	}

	// Register Kandji if configured
	if a.Config.KandjiAPIToken != "" {
		registerProvider("kandji", providers.NewKandjiProvider(), map[string]interface{}{
			"api_url":   a.Config.KandjiAPIURL,
			"api_token": a.Config.KandjiAPIToken,
		})
	}

	// Register CloudTrail if explicitly configured
	if a.Config.CloudTrailRegion != "" || a.Config.CloudTrailTrailARN != "" {
		cloudTrailConfig := map[string]interface{}{}
		if a.Config.CloudTrailRegion != "" {
			cloudTrailConfig["region"] = a.Config.CloudTrailRegion
		}
		if a.Config.CloudTrailTrailARN != "" {
			cloudTrailConfig["trail_arn"] = a.Config.CloudTrailTrailARN
		}
		if a.Config.CloudTrailLookbackDays > 0 {
			cloudTrailConfig["lookback_days"] = a.Config.CloudTrailLookbackDays
		}
		registerProvider("cloudtrail", providers.NewCloudTrailProvider(), cloudTrailConfig)
	}
}

func (a *App) initWebhooks() {
	a.Webhooks = webhooks.NewService()
	if len(a.Config.WebhookURLs) == 0 {
		return
	}

	for _, webhookURL := range a.Config.WebhookURLs {
		webhook, err := a.Webhooks.RegisterWebhook(webhookURL, webhooks.DefaultEventTypes(), "")
		if err != nil {
			a.Logger.Error("failed to register webhook", "url", webhookURL, "error", err)
			continue
		}
		a.Logger.Info("registered webhook", "id", webhook.ID, "url", webhook.URL)
	}
}

func (a *App) initNotifications() {
	a.Notifications = notifications.NewManager()

	if a.Config.SlackWebhookURL != "" {
		slack, err := notifications.NewSlackNotifier(notifications.SlackConfig{
			WebhookURL: a.Config.SlackWebhookURL,
		})
		if err != nil {
			a.Logger.Error("failed to configure slack notifications", "error", err)
		} else {
			a.Notifications.AddNotifier(slack)
			a.Logger.Info("slack notifications enabled")
		}
	}

	if a.Config.PagerDutyKey != "" {
		pd, err := notifications.NewPagerDutyNotifier(notifications.PagerDutyConfig{
			RoutingKey: a.Config.PagerDutyKey,
		})
		if err != nil {
			a.Logger.Error("failed to configure pagerduty notifications", "error", err)
		} else {
			a.Notifications.AddNotifier(pd)
			a.Logger.Info("pagerduty notifications enabled")
		}
	}

	for _, webhookURL := range a.Config.WebhookURLs {
		if err := webhooks.ValidateWebhookURL(webhookURL); err != nil {
			a.Logger.Error("invalid webhook URL", "url", webhookURL, "error", err)
			continue
		}
		webhook, err := notifications.NewWebhookNotifier(notifications.WebhookConfig{URL: webhookURL})
		if err != nil {
			a.Logger.Error("failed to configure webhook notifications", "error", err)
			continue
		}
		a.Notifications.AddNotifier(webhook)
		a.Logger.Info("webhook notifications enabled", "url", webhookURL)
	}
}

func (a *App) initScheduler(_ context.Context) {
	a.Scheduler = scheduler.NewScheduler(a.Logger)

	// Add scan job if interval configured
	if a.Config.ScanInterval != "" {
		interval, err := parseDuration(a.Config.ScanInterval)
		if err != nil {
			a.Logger.Warn("invalid scan interval", "value", a.Config.ScanInterval, "error", err)
			return
		}

		a.Scheduler.AddJob("policy-scan", interval, func(ctx context.Context) error {
			tables := a.resolveScanTables(ctx)
			if len(tables) == 0 {
				a.Logger.Info("no tables available for scheduled scan")
				return nil
			}
			return a.runScheduledScan(ctx, tables)
		})

		if a.Config.ScanTables != "" {
			a.Logger.Info("scheduled scanning enabled", "interval", interval, "tables", splitTables(a.Config.ScanTables))
		} else {
			a.Logger.Info("scheduled scanning enabled", "interval", interval, "table_source", "available_tables")
		}
	}

	// Add graph rebuild job - rebuild hourly by default
	graphInterval := time.Hour
	if envInterval := getEnv("GRAPH_REBUILD_INTERVAL", ""); envInterval != "" {
		if parsed, err := parseDuration(envInterval); err == nil {
			graphInterval = parsed
		}
	}

	a.Scheduler.AddJob("graph-rebuild", graphInterval, func(ctx context.Context) error {
		if a.SecurityGraphBuilder == nil {
			return nil
		}
		if err := a.SecurityGraphBuilder.Build(ctx); err != nil {
			return err
		}
		a.SecurityGraph = a.SecurityGraphBuilder.Graph()
		meta := a.SecurityGraph.Metadata()
		a.Logger.Info("security graph rebuilt",
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", meta.BuildDuration,
		)
		return nil
	})
	a.Logger.Info("scheduled graph rebuild enabled", "interval", graphInterval)
}

func (a *App) runScheduledScan(ctx context.Context, tables []string) error {
	if a.Snowflake == nil {
		return fmt.Errorf("snowflake not configured")
	}

	scanStart := time.Now()

	tuning := a.ScanTuning()
	var tableProfiles []scanner.TableScanProfile
	var totalScanned int64
	var totalViolations int64
	var relationshipCount int
	var graphToxicCount int
	var graphPaths int
	const batchSize = 1000
	const maxWatermarkAge = 7 * 24 * time.Hour

	for _, table := range tables {
		tableProfile := scanner.TableScanProfile{Table: table}
		tableStart := time.Now()
		tableCtx := ctx
		cancel := func() {}
		if tuning.TableTimeout > 0 {
			tableCtx, cancel = context.WithTimeout(ctx, tuning.TableTimeout)
		}

		// Build filter with incremental scanning support
		columns := a.ScanColumnsForTable(tableCtx, table)
		filter := snowflake.AssetFilter{Limit: batchSize, Columns: columns}
		var cursorTime time.Time
		var cursorID string
		useCursorPaging := false

		// Use watermarks for incremental scanning
		if a.ScanWatermarks != nil {
			if !a.ScanWatermarks.ShouldFullScan(table, maxWatermarkAge) {
				if wm := a.ScanWatermarks.GetWatermark(table); wm != nil {
					filter.Since = wm.LastScanTime
					filter.SinceID = wm.LastScanID
					a.Logger.Debug("incremental scan", "table", table, "since", wm.LastScanTime)
					useCursorPaging = true
				}
			}
		}

		// Paginate through all assets
		tableScanned := int64(0)
		tableViolations := int64(0)
		offset := 0
		for tableCtx.Err() == nil {
			if !useCursorPaging {
				filter.Offset = offset
			}
			assets, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]map[string]interface{}, error) {
				return a.Snowflake.GetAssets(tableCtx, table, filter)
			})
			if attempts > 1 {
				tableProfile.RetryAttempts += attempts - 1
			}
			if err != nil {
				tableProfile.FetchErrors++
				a.Logger.Warn("failed to fetch assets", "table", table, "offset", offset, "error", err)
				break
			}

			if len(assets) == 0 {
				break
			}

			result := a.Scanner.ScanAssets(tableCtx, assets)
			tableProfile.Batches++
			tableProfile.CacheSkipped += result.Skipped
			tableProfile.ScanErrors += len(result.Errors)
			totalScanned += result.Scanned
			totalViolations += result.Violations
			tableScanned += result.Scanned
			tableViolations += result.Violations

			batchTime, batchID := scanner.ExtractScanCursor(assets)
			if scanner.IsCursorAfter(batchTime, batchID, cursorTime, cursorID) {
				cursorTime = batchTime
				cursorID = batchID
			}

			if useCursorPaging {
				if batchTime.IsZero() {
					break
				}
				filter.Since = batchTime
				filter.SinceID = batchID
			} else {
				offset += len(assets)
			}

			// Persist findings
			for _, f := range result.Findings {
				finding := a.Findings.Upsert(tableCtx, f)

				// Send notification for new critical/high findings
				if finding.FirstSeen.Equal(finding.LastSeen) && (f.Severity == "critical" || f.Severity == "high") {
					if err := a.Notifications.Send(tableCtx, notifications.Event{
						Type:     notifications.EventFindingCreated,
						Severity: f.Severity,
						Title:    fmt.Sprintf("New %s Finding: %s", f.Severity, f.PolicyName),
						Message:  f.Description,
						Data: map[string]interface{}{
							"finding_id": f.ID,
							"policy_id":  f.PolicyID,
							"resource":   f.Resource,
						},
					}); err != nil {
						a.Logger.Warn("failed to send finding notification", "finding_id", f.ID, "error", err)
					}
				}
			}

			// If we got fewer than batchSize, we're done with this table
			if len(assets) < batchSize {
				break
			}
		}

		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			tableProfile.TimedOut = true
			a.Logger.Warn("table scan timed out", "table", table, "timeout", tuning.TableTimeout)
		}
		tableProfile.Scanned = tableScanned
		tableProfile.Violations = tableViolations
		tableProfile.Duration = time.Since(tableStart)
		cancel()
		tableProfiles = append(tableProfiles, tableProfile)

		// Update watermark after successful scan
		if a.ScanWatermarks != nil && tableScanned > 0 {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			a.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, tableScanned)
		}
	}

	scanDuration := time.Since(scanStart)
	profileSummary := scanner.SummarizeTableProfiles(tableProfiles, scanDuration)
	slowTables := scanner.FilterSlowTables(tableProfiles, tuning.ProfileSlowThreshold)
	if len(tableProfiles) > 0 {
		sorted := scanner.SortTableProfilesByDuration(tableProfiles)
		maxRows := 5
		if len(sorted) < maxRows {
			maxRows = len(sorted)
		}
		entries := make([]map[string]interface{}, 0, maxRows)
		for i := 0; i < maxRows; i++ {
			profile := sorted[i]
			entries = append(entries, map[string]interface{}{
				"table":          profile.Table,
				"duration":       profile.Duration.String(),
				"scanned":        profile.Scanned,
				"violations":     profile.Violations,
				"retry_attempts": profile.RetryAttempts,
				"fetch_errors":   profile.FetchErrors,
				"timed_out":      profile.TimedOut,
			})
		}
		a.Logger.Info("scan profiling",
			"total_scanned", profileSummary.TotalScanned,
			"total_violations", profileSummary.TotalViolations,
			"slow_threshold", tuning.ProfileSlowThreshold,
			"slow_tables", len(slowTables),
			"top_tables", entries,
		)
	}

	sqlToxicRiskSets := make(map[string][]map[string]bool)
	if a.Snowflake != nil {
		toxicFindings, err := scanner.DetectRelationshipToxicCombinations(ctx, a.Snowflake)
		if err != nil {
			a.Logger.Warn("relationship toxic combo scan failed", "error", err)
		} else {
			relationshipCount = len(toxicFindings)
			for _, f := range toxicFindings {
				if rid := scanner.NormalizeResourceID(f.ResourceID); rid != "" {
					if risks := scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(f.Risks)); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				if a.Findings != nil && f.PolicyID != "" && f.ResourceID != "" {
					a.Findings.Upsert(ctx, f.ToPolicyFinding())
				}
			}
			totalViolations += int64(relationshipCount)
		}
	}

	if a.SecurityGraph != nil {
		graphCtx := ctx
		cancel := func() {}
		if tuning.GraphWaitTimeout > 0 {
			graphCtx, cancel = context.WithTimeout(ctx, tuning.GraphWaitTimeout)
		}
		graphReady := a.WaitForGraph(graphCtx)
		cancel()
		if graphReady {
			graphResult := a.Scanner.AnalyzeGraph(ctx, a.SecurityGraph)
			if graphResult != nil {
				graphPaths = graphResult.AttackPathStats.TotalPaths
				for _, f := range graphResult.ToxicCombinations {
					resourceID := scanner.NormalizeResourceID(f.ResourceID)
					graphRiskSet := scanner.CanonicalizeRiskCategories(f.RiskCategories)
					if scanner.ShouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
						continue
					}
					a.Findings.Upsert(ctx, f)
					graphToxicCount++
				}
			}
		}
	}
	if graphToxicCount > 0 {
		totalViolations += int64(graphToxicCount)
	}
	if relationshipCount > 0 || graphToxicCount > 0 {
		a.Logger.Info("toxic combination analysis complete",
			"relationship_count", relationshipCount,
			"graph_count", graphToxicCount,
			"attack_paths", graphPaths,
		)
	}

	// Persist watermarks
	if a.ScanWatermarks != nil {
		if err := a.ScanWatermarks.PersistWatermarksWithRetry(ctx, scanner.DefaultWatermarkPersistOptions()); err != nil {
			a.Logger.Warn("failed to persist scan watermarks", "error", err)
		}
	}

	// Sync to Snowflake if available
	if a.SnowflakeFindings != nil {
		if err := a.SnowflakeFindings.Sync(ctx); err != nil {
			a.Logger.Warn("failed to sync findings to snowflake", "error", err)
		}
	}

	// Send scan completed notification
	if err := a.Notifications.Send(ctx, notifications.Event{
		Type:    notifications.EventScanCompleted,
		Title:   "Scheduled Scan Completed",
		Message: fmt.Sprintf("Scanned %d assets, found %d violations", totalScanned, totalViolations),
		Data: map[string]interface{}{
			"scanned":                  totalScanned,
			"violations":               totalViolations,
			"tables":                   tables,
			"relationship_toxic_count": relationshipCount,
			"graph_toxic_count":        graphToxicCount,
			"graph_attack_paths":       graphPaths,
			"scan_duration":            scanDuration.String(),
		},
	}); err != nil {
		a.Logger.Warn("failed to send scan completed notification", "error", err)
	}

	// Emit webhook
	if err := a.Webhooks.EmitScanCompleted(ctx, totalScanned, totalViolations, 0); err != nil {
		a.Logger.Warn("failed to emit scan completed webhook", "error", err)
	}

	return nil
}

func (a *App) initRepositories() {
	if a.Snowflake == nil {
		return
	}
	a.FindingsRepo = snowflake.NewFindingRepository(a.Snowflake)
	a.TicketsRepo = snowflake.NewTicketRepository(a.Snowflake)
	a.AuditRepo = snowflake.NewAuditRepository(a.Snowflake)
}

func (a *App) initSnowflakeFindings(ctx context.Context) {
	if a.Snowflake == nil || a.SnowflakeFindings == nil {
		return
	}

	// Load existing findings from Snowflake
	// SnowflakeStore is already created in initFindings when Snowflake is available
	if err := a.SnowflakeFindings.Load(ctx); err != nil {
		a.Logger.Warn("failed to load findings from snowflake", "error", err)
	} else {
		a.Logger.Info("loaded findings from snowflake", "count", a.SnowflakeFindings.Stats().Total)
	}
}

func (a *App) initScanWatermarks(ctx context.Context) {
	if a.Snowflake != nil {
		a.ScanWatermarks = scanner.NewWatermarkStore(a.Snowflake.DB())
		if err := a.ScanWatermarks.LoadWatermarks(ctx); err != nil {
			a.Logger.Warn("failed to load scan watermarks", "error", err)
		}
	} else {
		a.ScanWatermarks = scanner.NewWatermarkStore(nil)
	}
	a.Logger.Info("scan watermarks initialized")
}

// initAvailableTables caches the Snowflake table list for reuse by graph builder and policy validation.
func (a *App) initAvailableTables(ctx context.Context) {
	if a.Snowflake == nil {
		return
	}
	tables, err := a.Snowflake.ListAvailableTables(ctx)
	if err != nil {
		a.Logger.Warn("failed to list available tables", "error", err)
		return
	}
	a.AvailableTables = tables
}

// validatePolicyCoverage checks that required tables exist for loaded policies
func (a *App) validatePolicyCoverage(_ context.Context) error {
	if a.Snowflake == nil {
		a.Logger.Warn("skipping policy coverage validation - Snowflake not configured")
		return nil
	}

	if a.AvailableTables == nil {
		a.Logger.Warn("skipping policy coverage validation - table list not available")
		return nil
	}

	report := a.Policy.CoverageReport(a.AvailableTables)
	orphanTables := policy.GlobalMappingRegistry().OrphanNativeTables(a.AvailableTables)
	if report.TotalPolicies == 0 {
		if len(orphanTables) == 0 {
			return nil
		}
	}

	if len(report.Gaps) == 0 && report.UnknownResourcePolicies == 0 {
		a.Logger.Info("all policies have required tables available",
			"coverage_percent", fmt.Sprintf("%.1f%%", report.CoveragePercent))
	} else {
		missingTables := topMissingTables(report.MissingTables, 5)
		a.Logger.Warn("policy coverage incomplete",
			"total_policies", report.TotalPolicies,
			"covered_policies", report.CoveredPolicies,
			"uncovered_policies", report.UncoveredPolicies,
			"unknown_resource_policies", report.UnknownResourcePolicies,
			"coverage_percent", fmt.Sprintf("%.1f%%", report.CoveragePercent),
			"known_coverage_percent", fmt.Sprintf("%.1f%%", report.KnownCoveragePercent),
			"missing_tables", missingTables,
			"missing_by_provider", report.MissingByProvider,
		)
	}

	if len(orphanTables) > 0 {
		a.Logger.Warn("detected orphan native tables without policy mappings",
			"orphan_table_count", len(orphanTables),
			"orphan_tables_sample", topStrings(orphanTables, 10),
		)
	}

	threshold, ok, err := policy.CoverageThresholdFromEnv()
	if err != nil {
		a.Logger.Warn("invalid policy coverage threshold", "error", err)
		return nil
	}
	if ok && report.CoveragePercent < threshold {
		return fmt.Errorf("policy coverage %.1f%% below threshold %.1f%%", report.CoveragePercent, threshold)
	}

	orphanThreshold, orphanThresholdSet, err := policy.OrphanTableThresholdFromEnv()
	if err != nil {
		a.Logger.Warn("invalid policy orphan-table threshold", "error", err)
		return nil
	}
	if orphanThresholdSet && len(orphanTables) > orphanThreshold {
		return fmt.Errorf("orphan native tables %d exceed threshold %d", len(orphanTables), orphanThreshold)
	}
	return nil
}

func topMissingTables(counts map[string]int, limit int) []string {
	if limit <= 0 || len(counts) == 0 {
		return nil
	}
	type entry struct {
		table string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for table, count := range counts {
		entries = append(entries, entry{table: table, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].table < entries[j].table
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, fmt.Sprintf("%s (%d)", entry.table, entry.count))
	}
	return result
}

func topStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

// Close cleanly shuts down all services
func (a *App) Close() error {
	var errs []error

	// Sync findings store to persist any pending changes
	if syncer, ok := a.Findings.(interface{ Sync(context.Context) error }); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := syncer.Sync(ctx); err != nil {
			errs = append(errs, fmt.Errorf("findings sync: %w", err))
		}
	}

	if a.graphCancel != nil {
		a.graphCancel()
	}
	if a.graphReady != nil {
		select {
		case <-a.graphReady:
		case <-time.After(5 * time.Second):
		}
	}

	// Close Snowflake connection
	if a.Snowflake != nil {
		if err := a.Snowflake.Close(); err != nil {
			errs = append(errs, fmt.Errorf("snowflake: %w", err))
		}
	}

	// Close findings store if it implements io.Closer (e.g., SQLiteStore)
	if closer, ok := a.Findings.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("findings store: %w", err))
		}
	}

	// Stop scheduler if running
	if a.Scheduler != nil {
		a.Scheduler.Stop()
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func parseAPIKeys(value string) map[string]string {
	keys := make(map[string]string)
	if value == "" {
		return keys
	}

	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 1 {
			parts = strings.SplitN(entry, "=", 2)
		}

		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}

		userID := key
		if len(parts) == 2 {
			userID = strings.TrimSpace(parts[1])
			if userID == "" {
				userID = key
			}
		}
		keys[key] = userID
	}

	return keys
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func splitTables(s string) []string {
	return splitCSV(s)
}

func splitCSV(s string) []string {
	var result []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

// defaultScanTables returns the comprehensive list of tables to scan
func defaultScanTables() []string {
	return nativesync.SupportedTableNames()
}

func (a *App) resolveScanTables(ctx context.Context) []string {
	var tables []string
	if a.Config.ScanTables != "" {
		tables = splitTables(a.Config.ScanTables)
	}

	available := a.AvailableTables
	if a.Snowflake != nil {
		if refreshed, err := a.Snowflake.ListAvailableTables(ctx); err == nil {
			a.AvailableTables = refreshed
			available = refreshed
		} else if ctx.Err() == nil {
			a.Logger.Warn("failed to refresh available tables", "error", err)
		}
	}

	if len(tables) == 0 && len(available) > 0 {
		tables = scannableTablesFromAvailable(available)
	}
	if len(tables) == 0 {
		tables = defaultScanTables()
	}

	filtered, skipped := filterTablesByAvailability(tables, available)
	if len(available) > 0 {
		if skipped > 0 {
			a.Logger.Info("skipped tables not present in snowflake", "skipped", skipped)
		}
		return filtered
	}

	return tables
}

func scannableTablesFromAvailable(available []string) []string {
	if len(available) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(available))
	result := make([]string, 0, len(available))
	for _, table := range available {
		name := strings.ToLower(strings.TrimSpace(table))
		if !isScannableTable(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func isScannableTable(table string) bool {
	if table == "" {
		return false
	}
	if strings.HasPrefix(table, "cerebro_") {
		return false
	}
	if err := snowflake.ValidateTableNameStrict(table); err != nil {
		return false
	}
	return true
}

func filterTablesByAvailability(tables, available []string) ([]string, int) {
	if len(tables) == 0 || len(available) == 0 {
		return tables, 0
	}

	availableSet := make(map[string]struct{}, len(available))
	for _, table := range available {
		availableSet[strings.ToLower(table)] = struct{}{}
	}

	filtered := make([]string, 0, len(tables))
	skipped := 0
	for _, table := range tables {
		if _, ok := availableSet[strings.ToLower(table)]; ok {
			filtered = append(filtered, table)
		} else {
			skipped++
		}
	}

	return filtered, skipped
}

// New service initialization functions

func (a *App) initRBAC() {
	if a.Config.RBACStateFile == "" {
		a.RBAC = auth.NewRBAC()
		a.Logger.Info("rbac service initialized")
		return
	}

	rbac, err := auth.NewRBACWithStateFile(a.Config.RBACStateFile)
	if err != nil {
		a.Logger.Warn("failed to load rbac state file; falling back to in-memory", "error", err, "path", a.Config.RBACStateFile)
		a.RBAC = auth.NewRBAC()
		a.Logger.Info("rbac service initialized")
		return
	}

	a.RBAC = rbac
	a.Logger.Info("rbac service initialized", "state_file", a.Config.RBACStateFile)
}

func (a *App) initThreatIntel(ctx context.Context) {
	a.ThreatIntel = threatintel.NewThreatIntelService()

	// Sync feeds in background
	go func() {
		const (
			syncTimeout  = 2 * time.Minute
			syncMaxAge   = 12 * time.Hour
			syncAttempts = 3
			syncBackoff  = 5 * time.Second
		)
		if !a.ThreatIntel.ShouldSync(syncMaxAge) {
			stats := a.ThreatIntel.Stats()
			a.Logger.Info("threat intel feeds fresh", "last_updated", stats["last_updated"])
			return
		}

		syncCtx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()

		err := a.ThreatIntel.SyncAllWithRetry(syncCtx, threatintel.SyncOptions{
			MaxAge:   syncMaxAge,
			Attempts: syncAttempts,
			Backoff:  syncBackoff,
		})
		if err != nil {
			a.Logger.Warn("failed to sync threat intel feeds", "error", err)
			return
		}
		stats := a.ThreatIntel.Stats()
		a.Logger.Info("threat intel feeds synced", "indicators", stats["total_indicators"])
	}()
}

func (a *App) initCompliance() {
	// Compliance reports are generated on-demand, not stored
	a.Logger.Info("compliance service ready")
}

func (a *App) initHealth() {
	a.Health = health.NewRegistry()

	// Register health checks for all services
	a.Health.Register("snowflake", health.PingCheck("snowflake", func(ctx context.Context) error {
		if a.Snowflake == nil {
			return fmt.Errorf("not configured")
		}
		return a.Snowflake.Ping(ctx)
	}))

	a.Health.Register("policy_engine", health.PingCheck("policy_engine", func(ctx context.Context) error {
		if a.Policy == nil {
			return fmt.Errorf("not initialized")
		}
		if len(a.Policy.ListPolicies()) == 0 {
			return fmt.Errorf("no policies loaded")
		}
		return nil
	}))

	a.Health.Register("findings_store", health.PingCheck("findings_store", func(ctx context.Context) error {
		if a.Findings == nil {
			return fmt.Errorf("not initialized")
		}
		return nil
	}))

	a.Health.Register("sync_data", health.PingCheck("sync_data", func(ctx context.Context) error {
		if a.Snowflake == nil {
			return fmt.Errorf("not configured")
		}
		// Check that at least some tables have data
		tables, err := a.Snowflake.ListAvailableTables(ctx)
		if err != nil {
			return fmt.Errorf("cannot list tables: %w", err)
		}
		if len(tables) == 0 {
			return fmt.Errorf("no synced tables found - sync may be needed")
		}
		return nil
	}))

	a.Logger.Info("health service initialized")
}

func (a *App) initLineage() {
	a.Lineage = lineage.NewLineageMapper()
	a.Logger.Info("lineage mapper initialized")
}

func (a *App) initRemediation() {
	a.Remediation = remediation.NewEngine(a.Logger)
	a.RemediationExecutor = remediation.NewExecutor(a.Remediation, a.Ticketing, a.Notifications, a.Findings)
	a.Logger.Info("remediation engine initialized", "rules", len(a.Remediation.ListRules()))
}

func (a *App) initRuntime() {
	a.RuntimeDetect = runtime.NewDetectionEngine()
	a.RuntimeRespond = runtime.NewResponseEngine()
	a.Logger.Info("runtime detection initialized", "rules", len(a.RuntimeDetect.ListRules()))
	a.Logger.Info("runtime response initialized", "policies", len(a.RuntimeRespond.ListPolicies()))
}

func (a *App) initSecurityGraph(ctx context.Context) {
	a.graphReady = make(chan struct{})

	if a.Snowflake == nil {
		a.Logger.Warn("security graph disabled - snowflake not configured")
		a.graphCancel = nil
		close(a.graphReady)
		return
	}

	source := graph.NewSnowflakeSource(a.Snowflake)
	a.SecurityGraphBuilder = graph.NewBuilder(source, a.Logger)
	a.SecurityGraph = a.SecurityGraphBuilder.Graph()

	graphCtx := ctx
	if graphCtx == nil {
		graphCtx = context.Background()
	}
	graphCtx, cancel := context.WithCancel(graphCtx)
	a.graphCancel = cancel

	// Build initial graph in background
	go func() {
		defer close(a.graphReady)

		if err := a.SecurityGraphBuilder.Build(graphCtx); err != nil {
			a.Logger.Error("failed to build security graph", "error", err)
			return
		}
		meta := a.SecurityGraph.Metadata()
		a.Logger.Info("security graph built",
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", meta.BuildDuration,
		)

		if err := a.Webhooks.EmitWithErrors(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
			"nodes":          meta.NodeCount,
			"edges":          meta.EdgeCount,
			"build_duration": meta.BuildDuration.String(),
		}); err != nil {
			a.Logger.Warn("failed to emit graph rebuilt webhook", "error", err)
		}
	}()
}

// WaitForGraph blocks until the initial graph build completes (or ctx is cancelled).
// Returns true if the graph is ready and has nodes, false otherwise.
func (a *App) WaitForGraph(ctx context.Context) bool {
	if a.graphReady == nil {
		return false
	}
	select {
	case <-a.graphReady:
		return a.SecurityGraph != nil && a.SecurityGraph.NodeCount() > 0
	case <-ctx.Done():
		return false
	}
}

// RebuildSecurityGraph triggers a rebuild of the security graph
func (a *App) RebuildSecurityGraph(ctx context.Context) error {
	if a.SecurityGraphBuilder == nil {
		return fmt.Errorf("security graph not initialized")
	}

	start := time.Now()
	if err := a.SecurityGraphBuilder.Build(ctx); err != nil {
		return err
	}

	meta := a.SecurityGraph.Metadata()
	a.Logger.Info("security graph rebuilt",
		"nodes", meta.NodeCount,
		"edges", meta.EdgeCount,
		"duration", time.Since(start),
	)

	// Emit webhook event
	if err := a.Webhooks.EmitWithErrors(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
		"nodes":          meta.NodeCount,
		"edges":          meta.EdgeCount,
		"build_duration": time.Since(start).String(),
	}); err != nil {
		a.Logger.Warn("failed to emit graph rebuilt webhook", "error", err)
	}

	return nil
}

// normalizePrivateKey cleans up PEM-encoded private key strings that may have
// escaped newlines or extra whitespace from environment variable storage.
func normalizePrivateKey(value string) string {
	if value == "" {
		return value
	}
	if strings.Contains(value, "\\n") {
		value = strings.ReplaceAll(value, "\\n", "\n")
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
