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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	"github.com/writerinternal/cerebro/internal/threatintel"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"
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

	// Webhooks
	WebhookURLs []string

	// Notifications
	SlackWebhookURL    string
	SlackSigningSecret string
	PagerDutyKey       string

	// Scheduler
	ScanInterval string // e.g., "1h", "30m"
	ScanTables   string // comma-separated list of tables to scan

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
}

func LoadConfig() *Config {
	apiKeys := parseAPIKeys(getEnv("API_KEYS", ""))
	apiAuthEnabled := getEnvBool("API_AUTH_ENABLED", len(apiKeys) > 0)

	return &Config{
		Port:                    getEnvInt("API_PORT", 8080),
		LogLevel:                getEnv("LOG_LEVEL", "info"),
		SnowflakeAccount:        getEnv("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:           getEnv("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey:     normalizePrivateKey(getEnv("SNOWFLAKE_PRIVATE_KEY", "")),
		SnowflakeDatabase:       getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:         getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeWarehouse:      getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeRole:           getEnv("SNOWFLAKE_ROLE", ""),
		PoliciesPath:            getEnv("POLICIES_PATH", "policies"),
		AnthropicAPIKey:         getEnv("ANTHROPIC_API_KEY", ""),
		OpenAIAPIKey:            getEnv("OPENAI_API_KEY", ""),
		JiraBaseURL:             getEnv("JIRA_BASE_URL", ""),
		JiraEmail:               getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:            getEnv("JIRA_API_TOKEN", ""),
		JiraProject:             getEnv("JIRA_PROJECT", "SEC"),
		LinearAPIKey:            getEnv("LINEAR_API_KEY", ""),
		LinearTeamID:            getEnv("LINEAR_TEAM_ID", ""),
		CrowdStrikeClientID:     getEnv("CROWDSTRIKE_CLIENT_ID", ""),
		CrowdStrikeClientSecret: getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
		OktaDomain:              getEnv("OKTA_DOMAIN", ""),
		OktaAPIToken:            getEnv("OKTA_API_TOKEN", ""),
		AzureTenantID:           getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:           getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret:       getEnv("AZURE_CLIENT_SECRET", ""),
		AzureSubscriptionID:     getEnv("AZURE_SUBSCRIPTION_ID", ""),
		SnykAPIToken:            getEnv("SNYK_API_TOKEN", ""),
		SnykOrgID:               getEnv("SNYK_ORG_ID", ""),
		DatadogAPIKey:           getEnv("DATADOG_API_KEY", ""),
		DatadogAppKey:           getEnv("DATADOG_APP_KEY", ""),
		DatadogSite:             getEnv("DATADOG_SITE", "datadoghq.com"),
		GitHubToken:             getEnv("GITHUB_TOKEN", ""),
		GitHubOrg:               getEnv("GITHUB_ORG", ""),
		SentinelOneAPIToken:     getEnv("SENTINELONE_API_TOKEN", ""),
		SentinelOneBaseURL:      getEnv("SENTINELONE_BASE_URL", ""),
		TenableAccessKey:        getEnv("TENABLE_ACCESS_KEY", ""),
		TenableSecretKey:        getEnv("TENABLE_SECRET_KEY", ""),
		QualysUsername:          getEnv("QUALYS_USERNAME", ""),
		QualysPassword:          getEnv("QUALYS_PASSWORD", ""),
		QualysPlatform:          getEnv("QUALYS_PLATFORM", "US1"),
		SemgrepAPIToken:         getEnv("SEMGREP_API_TOKEN", ""),
		GitLabToken:             getEnv("GITLAB_TOKEN", ""),
		GitLabBaseURL:           getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
		TerraformCloudToken:     getEnv("TFC_TOKEN", ""),
		SplunkURL:               getEnv("SPLUNK_URL", ""),
		SplunkToken:             getEnv("SPLUNK_TOKEN", ""),
		Auth0Domain:             getEnv("AUTH0_DOMAIN", ""),
		Auth0ClientID:           getEnv("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:       getEnv("AUTH0_CLIENT_SECRET", ""),
		CloudflareAPIToken:      getEnv("CLOUDFLARE_API_TOKEN", ""),
		WebhookURLs:             splitCSV(getEnv("WEBHOOK_URLS", "")),
		SlackWebhookURL:         getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:      getEnv("SLACK_SIGNING_SECRET", ""),
		PagerDutyKey:            getEnv("PAGERDUTY_ROUTING_KEY", ""),
		ScanInterval:            getEnv("SCAN_INTERVAL", ""),
		ScanTables:              getEnv("SCAN_TABLES", ""),
		JobQueueURL:             getEnv("JOB_QUEUE_URL", ""),
		JobTableName:            getEnv("JOB_TABLE_NAME", ""),
		JobRegion:               getEnv("JOB_REGION", getEnv("AWS_REGION", "")),
		JobWorkerConcurrency:    getEnvInt("JOB_WORKER_CONCURRENCY", 4),
		JobVisibilityTimeout:    getEnvDuration("JOB_VISIBILITY_TIMEOUT", 30*time.Second),
		JobPollWait:             getEnvDuration("JOB_POLL_WAIT", 10*time.Second),
		JobMaxAttempts:          getEnvInt("JOB_MAX_ATTEMPTS", 3),
		RateLimitEnabled:        getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests:       getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:         getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
		APIAuthEnabled:          apiAuthEnabled,
		APIKeys:                 apiKeys,
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

	// Initialize core services
	if err := app.initSnowflake(ctx); err != nil {
		logger.Warn("snowflake initialization failed", "error", err)
	}

	app.initPolicy()
	app.initFindings()
	app.initScanner()
	app.initCache()

	// Initialize feature services
	app.initAgents()
	app.initTicketing()
	app.initIdentity()
	app.initAttackPath()
	app.initProviders(ctx)
	app.initWebhooks()
	app.initNotifications()
	app.initScheduler(ctx)
	app.initRepositories()
	app.initSnowflakeFindings(ctx)
	app.initScanWatermarks(ctx)

	// Initialize new services
	app.initRBAC()
	app.initThreatIntel(ctx)
	app.initCompliance()
	app.initHealth()
	app.initLineage()
	app.initRemediation()
	app.initRuntime()
	app.initSecurityGraph(ctx)

	// Validate policy coverage against available tables
	app.validatePolicyCoverage(ctx)

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

func (a *App) initPolicy() {
	a.Policy = policy.NewEngine()
	if err := a.Policy.LoadPolicies(a.Config.PoliciesPath); err != nil {
		a.Logger.Warn("failed to load policies", "error", err, "path", a.Config.PoliciesPath)
	}
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
}

func (a *App) initCache() {
	a.Cache = cache.NewPolicyCache(10000, 0) // No TTL for policy cache
}

func (a *App) initAgents() {
	a.Agents = agents.NewAgentRegistry()

	// Initialize SCM client
	var scmClient scm.Client
	if a.Config.GitHubToken != "" {
		scmClient = scm.NewGitHubClient(a.Config.GitHubToken)
	}

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
		if err := p.Configure(ctx, config); err != nil {
			a.Logger.Warn("provider configuration failed, skipping registration",
				"provider", name,
				"error", err)
			return
		}
		a.Providers.Register(p)
		a.Logger.Info("provider registered", "provider", name)
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

		tables := defaultScanTables()
		if a.Config.ScanTables != "" {
			tables = splitTables(a.Config.ScanTables)
		}

		a.Scheduler.AddJob("policy-scan", interval, func(ctx context.Context) error {
			return a.runScheduledScan(ctx, tables)
		})

		a.Logger.Info("scheduled scanning enabled", "interval", interval, "tables", tables)
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
		return a.RebuildSecurityGraph(ctx)
	})
	a.Logger.Info("scheduled graph rebuild enabled", "interval", graphInterval)
}

func (a *App) runScheduledScan(ctx context.Context, tables []string) error {
	if a.Snowflake == nil {
		return fmt.Errorf("snowflake not configured")
	}

	totalScanned := 0
	totalViolations := 0
	const batchSize = 1000
	const maxWatermarkAge = 7 * 24 * time.Hour

	for _, table := range tables {
		// Build filter with incremental scanning support
		filter := snowflake.AssetFilter{Limit: batchSize}
		var cursorTime time.Time
		var cursorID string

		// Use watermarks for incremental scanning
		if a.ScanWatermarks != nil {
			if !a.ScanWatermarks.ShouldFullScan(table, maxWatermarkAge) {
				if wm := a.ScanWatermarks.GetWatermark(table); wm != nil {
					filter.Since = wm.LastScanTime
					filter.SinceID = wm.LastScanID
					a.Logger.Debug("incremental scan", "table", table, "since", wm.LastScanTime)
				}
			}
		}

		// Paginate through all assets
		tableScanned := int64(0)
		offset := 0
		for {
			filter.Offset = offset
			assets, err := a.Snowflake.GetAssets(ctx, table, filter)
			if err != nil {
				a.Logger.Warn("failed to fetch assets", "table", table, "offset", offset, "error", err)
				break
			}

			if len(assets) == 0 {
				break
			}

			result := a.Scanner.ScanAssets(ctx, assets)
			totalScanned += int(result.Scanned)
			totalViolations += int(result.Violations)
			tableScanned += result.Scanned

			batchTime, batchID := scanner.ExtractScanCursor(assets)
			if scanner.IsCursorAfter(batchTime, batchID, cursorTime, cursorID) {
				cursorTime = batchTime
				cursorID = batchID
			}

			// Persist findings
			for _, f := range result.Findings {
				finding := a.Findings.Upsert(ctx, f)

				// Send notification for new critical/high findings
				if finding.FirstSeen.Equal(finding.LastSeen) && (f.Severity == "critical" || f.Severity == "high") {
					_ = a.Notifications.Send(ctx, notifications.Event{
						Type:     notifications.EventFindingCreated,
						Severity: f.Severity,
						Title:    fmt.Sprintf("New %s Finding: %s", f.Severity, f.PolicyName),
						Message:  f.Description,
						Data: map[string]interface{}{
							"finding_id": f.ID,
							"policy_id":  f.PolicyID,
							"resource":   f.Resource,
						},
					})
				}
			}

			// If we got fewer than batchSize, we're done with this table
			if len(assets) < batchSize {
				break
			}
			offset += batchSize
		}

		// Update watermark after successful scan
		if a.ScanWatermarks != nil && tableScanned > 0 {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			a.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, tableScanned)
		}
	}

	// Persist watermarks
	if a.ScanWatermarks != nil {
		if err := a.ScanWatermarks.PersistWatermarks(ctx); err != nil {
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
	_ = a.Notifications.Send(ctx, notifications.Event{
		Type:    notifications.EventScanCompleted,
		Title:   "Scheduled Scan Completed",
		Message: fmt.Sprintf("Scanned %d assets, found %d violations", totalScanned, totalViolations),
		Data: map[string]interface{}{
			"scanned":    totalScanned,
			"violations": totalViolations,
			"tables":     tables,
		},
	})

	// Emit webhook
	if err := a.Webhooks.EmitScanCompleted(ctx, int64(totalScanned), int64(totalViolations), 0); err != nil {
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
	var db interface{ Query(string) error }
	if a.Snowflake != nil {
		a.ScanWatermarks = scanner.NewWatermarkStore(a.Snowflake.DB())
		// Load existing watermarks
		if err := a.ScanWatermarks.LoadWatermarks(ctx); err != nil {
			a.Logger.Warn("failed to load scan watermarks", "error", err)
		}
	} else {
		a.ScanWatermarks = scanner.NewWatermarkStore(nil)
	}
	_ = db // unused but shows pattern
	a.Logger.Info("scan watermarks initialized")
}

// validatePolicyCoverage checks that required tables exist for loaded policies
func (a *App) validatePolicyCoverage(ctx context.Context) {
	if a.Snowflake == nil {
		a.Logger.Warn("skipping policy coverage validation - Snowflake not configured")
		return
	}

	availableTables, err := a.Snowflake.ListAvailableTables(ctx)
	if err != nil {
		a.Logger.Warn("failed to list available tables for policy validation", "error", err)
		return
	}

	gaps := a.Policy.ValidateTableCoverage(availableTables)
	if len(gaps) == 0 {
		a.Logger.Info("all policies have required tables available")
		return
	}

	// Log warnings for each policy that can't be fully evaluated
	for _, gap := range gaps {
		a.Logger.Warn("policy missing required tables - will silently skip",
			"policy_id", gap.PolicyID,
			"policy_name", gap.PolicyName,
			"resource", gap.Resource,
			"missing_tables", gap.MissingTables,
		)
	}

	totalPolicies := len(a.Policy.ListPolicies())
	coveredPolicies := totalPolicies - len(gaps)
	a.Logger.Warn("policy coverage incomplete",
		"total_policies", totalPolicies,
		"covered_policies", coveredPolicies,
		"uncovered_policies", len(gaps),
		"coverage_percent", fmt.Sprintf("%.1f%%", float64(coveredPolicies)/float64(totalPolicies)*100),
	)
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
	return []string{
		// AWS IAM
		"aws_iam_users",
		"aws_iam_roles",
		"aws_iam_policies",
		"aws_iam_groups",
		// AWS S3
		"aws_s3_buckets",
		// AWS EC2
		"aws_ec2_instances",
		"aws_ec2_security_groups",
		"aws_ec2_vpcs",
		"aws_ec2_subnets",
		"aws_ec2_ebs_volumes",
		"aws_ec2_ebs_snapshots",
		"aws_ec2_amis",
		// AWS RDS
		"aws_rds_db_instances",
		"aws_rds_db_clusters",
		// AWS Lambda
		"aws_lambda_functions",
		// AWS ELB/ALB
		"aws_elbv2_load_balancers",
		"aws_elbv2_target_groups",
		// AWS KMS
		"aws_kms_keys",
		// AWS CloudTrail
		"aws_cloudtrail_trails",
		// AWS CloudWatch
		"aws_cloudwatch_alarms",
		"aws_cloudwatch_log_groups",
		// AWS Config
		"aws_config_configuration_recorders",
		// AWS GuardDuty
		"aws_guardduty_detectors",
		// AWS EKS
		"aws_eks_clusters",
		// AWS ECR
		"aws_ecr_repositories",
		// AWS Secrets Manager
		"aws_secretsmanager_secrets",
		// AWS SNS/SQS
		"aws_sns_topics",
		"aws_sqs_queues",
		// AWS VPC Flow Logs
		"aws_ec2_flow_logs",
		// AWS DynamoDB
		"aws_dynamodb_tables",
		// AWS Redshift
		"aws_redshift_clusters",
		// AWS ElastiCache
		"aws_elasticache_clusters",
		// AWS OpenSearch
		"aws_opensearch_domains",
		// AWS API Gateway
		"aws_apigateway_rest_apis",
		// AWS CloudFront
		"aws_cloudfront_distributions",
		// AWS CodeBuild
		"aws_codebuild_projects",
		// AWS ECS
		"aws_ecs_clusters",
		"aws_ecs_task_definitions",
		// GCP Compute
		"gcp_compute_instances",
		"gcp_compute_firewalls",
		// GCP IAM
		"gcp_iam_service_accounts",
		"gcp_iam_roles",
		// GCP Storage
		"gcp_storage_buckets",
		// GCP SQL
		"gcp_sql_instances",
		// GCP GKE
		"gcp_container_clusters",
		// Azure VMs
		"azure_compute_virtual_machines",
		// Azure Storage
		"azure_storage_accounts",
		"azure_storage_containers",
		// Azure SQL
		"azure_sql_servers",
		"azure_sql_databases",
		// Azure Network
		"azure_network_security_groups",
		// Azure Identity
		"azure_ad_users",
		"azure_ad_service_principals",
	}
}

// New service initialization functions

func (a *App) initRBAC() {
	a.RBAC = auth.NewRBAC()
	a.Logger.Info("rbac service initialized")
}

func (a *App) initThreatIntel(ctx context.Context) {
	a.ThreatIntel = threatintel.NewThreatIntelService()

	// Sync feeds in background
	go func() {
		if err := a.ThreatIntel.SyncAll(ctx); err != nil {
			a.Logger.Warn("failed to sync threat intel feeds", "error", err)
		} else {
			stats := a.ThreatIntel.Stats()
			a.Logger.Info("threat intel feeds synced", "indicators", stats["total_indicators"])
		}
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
	if a.Snowflake == nil {
		a.Logger.Warn("security graph disabled - snowflake not configured")
		return
	}

	source := graph.NewSnowflakeSource(a.Snowflake)
	a.SecurityGraphBuilder = graph.NewBuilder(source, a.Logger)
	a.SecurityGraph = a.SecurityGraphBuilder.Graph()

	// Build initial graph in background
	go func() {
		if err := a.SecurityGraphBuilder.Build(ctx); err != nil {
			a.Logger.Error("failed to build security graph", "error", err)
			return
		}
		meta := a.SecurityGraph.Metadata()
		a.Logger.Info("security graph built",
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", meta.BuildDuration,
		)

		// Emit webhook event
		if err := a.Webhooks.EmitWithErrors(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
			"nodes":          meta.NodeCount,
			"edges":          meta.EdgeCount,
			"build_duration": meta.BuildDuration.String(),
		}); err != nil {
			a.Logger.Warn("failed to emit graph rebuilt webhook", "error", err)
		}
	}()
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
