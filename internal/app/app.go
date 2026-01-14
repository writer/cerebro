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
	"strings"
	"time"

	"github.com/writerinternal/cerebro/internal/agents"
	agentproviders "github.com/writerinternal/cerebro/internal/agents/providers"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/auth"
	"github.com/writerinternal/cerebro/internal/cache"
	"github.com/writerinternal/cerebro/internal/cloudquery"
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
	Findings  *findings.Store
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

	// CloudQuery table management
	CloudQuery *cloudquery.TableManager

	// Incremental scanning
	ScanWatermarks *scanner.WatermarkStore

	// File-based findings (for dev mode)
	FileFindings *findings.FileStore

	// New services
	RBAC           *auth.RBAC
	ThreatIntel    *threatintel.ThreatIntelService
	Compliance     *compliance.ComplianceReport
	Health         *health.Registry
	Lineage        *lineage.LineageMapper
	Remediation    *remediation.Engine
	RuntimeDetect  *runtime.DetectionEngine
	RuntimeRespond *runtime.ResponseEngine

	// Security Graph
	SecurityGraph        *graph.Graph
	SecurityGraphBuilder *graph.Builder
}

// Config holds all application configuration
type Config struct {
	// Server
	Port     int
	LogLevel string

	// Snowflake
	SnowflakeConnectionString string
	SnowflakeDatabase         string
	SnowflakeSchema           string
	SnowflakeWarehouse        string

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

	// Wiz Provider
	WizClientID     string
	WizClientSecret string

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

	// Rate Limiting
	RateLimitEnabled  bool
	RateLimitRequests int
	RateLimitWindow   time.Duration
}

func LoadConfig() *Config {
	return &Config{
		Port:                      getEnvInt("API_PORT", 8080),
		LogLevel:                  getEnv("LOG_LEVEL", "info"),
		SnowflakeConnectionString: getEnv("SNOWFLAKE_CONNECTION_STRING", ""),
		SnowflakeDatabase:         getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:           getEnv("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeWarehouse:        getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		PoliciesPath:              getEnv("POLICIES_PATH", "policies"),
		AnthropicAPIKey:           getEnv("ANTHROPIC_API_KEY", ""),
		OpenAIAPIKey:              getEnv("OPENAI_API_KEY", ""),
		JiraBaseURL:               getEnv("JIRA_BASE_URL", ""),
		JiraEmail:                 getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:              getEnv("JIRA_API_TOKEN", ""),
		JiraProject:               getEnv("JIRA_PROJECT", "SEC"),
		LinearAPIKey:              getEnv("LINEAR_API_KEY", ""),
		LinearTeamID:              getEnv("LINEAR_TEAM_ID", ""),
		CrowdStrikeClientID:       getEnv("CROWDSTRIKE_CLIENT_ID", ""),
		CrowdStrikeClientSecret:   getEnv("CROWDSTRIKE_CLIENT_SECRET", ""),
		OktaDomain:                getEnv("OKTA_DOMAIN", ""),
		OktaAPIToken:              getEnv("OKTA_API_TOKEN", ""),
		AzureTenantID:             getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:             getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret:         getEnv("AZURE_CLIENT_SECRET", ""),
		AzureSubscriptionID:       getEnv("AZURE_SUBSCRIPTION_ID", ""),
		SnykAPIToken:              getEnv("SNYK_API_TOKEN", ""),
		SnykOrgID:                 getEnv("SNYK_ORG_ID", ""),
		WizClientID:               getEnv("WIZ_CLIENT_ID", ""),
		WizClientSecret:           getEnv("WIZ_CLIENT_SECRET", ""),
		DatadogAPIKey:             getEnv("DATADOG_API_KEY", ""),
		DatadogAppKey:             getEnv("DATADOG_APP_KEY", ""),
		DatadogSite:               getEnv("DATADOG_SITE", "datadoghq.com"),
		GitHubToken:               getEnv("GITHUB_TOKEN", ""),
		GitHubOrg:                 getEnv("GITHUB_ORG", ""),
		SentinelOneAPIToken:       getEnv("SENTINELONE_API_TOKEN", ""),
		SentinelOneBaseURL:        getEnv("SENTINELONE_BASE_URL", ""),
		TenableAccessKey:          getEnv("TENABLE_ACCESS_KEY", ""),
		TenableSecretKey:          getEnv("TENABLE_SECRET_KEY", ""),
		QualysUsername:            getEnv("QUALYS_USERNAME", ""),
		QualysPassword:            getEnv("QUALYS_PASSWORD", ""),
		QualysPlatform:            getEnv("QUALYS_PLATFORM", "US1"),
		SemgrepAPIToken:           getEnv("SEMGREP_API_TOKEN", ""),
		GitLabToken:               getEnv("GITLAB_TOKEN", ""),
		GitLabBaseURL:             getEnv("GITLAB_BASE_URL", "https://gitlab.com"),
		TerraformCloudToken:       getEnv("TFC_TOKEN", ""),
		SplunkURL:                 getEnv("SPLUNK_URL", ""),
		SplunkToken:               getEnv("SPLUNK_TOKEN", ""),
		Auth0Domain:               getEnv("AUTH0_DOMAIN", ""),
		Auth0ClientID:             getEnv("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:         getEnv("AUTH0_CLIENT_SECRET", ""),
		CloudflareAPIToken:        getEnv("CLOUDFLARE_API_TOKEN", ""),
		SlackWebhookURL:           getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:        getEnv("SLACK_SIGNING_SECRET", ""),
		PagerDutyKey:              getEnv("PAGERDUTY_ROUTING_KEY", ""),
		ScanInterval:              getEnv("SCAN_INTERVAL", ""),
		ScanTables:                getEnv("SCAN_TABLES", ""),
		RateLimitEnabled:          getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests:         getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:           getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),
	}
}

// New creates and wires up the entire application
func New(ctx context.Context) (*App, error) {
	cfg := LoadConfig()

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
	app.initCloudQuery()
	app.initScanWatermarks(ctx)
	app.initFileFindings()

	// Initialize new services
	app.initRBAC()
	app.initThreatIntel(ctx)
	app.initCompliance()
	app.initHealth()
	app.initLineage()
	app.initRemediation()
	app.initRuntime()
	app.initSecurityGraph(ctx)

	logger.Info("application initialized",
		"snowflake", app.Snowflake != nil,
		"policies", len(app.Policy.ListPolicies()),
	)

	return app, nil
}

func (a *App) initSnowflake(ctx context.Context) error {
	if a.Config.SnowflakeConnectionString == "" {
		return fmt.Errorf("SNOWFLAKE_CONNECTION_STRING not set")
	}

	client, err := snowflake.NewClient(
		a.Config.SnowflakeConnectionString,
		a.Config.SnowflakeDatabase,
		a.Config.SnowflakeSchema,
	)
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
	a.Findings = findings.NewStore()
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

	// Create security tools for agents
	tools := agents.NewSecurityTools(a.Snowflake, a.Findings, a.Policy)

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

	// Register CrowdStrike if configured
	if a.Config.CrowdStrikeClientID != "" {
		cs := providers.NewCrowdStrikeProvider()
		_ = cs.Configure(ctx, map[string]interface{}{
			"client_id":     a.Config.CrowdStrikeClientID,
			"client_secret": a.Config.CrowdStrikeClientSecret,
		})
		a.Providers.Register(cs)
		a.Logger.Info("crowdstrike provider registered")
	}

	// Register Okta if configured
	if a.Config.OktaDomain != "" {
		okta := providers.NewOktaProvider()
		_ = okta.Configure(ctx, map[string]interface{}{
			"domain":    a.Config.OktaDomain,
			"api_token": a.Config.OktaAPIToken,
		})
		a.Providers.Register(okta)
		a.Logger.Info("okta provider registered")
	}

	// Register Azure if configured
	if a.Config.AzureTenantID != "" && a.Config.AzureClientID != "" {
		azure := providers.NewAzureProvider()
		_ = azure.Configure(ctx, map[string]interface{}{
			"tenant_id":       a.Config.AzureTenantID,
			"client_id":       a.Config.AzureClientID,
			"client_secret":   a.Config.AzureClientSecret,
			"subscription_id": a.Config.AzureSubscriptionID,
		})
		a.Providers.Register(azure)
		a.Logger.Info("azure provider registered")
	}

	// Register Snyk if configured
	if a.Config.SnykAPIToken != "" {
		snyk := providers.NewSnykProvider()
		_ = snyk.Configure(ctx, map[string]interface{}{
			"api_token": a.Config.SnykAPIToken,
			"org_id":    a.Config.SnykOrgID,
		})
		a.Providers.Register(snyk)
		a.Logger.Info("snyk provider registered")
	}

	// Register Wiz if configured
	if a.Config.WizClientID != "" {
		wiz := providers.NewWizProvider()
		_ = wiz.Configure(ctx, map[string]interface{}{
			"client_id":     a.Config.WizClientID,
			"client_secret": a.Config.WizClientSecret,
		})
		a.Providers.Register(wiz)
		a.Logger.Info("wiz provider registered")
	}

	// Register Datadog if configured
	if a.Config.DatadogAPIKey != "" {
		dd := providers.NewDatadogProvider()
		_ = dd.Configure(ctx, map[string]interface{}{
			"api_key": a.Config.DatadogAPIKey,
			"app_key": a.Config.DatadogAppKey,
			"site":    a.Config.DatadogSite,
		})
		a.Providers.Register(dd)
		a.Logger.Info("datadog provider registered")
	}

	// Register GitHub if configured
	if a.Config.GitHubToken != "" && a.Config.GitHubOrg != "" {
		gh := providers.NewGitHubProvider()
		_ = gh.Configure(ctx, map[string]interface{}{
			"token": a.Config.GitHubToken,
			"org":   a.Config.GitHubOrg,
		})
		a.Providers.Register(gh)
		a.Logger.Info("github provider registered")
	}

	// Register SentinelOne if configured
	if a.Config.SentinelOneAPIToken != "" {
		s1 := providers.NewSentinelOneProvider()
		_ = s1.Configure(ctx, map[string]interface{}{
			"api_token": a.Config.SentinelOneAPIToken,
			"base_url":  a.Config.SentinelOneBaseURL,
		})
		a.Providers.Register(s1)
		a.Logger.Info("sentinelone provider registered")
	}

	// Register Tenable if configured
	if a.Config.TenableAccessKey != "" {
		tenable := providers.NewTenableProvider()
		_ = tenable.Configure(ctx, map[string]interface{}{
			"access_key": a.Config.TenableAccessKey,
			"secret_key": a.Config.TenableSecretKey,
		})
		a.Providers.Register(tenable)
		a.Logger.Info("tenable provider registered")
	}
}

func (a *App) initWebhooks() {
	a.Webhooks = webhooks.NewService()
}

func (a *App) initNotifications() {
	a.Notifications = notifications.NewManager()

	if a.Config.SlackWebhookURL != "" {
		slack := notifications.NewSlackNotifier(notifications.SlackConfig{
			WebhookURL: a.Config.SlackWebhookURL,
		})
		a.Notifications.AddNotifier(slack)
		a.Logger.Info("slack notifications enabled")
	}

	if a.Config.PagerDutyKey != "" {
		pd := notifications.NewPagerDutyNotifier(notifications.PagerDutyConfig{
			RoutingKey: a.Config.PagerDutyKey,
		})
		a.Notifications.AddNotifier(pd)
		a.Logger.Info("pagerduty notifications enabled")
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

	// Check data freshness before scan (spot check first few tables)
	if a.CloudQuery != nil {
		checkCount := 3
		if len(tables) < checkCount {
			checkCount = len(tables)
		}
		for i := 0; i < checkCount; i++ {
			freshness, err := a.CloudQuery.CheckDataFreshness(ctx, tables[i])
			if err == nil && freshness.IsStale {
				a.Logger.Warn("cloudquery data is stale",
					"table", tables[i],
					"hours_old", freshness.HoursSinceSync,
					"last_sync", freshness.LastSyncTime,
				)
			}
		}
	}

	totalScanned := 0
	totalViolations := 0

	for _, table := range tables {
		assets, err := a.Snowflake.GetAssets(ctx, table, snowflake.AssetFilter{Limit: 1000})
		if err != nil {
			a.Logger.Warn("failed to fetch assets", "table", table, "error", err)
			continue
		}

		result := a.Scanner.ScanAssets(ctx, assets)
		totalScanned += int(result.Scanned)
		totalViolations += int(result.Violations)

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
	a.Webhooks.EmitScanCompleted(ctx, int64(totalScanned), int64(totalViolations), 0)

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
	if a.Snowflake == nil {
		return
	}

	a.SnowflakeFindings = findings.NewSnowflakeStore(
		a.Snowflake.DB(),
		a.Config.SnowflakeDatabase,
		a.Config.SnowflakeSchema,
	)

	// Load existing findings from Snowflake
	if err := a.SnowflakeFindings.Load(ctx); err != nil {
		a.Logger.Warn("failed to load findings from snowflake", "error", err)
	} else {
		a.Logger.Info("loaded findings from snowflake", "count", a.SnowflakeFindings.Stats().Total)
	}
}

func (a *App) initCloudQuery() {
	if a.Snowflake == nil {
		return
	}
	a.CloudQuery = cloudquery.NewTableManager(a.Snowflake, a.Config.SnowflakeSchema)
	a.Logger.Info("cloudquery table manager initialized")
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

func (a *App) initFileFindings() {
	// Only enable file-based findings in dev mode when Snowflake is not available
	if a.Snowflake != nil {
		return
	}

	filePath := findings.DefaultFilePath()
	if path := os.Getenv("CEREBRO_FINDINGS_FILE"); path != "" {
		filePath = path
	}

	store, err := findings.NewFileStore(filePath)
	if err != nil {
		a.Logger.Warn("failed to initialize file findings store", "error", err)
		return
	}

	a.FileFindings = store
	a.Logger.Info("file-based findings store initialized", "path", filePath)
}

// Close cleanly shuts down all services
func (a *App) Close() error {
	if a.Snowflake != nil {
		return a.Snowflake.Close()
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
	var result []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

// defaultScanTables returns the comprehensive list of CloudQuery tables to scan
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

	a.Health.Register("cloudquery_data", health.PingCheck("cloudquery_data", func(ctx context.Context) error {
		if a.CloudQuery == nil {
			return fmt.Errorf("not configured")
		}
		// Check that at least some tables have data
		tables, err := a.CloudQuery.ListAvailableTables(ctx)
		if err != nil {
			return fmt.Errorf("cannot list tables: %w", err)
		}
		if len(tables) == 0 {
			return fmt.Errorf("no cloudquery tables found - sync may be needed")
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
		a.Webhooks.Emit(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
			"nodes":          meta.NodeCount,
			"edges":          meta.EdgeCount,
			"build_duration": meta.BuildDuration.String(),
		})
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
	a.Webhooks.Emit(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
		"nodes":          meta.NodeCount,
		"edges":          meta.EdgeCount,
		"build_duration": time.Since(start).String(),
	})

	return nil
}
