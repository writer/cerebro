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
	"github.com/writerinternal/cerebro/internal/cache"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/scanner"
	"github.com/writerinternal/cerebro/internal/scheduler"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"
)

// App is the main application container with all services wired together
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
		SlackWebhookURL:           getEnv("SLACK_WEBHOOK_URL", ""),
		SlackSigningSecret:       getEnv("SLACK_SIGNING_SECRET", ""),
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
	}

	// Register Okta if configured
	if a.Config.OktaDomain != "" {
		okta := providers.NewOktaProvider()
		_ = okta.Configure(ctx, map[string]interface{}{
			"domain":    a.Config.OktaDomain,
			"api_token": a.Config.OktaAPIToken,
		})
		a.Providers.Register(okta)
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

		tables := []string{"aws_s3_buckets", "aws_ec2_instances", "aws_iam_users"}
		if a.Config.ScanTables != "" {
			tables = splitTables(a.Config.ScanTables)
		}

		a.Scheduler.AddJob("policy-scan", interval, func(ctx context.Context) error {
			return a.runScheduledScan(ctx, tables)
		})

		a.Logger.Info("scheduled scanning enabled", "interval", interval, "tables", tables)
	}
}

func (a *App) runScheduledScan(ctx context.Context, tables []string) error {
	if a.Snowflake == nil {
		return fmt.Errorf("snowflake not configured")
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
