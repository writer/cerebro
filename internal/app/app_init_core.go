package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	agentproviders "github.com/writer/cerebro/internal/agents/providers"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scm"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

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
		metrics.SetPolicyLoadMetrics(0, 0)
		return nil
	}
	metrics.SetPolicyLoadMetrics(len(a.Policy.ListPolicies()), len(a.Policy.ListQueryPolicies()))
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
			a.configureFindingAttestation()
			return
		}
		a.Findings = store
		a.configureFindingAttestation()
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
	a.configureFindingAttestation()
	a.Logger.Info("using snowflake findings store")
}

func (a *App) configureFindingAttestation() {
	if !a.Config.FindingAttestationEnabled {
		return
	}

	signingKey := strings.TrimSpace(a.Config.FindingAttestationSigningKey)
	if signingKey == "" {
		a.Logger.Warn("finding attestation enabled but signing key is not configured")
		return
	}

	attestor, err := findings.NewTransparencyDevAttestor(findings.TransparencyDevAttestorConfig{
		LogURL:     strings.TrimSpace(a.Config.FindingAttestationLogURL),
		SigningKey: signingKey,
		KeyID:      strings.TrimSpace(a.Config.FindingAttestationKeyID),
		Timeout:    a.Config.FindingAttestationTimeout,
	})
	if err != nil {
		a.Logger.Warn("failed to initialize finding attestor", "error", err)
		return
	}

	configured := false
	if store, ok := a.Findings.(*findings.Store); ok {
		store.SetAttestor(attestor, a.Config.FindingAttestationAttestReobserved)
		configured = true
	}
	if store, ok := a.Findings.(*findings.SQLiteStore); ok {
		store.SetAttestor(attestor, a.Config.FindingAttestationAttestReobserved)
		configured = true
	}
	if store, ok := a.Findings.(*findings.SnowflakeStore); ok {
		store.SetAttestor(attestor, a.Config.FindingAttestationAttestReobserved)
		configured = true
	}
	if store, ok := a.Findings.(*findings.FileStore); ok {
		store.SetAttestor(attestor, a.Config.FindingAttestationAttestReobserved)
		configured = true
	}

	if !configured {
		a.Logger.Warn("finding attestation enabled but findings store does not support attestations")
		return
	}

	a.Logger.Info("finding attestation chain enabled",
		"log_url", strings.TrimSpace(a.Config.FindingAttestationLogURL),
		"attest_reobserved", a.Config.FindingAttestationAttestReobserved,
	)
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
	if a.Snowflake != nil {
		store, err := agents.NewSnowflakeSessionStore(a.Snowflake)
		if err != nil {
			a.Logger.Warn("failed to initialize persistent agent session store, using in-memory store", "error", err)
		} else {
			a.Agents.SetSessionStore(store)
		}
	}

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

func (a *App) initWebhooks() {
	a.Webhooks = webhooks.NewService()
	a.initJetStreamEventPublisher()

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

func (a *App) initJetStreamEventPublisher() {
	if !a.Config.NATSJetStreamEnabled {
		return
	}

	publisher, err := events.NewJetStreamPublisher(events.JetStreamConfig{
		URLs:                  a.Config.NATSJetStreamURLs,
		Stream:                a.Config.NATSJetStreamStream,
		SubjectPrefix:         a.Config.NATSJetStreamSubjectPrefix,
		Source:                a.Config.NATSJetStreamSource,
		OutboxPath:            a.Config.NATSJetStreamOutboxPath,
		OutboxDLQPath:         a.Config.NATSJetStreamOutboxDLQPath,
		OutboxMaxRecords:      a.Config.NATSJetStreamOutboxMaxItems,
		OutboxMaxAge:          a.Config.NATSJetStreamOutboxMaxAge,
		OutboxMaxAttempts:     a.Config.NATSJetStreamOutboxMaxRetry,
		OutboxWarnPercent:     a.Config.NATSJetStreamOutboxWarnPercent,
		OutboxCriticalPercent: a.Config.NATSJetStreamOutboxCriticalPercent,
		OutboxWarnAge:         a.Config.NATSJetStreamOutboxWarnAge,
		OutboxCriticalAge:     a.Config.NATSJetStreamOutboxCriticalAge,
		PublishTimeout:        a.Config.NATSJetStreamPublishTimeout,
		RetryAttempts:         a.Config.NATSJetStreamRetryAttempts,
		RetryBackoff:          a.Config.NATSJetStreamRetryBackoff,
		FlushInterval:         a.Config.NATSJetStreamFlushInterval,
		ConnectTimeout:        a.Config.NATSJetStreamConnectTimeout,
		AuthMode:              a.Config.NATSJetStreamAuthMode,
		Username:              a.Config.NATSJetStreamUsername,
		Password:              a.Config.NATSJetStreamPassword,
		NKeySeed:              a.Config.NATSJetStreamNKeySeed,
		UserJWT:               a.Config.NATSJetStreamUserJWT,
		TLSEnabled:            a.Config.NATSJetStreamTLSEnabled,
		TLSCAFile:             a.Config.NATSJetStreamTLSCAFile,
		TLSCertFile:           a.Config.NATSJetStreamTLSCertFile,
		TLSKeyFile:            a.Config.NATSJetStreamTLSKeyFile,
		TLSServerName:         a.Config.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: a.Config.NATSJetStreamTLSInsecure,
	}, a.Logger)
	if err != nil {
		a.Logger.Warn("failed to initialize jetstream event publisher", "error", err)
		return
	}

	a.Webhooks.SetEventPublisher(publisher)
	a.Logger.Info("jetstream event publishing enabled",
		"stream", a.Config.NATSJetStreamStream,
		"subject_prefix", a.Config.NATSJetStreamSubjectPrefix,
		"urls", len(a.Config.NATSJetStreamURLs),
	)
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
