package app

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/dspm"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
)

func (a *App) initPostgres(ctx context.Context) error {
	warehouseURL := strings.TrimSpace(a.Config.DatabaseURL)
	databaseURL := warehouseURL
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(a.Config.JobDatabaseURL)
	}
	if databaseURL == "" {
		a.Logger.Warn("DATABASE_URL not set, running without database")
		return nil
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping postgres: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	a.PostgresDB = db
	a.PostgresClient = postgres.NewPostgresClient(db, "cerebro", "cerebro")
	if warehouseURL != "" {
		a.Warehouse = a.PostgresClient
	} else {
		a.Warehouse = nil
	}

	// Bootstrap schema and tables
	if err := a.PostgresClient.Bootstrap(ctx); err != nil {
		a.Logger.Warn("failed to bootstrap postgres schema", "error", err)
	}

	return nil
}

func (a *App) initWarehouse(ctx context.Context) error {
	switch strings.ToLower(strings.TrimSpace(a.Config.WarehouseBackend)) {
	case "sqlite":
		return a.initSQLiteWarehouse(ctx)
	case "postgres":
		return a.initPostgresWarehouse(ctx)
	default:
		return a.initSQLiteWarehouse(ctx)
	}
}

func (a *App) initSQLiteWarehouse(_ context.Context) error {
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{
		Path:      strings.TrimSpace(a.Config.WarehouseSQLitePath),
		Database:  "sqlite",
		Schema:    "RAW",
		AppSchema: "CEREBRO",
	})
	if err != nil {
		return err
	}
	a.Snowflake = nil
	a.Warehouse = store
	return nil
}

func (a *App) initPostgresWarehouse(_ context.Context) error {
	store, err := warehouse.NewPostgresWarehouse(warehouse.PostgresWarehouseConfig{
		DSN:       strings.TrimSpace(a.Config.WarehousePostgresDSN),
		AppSchema: "cerebro",
	})
	if err != nil {
		return err
	}
	a.Snowflake = nil
	a.Warehouse = store
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
	// When Postgres is available, use PostgresStore as primary
	if a.PostgresDB != nil {
		schemaName := "cerebro"
		if a.PostgresClient != nil {
			if candidate := strings.TrimSpace(a.PostgresClient.AppSchema()); candidate != "" {
				schemaName = candidate
			}
		}
		pgStore := findings.NewPostgresStore(a.PostgresDB, schemaName)
		pgStore.SetSemanticDedup(a.Config.FindingsSemanticDedupEnabled)
		a.Findings = pgStore
		a.PostgresFindings = pgStore
		a.configureFindingAttestation()
		a.Logger.Info("using postgres findings store")
		return
	}

	// Fall back to in-memory store when no database is available
	a.Findings = a.newInMemoryFindingsStore()
	a.configureFindingAttestation()
}

func (a *App) newInMemoryFindingsStore() *findings.Store {
	cfg := findings.DefaultStoreConfig()
	if a != nil && a.Config != nil {
		cfg.MaxFindings = a.Config.FindingsMaxInMemory
		cfg.ResolvedRetention = a.Config.FindingsResolvedRetention
		cfg.SemanticDedup = a.Config.FindingsSemanticDedupEnabled
	}

	if cfg.MaxFindings == 0 && cfg.ResolvedRetention == 0 && a != nil && a.Logger != nil {
		a.Logger.Warn("findings in-memory store configured without size or retention bounds",
			"max_findings", cfg.MaxFindings,
			"resolved_retention", cfg.ResolvedRetention.String(),
		)
	}

	store := findings.NewStoreWithConfig(cfg)
	if a != nil && a.Logger != nil {
		a.Logger.Info("using in-memory findings store",
			"max_findings", cfg.MaxFindings,
			"resolved_retention", cfg.ResolvedRetention.String(),
		)
	}
	return store
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
	if store, ok := a.Findings.(*findings.PostgresStore); ok {
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
	a.DSPM = dspm.NewScanner(dspm.NewMetadataFetcher(), a.Logger, dspm.DefaultScannerConfig())
}

func (a *App) initCache() {
	a.Cache = cache.NewPolicyCache(10000, 15*time.Minute)
}

func (a *App) initTicketing(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	a.Ticketing = ticketing.NewService()

	// Register Jira if configured
	if a.Config.JiraBaseURL != "" && a.Config.JiraAPIToken != "" {
		jira := ticketing.NewJiraProvider(ticketing.JiraConfig{
			BaseURL:          a.Config.JiraBaseURL,
			Email:            a.Config.JiraEmail,
			APIToken:         a.Config.JiraAPIToken,
			Project:          a.Config.JiraProject,
			CloseTransitions: a.Config.JiraCloseTransitions,
		})
		if err := validateTicketingProvider(ctx, jira, a.Config.TicketingProviderValidateTimeoutOrDefault()); err != nil {
			a.Logger.Error("ticketing provider validation failed", "provider", jira.Name(), "error", err)
		} else {
			a.Ticketing.RegisterProvider(jira)
		}
	}

	// Register Linear if configured
	if a.Config.LinearAPIKey != "" {
		linear := ticketing.NewLinearProvider(ticketing.LinearConfig{
			APIKey: a.Config.LinearAPIKey,
			TeamID: a.Config.LinearTeamID,
		})
		if err := validateTicketingProvider(ctx, linear, a.Config.TicketingProviderValidateTimeoutOrDefault()); err != nil {
			a.Logger.Error("ticketing provider validation failed", "provider", linear.Name(), "error", err)
		} else {
			a.Ticketing.RegisterProvider(linear)
		}
	}
}

func validateTicketingProvider(parent context.Context, provider ticketing.Provider, timeout time.Duration) error {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		timeout = (*Config)(nil).TicketingProviderValidateTimeoutOrDefault()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return provider.Validate(ctx)
}

func (a *App) initIdentity() {
	a.Identity = identity.NewService(
		identity.WithExecutionStore(a.ExecutionStore),
		identity.WithGraphResolver(func(ctx context.Context) *graph.Graph {
			if scope, ok := graph.TenantReadScopeFromContext(ctx); ok && !scope.CrossTenant && len(scope.TenantIDs) == 1 {
				view, err := a.currentOrStoredSecurityGraphViewForTenant(scope.TenantIDs[0])
				if err != nil {
					return nil
				}
				return view
			}
			view, err := a.currentOrStoredSecurityGraphView()
			if err != nil {
				return nil
			}
			return view
		}),
	)
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
