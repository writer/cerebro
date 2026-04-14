package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sync/errgroup"
)

type concurrentInitTask struct {
	name string
	run  func(context.Context)
}

func (a *App) initialize(ctx context.Context) error {
	if err := runInitErrorStep("telemetry", func() error { return a.initTelemetry(ctx) }); err != nil {
		a.Logger.Warn("telemetry initialization failed", "error", err)
	}

	if err := a.initPhase1(ctx); err != nil {
		return err
	}
	if err := a.initPhase2a(ctx); err != nil {
		return err
	}
	if err := a.initPhase2b(ctx); err != nil {
		return err
	}

	a.initPhase3()
	if err := a.validateRequiredServices(); err != nil {
		return err
	}

	if err := a.initPhase4(ctx); err != nil {
		a.Logger.Warn("policy coverage validation failed", "error", err)
		if os.Getenv("CI") != "" {
			return err
		}
	}

	return nil
}

func (a *App) initPhase1(ctx context.Context) error {
	warehouseBackend := strings.ToLower(strings.TrimSpace(a.Config.WarehouseBackend))

	if err := runInitErrorStep("warehouse", func() error { return a.initWarehouse(ctx) }); err != nil {
		if warehouseBackend == "snowflake" {
			return fmt.Errorf("warehouse initialization failed for backend %s: %w", warehouseBackend, err)
		}
		a.Logger.Warn("warehouse initialization failed", "error", err, "backend", a.Config.WarehouseBackend)
	}
	if warehouseBackend == "snowflake" && a.Snowflake == nil {
		return fmt.Errorf("warehouse initialization failed for backend %s: snowflake client was not initialized", warehouseBackend)
	}
	if err := runInitErrorStep("policy", a.initPolicy); err != nil {
		return err
	}
	return nil
}

func (a *App) initPhase2a(ctx context.Context) error {
	a.initExecutionStore()
	a.initGraphPersistenceStore()
	if err := runInitErrorStep("app_state_db", func() error { return a.initAppStateDB(ctx) }); err != nil {
		return err
	}
	if err := a.initLegacySnowflakeForAppState(ctx); err != nil {
		return err
	}
	if err := runInitErrorStep("graph_store_backend", func() error { return a.initConfiguredSecurityGraphStore(ctx) }); err != nil {
		return err
	}
	if err := runInitErrorStep("graph_writer_lease", func() error { return a.initGraphWriterLease(ctx) }); err != nil {
		return err
	}
	if err := runInitErrorStep("entity_search_backend", func() error { return a.initEntitySearchBackend(ctx) }); err != nil {
		return err
	}

	if err := runInitTasksConcurrently(ctx, []concurrentInitTask{
		{name: "cache", run: func(context.Context) { a.initCache() }},
		{name: "ticketing", run: func(taskCtx context.Context) { a.initTicketing(taskCtx) }},
		{name: "identity", run: func(context.Context) { a.initIdentity() }},
		{name: "attackpath", run: func(context.Context) { a.initAttackPath() }},
		{name: "webhooks", run: func(context.Context) { a.initWebhooks() }},
		{name: "notifications", run: func(context.Context) { a.initNotifications() }},
		{name: "rbac", run: func(context.Context) { a.initRBAC() }},
		{name: "compliance", run: func(context.Context) { a.initCompliance() }},
		{name: "health", run: func(context.Context) { a.initHealth() }},
		{name: "lineage", run: func(context.Context) { a.initLineage() }},
		{name: "runtime", run: func(context.Context) { a.initRuntime() }},
		{name: "findings", run: func(context.Context) { a.initFindings() }},
		{name: "providers", run: func(taskCtx context.Context) { a.initProviders(taskCtx) }},
		{name: "scheduler", run: func(taskCtx context.Context) { a.initScheduler(taskCtx) }},
		{name: "repositories", run: func(context.Context) { a.initRepositories() }},
		{name: "snowflake_findings", run: func(taskCtx context.Context) { a.initSnowflakeFindings(taskCtx) }},
		{name: "scan_watermarks", run: func(taskCtx context.Context) { a.initScanWatermarks(taskCtx) }},
		{name: "threatintel", run: func(context.Context) { a.initThreatIntel(ctx) }},
		{name: "vulndb", run: func(context.Context) { a.initVulnDB() }},
		{name: "available_tables", run: func(taskCtx context.Context) { a.initAvailableTables(taskCtx) }},
	}); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	if err := runInitErrorStep("app_state_migration", func() error { return a.migrateAppState(ctx) }); err != nil {
		return err
	}
	if err := runInitErrorStep("endpoint_vulnerability_tables", func() error {
		return a.refreshEndpointVulnerabilityTables(ctx, "startup")
	}); err != nil {
		return err
	}
	return nil
}

func (a *App) initLegacySnowflakeForAppState(ctx context.Context) error {
	required, stateErr := a.requiresLegacySnowflakeSource(ctx)
	if stateErr != nil {
		return fmt.Errorf("determine legacy snowflake source requirement: %w", stateErr)
	}
	if err := runInitErrorStep("legacy_snowflake", func() error { return a.initLegacySnowflake(ctx) }); err != nil {
		if required {
			return fmt.Errorf("legacy snowflake initialization failed: %w", err)
		}
		a.Logger.Warn("legacy snowflake initialization failed", "error", err)
	}
	if required && a.appStateMigrationSnowflake() == nil {
		return fmt.Errorf("legacy snowflake source is required until app-state migration completes or legacy retention is disabled")
	}
	return nil
}

func (a *App) requiresLegacySnowflakeSource(ctx context.Context) (bool, error) {
	migrationRequired, err := a.requiresLegacySnowflakeMigrationSource(ctx)
	if err != nil || migrationRequired {
		return migrationRequired, err
	}
	return a.requiresLegacySnowflakeRetentionSource(ctx)
}

func (a *App) requiresLegacySnowflakeMigrationSource(ctx context.Context) (bool, error) {
	if a == nil || a.appStateDB == nil {
		return false, nil
	}
	completed, err := a.appStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName)
	if err != nil {
		return false, err
	}
	if completed {
		return false, nil
	}
	if a.Snowflake != nil {
		return false, nil
	}
	started, err := a.appStateMigrationComplete(ctx, legacySnowflakeAppStateStartedName)
	if err != nil {
		return false, err
	}
	if started || hasSnowflakeCredentials(a.Config) {
		return true, nil
	}
	return a.hasExistingWarehouseTables(ctx)
}

func (a *App) requiresLegacySnowflakeRetentionSource(ctx context.Context) (bool, error) {
	if a == nil || a.appStateDB == nil || a.Snowflake != nil || !legacySnowflakeRetentionEnabled(a.Config) {
		return false, nil
	}
	completed, err := a.appStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName)
	if err != nil {
		return false, err
	}
	return completed, nil
}

func (a *App) hasExistingWarehouseTables(ctx context.Context) (bool, error) {
	if a == nil || a.Warehouse == nil {
		return false, nil
	}
	tables, err := a.Warehouse.ListAvailableTables(ctx)
	if err != nil {
		return false, err
	}
	for _, table := range tables {
		if !isAppStateWarehouseTable(table) {
			return true, nil
		}
	}
	return false, nil
}

func legacySnowflakeRetentionEnabled(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return maxRetentionDays(cfg.GraphRetentionDays) > 0 || maxRetentionDays(cfg.AccessReviewRetentionDays) > 0
}

func isAppStateWarehouseTable(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case
		"cerebro_findings",
		"cerebro_agent_sessions",
		"cerebro_audit_log",
		"cerebro_policy_history",
		"cerebro_risk_engine_state",
		"cerebro_app_state_migrations":
		return true
	default:
		return false
	}
}

func (a *App) initPhase2b(ctx context.Context) error {
	// Agent tooling rebinds remediation remote callers, so remediation must be ready first.
	if err := runInitStep("remediation", func() { a.initRemediation() }); err != nil {
		return fmt.Errorf("phase 2b init failed: %w", err)
	}
	if err := runInitStep("agents", func() { a.initAgents(ctx) }); err != nil {
		return fmt.Errorf("phase 2b init failed: %w", err)
	}
	a.startEventRemediation(ctx)
	a.startEventAlertRouting(ctx)
	return nil
}

func (a *App) initPhase3() {
	a.initScanner()
}

func (a *App) initPhase4(ctx context.Context) error {
	a.initSecurityGraph(ctx)
	a.initTapGraphConsumer(ctx)
	return a.validatePolicyCoverage(ctx)
}

func runInitTasksConcurrently(ctx context.Context, tasks []concurrentInitTask) error {
	if len(tasks) == 0 {
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	for _, task := range tasks {
		task := task
		g.Go(func() error {
			return runInitStep(task.name, func() {
				task.run(gctx)
			})
		})
	}
	return g.Wait()
}
