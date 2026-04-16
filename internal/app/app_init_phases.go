package app

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	appState := a.appStateSubsystem()
	graphSubsystem := a.graphSubsystem()

	a.initExecutionStore()
	if err := appState.Init(ctx); err != nil {
		return err
	}
	if err := runInitErrorStep("legacy_snowflake", func() error { return a.initLegacySnowflake(ctx) }); err != nil {
		a.Logger.Warn("legacy snowflake initialization failed", "error", err)
	}
	if err := graphSubsystem.Init(ctx); err != nil {
		return err
	}

	if err := runSubsystemInitConcurrently(ctx,
		initOnlySubsystem("cache", func(context.Context) { a.initCache() }),
		initOnlySubsystem("ticketing", func(taskCtx context.Context) { a.initTicketing(taskCtx) }),
		initOnlySubsystem("identity", func(context.Context) { a.initIdentity() }),
		initOnlySubsystem("attackpath", func(context.Context) { a.initAttackPath() }),
		initOnlySubsystem("webhooks", func(context.Context) { a.initWebhooks() }),
		initOnlySubsystem("notifications", func(context.Context) { a.initNotifications() }),
		initOnlySubsystem("rbac", func(context.Context) { a.initRBAC() }),
		initOnlySubsystem("health", func(context.Context) { a.initHealth() }),
		initOnlySubsystem("lineage", func(context.Context) { a.initLineage() }),
		a.runtimeSubsystem(),
		initOnlySubsystem("findings", func(context.Context) { a.initFindings() }),
		initOnlySubsystem("providers", func(taskCtx context.Context) { a.initProviders(taskCtx) }),
		initOnlySubsystem("scheduler", func(taskCtx context.Context) { a.initScheduler(taskCtx) }),
		initOnlySubsystem("snowflake_findings", func(taskCtx context.Context) { a.initSnowflakeFindings(taskCtx) }),
		initOnlySubsystem("scan_watermarks", func(taskCtx context.Context) { a.initScanWatermarks(taskCtx) }),
		initOnlySubsystem("threatintel", func(context.Context) { a.initThreatIntel(ctx) }),
		initOnlySubsystem("available_tables", func(taskCtx context.Context) { a.initAvailableTables(taskCtx) }),
	); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	if err := appState.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (a *App) initPhase2b(ctx context.Context) error {
	remediation := a.remediationSubsystem()
	if err := runSubsystemInitConcurrently(ctx, remediation, a.agentsSubsystem()); err != nil {
		return fmt.Errorf("phase 2b init failed: %w", err)
	}
	if err := runSubsystemStartSequentially(ctx, remediation, a.eventsSubsystem()); err != nil {
		return fmt.Errorf("phase 2b start failed: %w", err)
	}
	return nil
}

func (a *App) initPhase3() {
	a.initScanner()
}

func (a *App) initPhase4(ctx context.Context) error {
	if err := runSubsystemStartSequentially(ctx, a.graphSubsystem()); err != nil {
		return err
	}
	return a.validatePolicyCoverage(ctx)
}

func runInitTasksConcurrently(ctx context.Context, tasks []concurrentInitTask) error {
	subsystems := make([]initSubsystem, 0, len(tasks))
	for _, task := range tasks {
		task := task
		subsystems = append(subsystems, initOnlySubsystem(task.name, task.run))
	}
	return runSubsystemInitConcurrently(ctx, subsystems...)
}
