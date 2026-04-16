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
	if err := appState.Start(ctx); err != nil {
		return err
	}
	if _, err := executeLifecycleStages(ctx, a.Logger, lifecycleStage{
		phase:        "phase2a.init",
		action:       lifecycleActionInit,
		preSatisfied: []string{"appstate", "graph"},
		subsystems:   a.phase2aInitSubsystems(),
	}); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	return nil
}

func (a *App) initPhase2b(ctx context.Context) error {
	if _, err := executeLifecycleStages(ctx, a.Logger,
		lifecycleStage{
			phase:        "phase2b.init",
			action:       lifecycleActionInit,
			preSatisfied: []string{"findings", "notifications", "runtime", "ticketing", "webhooks"},
			subsystems:   a.phase2bInitSubsystems(),
		},
		lifecycleStage{
			phase:        "phase2b.start",
			action:       lifecycleActionStart,
			preSatisfied: []string{"graph", "webhooks"},
			subsystems:   a.phase2bStartSubsystems(),
		},
	); err != nil {
		return fmt.Errorf("phase 2b lifecycle failed: %w", err)
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

func (a *App) phase2aInitSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		initOnlySubsystem("cache", func(context.Context) { a.initCache() }),
		initOnlySubsystem("ticketing", func(taskCtx context.Context) { a.initTicketing(taskCtx) }),
		initOnlySubsystem("identity", func(context.Context) { a.initIdentity() }),
		initOnlySubsystem("attackpath", func(context.Context) { a.initAttackPath() }),
		initOnlySubsystem("webhooks", func(context.Context) { a.initWebhooks() }),
		initOnlySubsystem("notifications", func(context.Context) { a.initNotifications() }),
		initOnlySubsystem("rbac", func(context.Context) { a.initRBAC() }),
		initOnlySubsystem("compliance", func(context.Context) { a.initCompliance() }),
		initOnlySubsystem("health", func(context.Context) { a.initHealth() }),
		initOnlySubsystem("lineage", func(context.Context) { a.initLineage() }),
		wrapInitSubsystem(a.runtimeSubsystem()),
		initOnlySubsystem("findings", func(context.Context) { a.initFindings() }),
		initOnlySubsystem("providers", func(taskCtx context.Context) { a.initProviders(taskCtx) }),
		initOnlySubsystemWithDeps("snowflake_findings", []string{"findings"}, func(taskCtx context.Context) {
			a.initSnowflakeFindings(taskCtx)
		}),
		initOnlySubsystem("scan_watermarks", func(taskCtx context.Context) { a.initScanWatermarks(taskCtx) }),
		initOnlySubsystemWithDeps("threatintel", []string{"webhooks"}, func(taskCtx context.Context) {
			a.initThreatIntel(taskCtx)
		}),
		initOnlySubsystem("available_tables", func(taskCtx context.Context) { a.initAvailableTables(taskCtx) }),
		initOnlySubsystemWithDeps("scheduler", []string{"appstate", "available_tables", "findings", "health", "notifications", "scan_watermarks"}, func(taskCtx context.Context) {
			a.initScheduler(taskCtx)
		}),
	}
}

func (a *App) phase2bInitSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		wrapInitSubsystem(a.remediationSubsystem(), "findings", "notifications", "runtime", "ticketing", "webhooks"),
		wrapInitSubsystem(a.agentsSubsystem(), "remediation", "runtime"),
	}
}

func (a *App) phase2bStartSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		wrapStartSubsystem(a.remediationSubsystem()),
		wrapStartSubsystem(a.eventsSubsystem(), "remediation"),
	}
}

func runInitTasksConcurrently(ctx context.Context, tasks []concurrentInitTask) error {
	subsystems := make([]initSubsystem, 0, len(tasks))
	for _, task := range tasks {
		task := task
		subsystems = append(subsystems, initOnlySubsystem(task.name, task.run))
	}
	return runSubsystemInitConcurrently(ctx, subsystems...)
}
