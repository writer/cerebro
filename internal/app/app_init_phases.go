package app

import (
	"context"
	"fmt"
	"os"

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
	if err := runInitErrorStep("warehouse", func() error { return a.initWarehouse(ctx) }); err != nil {
		a.Logger.Warn("warehouse initialization failed", "error", err, "backend", a.Config.WarehouseBackend)
	}
	if err := runInitErrorStep("policy", a.initPolicy); err != nil {
		return err
	}
	return nil
}

func (a *App) initPhase2a(ctx context.Context) error {
	a.initExecutionStore()
	a.initGraphPersistenceStore()
	if err := runInitErrorStep("graph_writer_lease", func() error { return a.initGraphWriterLease(ctx) }); err != nil {
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
		{name: "available_tables", run: func(taskCtx context.Context) { a.initAvailableTables(taskCtx) }},
	}); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	return nil
}

func (a *App) initPhase2b(ctx context.Context) error {
	if err := runInitTasksConcurrently(ctx, []concurrentInitTask{
		{name: "remediation", run: func(context.Context) { a.initRemediation() }},
		{name: "agents", run: func(taskCtx context.Context) { a.initAgents(taskCtx) }},
	}); err != nil {
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
