package app

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sync/errgroup"
)

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
	if err := runInitErrorStep("snowflake", func() error { return a.initSnowflake(ctx) }); err != nil {
		a.Logger.Warn("snowflake initialization failed", "error", err)
	}
	if err := runInitErrorStep("policy", a.initPolicy); err != nil {
		return err
	}
	return nil
}

func (a *App) initPhase2a(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return runInitStep("cache", a.initCache) })
	g.Go(func() error { return runInitStep("ticketing", a.initTicketing) })
	g.Go(func() error { return runInitStep("identity", a.initIdentity) })
	g.Go(func() error { return runInitStep("attackpath", a.initAttackPath) })
	g.Go(func() error { return runInitStep("webhooks", a.initWebhooks) })
	g.Go(func() error { return runInitStep("notifications", a.initNotifications) })
	g.Go(func() error { return runInitStep("rbac", a.initRBAC) })
	g.Go(func() error { return runInitStep("compliance", a.initCompliance) })
	g.Go(func() error { return runInitStep("health", a.initHealth) })
	g.Go(func() error { return runInitStep("lineage", a.initLineage) })
	g.Go(func() error { return runInitStep("runtime", a.initRuntime) })
	g.Go(func() error { return runInitStep("findings", a.initFindings) })
	g.Go(func() error {
		return runInitStep("providers", func() { a.initProviders(gctx) })
	})
	g.Go(func() error {
		return runInitStep("scheduler", func() { a.initScheduler(gctx) })
	})
	g.Go(func() error { return runInitStep("repositories", a.initRepositories) })
	g.Go(func() error {
		return runInitStep("snowflake_findings", func() { a.initSnowflakeFindings(gctx) })
	})
	g.Go(func() error {
		return runInitStep("scan_watermarks", func() { a.initScanWatermarks(gctx) })
	})
	g.Go(func() error { return runInitStep("threatintel", func() { a.initThreatIntel(ctx) }) })
	g.Go(func() error {
		return runInitStep("available_tables", func() { a.initAvailableTables(gctx) })
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	return nil
}

func (a *App) initPhase2b(ctx context.Context) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error { return runInitStep("remediation", a.initRemediation) })
	g.Go(func() error { return runInitStep("agents", a.initAgents) })
	if err := g.Wait(); err != nil {
		return fmt.Errorf("phase 2b init failed: %w", err)
	}
	a.startEventRemediation(ctx)
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
