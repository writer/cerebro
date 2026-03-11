package app

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/snowflake"
)

var appShutdownTimeout = 30 * time.Second

func (a *App) initRepositories() {
	a.FindingsRepo = nil
	a.TicketsRepo = nil
	a.AuditRepo = nil
	a.PolicyHistoryRepo = nil
	a.RiskEngineStateRepo = nil
	a.RetentionRepo = nil

	if a.Snowflake == nil {
		return
	}
	a.FindingsRepo = snowflake.NewFindingRepository(a.Snowflake)
	a.TicketsRepo = snowflake.NewTicketRepository(a.Snowflake)
	a.AuditRepo = snowflake.NewAuditRepository(a.Snowflake)
	a.PolicyHistoryRepo = snowflake.NewPolicyHistoryRepository(a.Snowflake)
	a.RiskEngineStateRepo = snowflake.NewRiskEngineStateRepository(a.Snowflake)
	a.RetentionRepo = snowflake.NewRetentionRepository(a.Snowflake)
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
	if a.Snowflake != nil {
		a.ScanWatermarks = scanner.NewWatermarkStore(a.Snowflake.DB())
		if err := a.ScanWatermarks.LoadWatermarks(ctx); err != nil {
			a.Logger.Warn("failed to load scan watermarks", "error", err)
		}
	} else {
		a.ScanWatermarks = scanner.NewWatermarkStore(nil)
	}
	a.Logger.Info("scan watermarks initialized")
}

// initAvailableTables caches the Snowflake table list for reuse by graph builder and policy validation.

func (a *App) initAvailableTables(ctx context.Context) {
	if a.Snowflake == nil {
		return
	}
	tables, err := a.Snowflake.ListAvailableTables(ctx)
	if err != nil {
		a.Logger.Warn("failed to list available tables", "error", err)
		return
	}
	a.AvailableTables = tables
}

// validatePolicyCoverage checks that required tables exist for loaded policies

func (a *App) validatePolicyCoverage(_ context.Context) error {
	if a.Snowflake == nil {
		a.Logger.Warn("skipping policy coverage validation - Snowflake not configured")
		return nil
	}

	if a.AvailableTables == nil {
		a.Logger.Warn("skipping policy coverage validation - table list not available")
		return nil
	}

	report := a.Policy.CoverageReport(a.AvailableTables)
	orphanTables := policy.GlobalMappingRegistry().OrphanNativeTables(a.AvailableTables)
	if report.TotalPolicies == 0 {
		if len(orphanTables) == 0 {
			return nil
		}
	}

	threshold, coverageThresholdSet, err := policy.CoverageThresholdFromEnv()
	if err != nil {
		a.Logger.Warn("invalid policy coverage threshold", "error", err)
		return nil
	}
	coverageBelowThreshold := coverageThresholdSet && report.CoveragePercent < threshold

	orphanThreshold, orphanThresholdSet, err := policy.OrphanTableThresholdFromEnv()
	if err != nil {
		a.Logger.Warn("invalid policy orphan-table threshold", "error", err)
		return nil
	}
	orphanAboveThreshold := orphanThresholdSet && len(orphanTables) > orphanThreshold

	if len(report.Gaps) == 0 && report.UnknownResourcePolicies == 0 {
		a.Logger.Info("all policies have required tables available",
			"coverage_percent", fmt.Sprintf("%.1f%%", report.CoveragePercent))
	} else {
		missingTables := topMissingTables(report.MissingTables, 5)
		logCoverage := a.Logger.Info
		msg := "policy coverage summary"
		if coverageBelowThreshold {
			logCoverage = a.Logger.Warn
			msg = "policy coverage incomplete"
		}
		logCoverage(msg,
			"total_policies", report.TotalPolicies,
			"covered_policies", report.CoveredPolicies,
			"uncovered_policies", report.UncoveredPolicies,
			"unknown_resource_policies", report.UnknownResourcePolicies,
			"coverage_percent", fmt.Sprintf("%.1f%%", report.CoveragePercent),
			"known_coverage_percent", fmt.Sprintf("%.1f%%", report.KnownCoveragePercent),
			"missing_tables", missingTables,
			"missing_by_provider", report.MissingByProvider,
			"threshold_applied", coverageThresholdSet,
		)
	}

	if len(orphanTables) > 0 {
		logOrphans := a.Logger.Info
		if orphanAboveThreshold {
			logOrphans = a.Logger.Warn
		}
		logOrphans("native table mapping coverage summary",
			"orphan_table_count", len(orphanTables),
			"orphan_tables_sample", topStrings(orphanTables, 10),
			"threshold_applied", orphanThresholdSet,
		)
	}
	if coverageBelowThreshold {
		return fmt.Errorf("policy coverage %.1f%% below threshold %.1f%%", report.CoveragePercent, threshold)
	}
	if orphanAboveThreshold {
		return fmt.Errorf("orphan native tables %d exceed threshold %d", len(orphanTables), orphanThreshold)
	}
	return nil
}

func topMissingTables(counts map[string]int, limit int) []string {
	if limit <= 0 || len(counts) == 0 {
		return nil
	}
	type entry struct {
		table string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for table, count := range counts {
		entries = append(entries, entry{table: table, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].table < entries[j].table
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, fmt.Sprintf("%s (%d)", entry.table, entry.count))
	}
	return result
}

func topStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

// Close cleanly shuts down all services

func (a *App) Close() error {
	var errs []error

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), appShutdownTimeout)
	defer shutdownCancel()

	// Sync findings store to persist any pending changes
	if syncer, ok := a.Findings.(interface{ Sync(context.Context) error }); ok {
		if err := syncer.Sync(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("findings sync: %w", err))
		}
	}

	if a.TapConsumer != nil {
		drainTimeout := appShutdownTimeout
		if a.Config != nil && a.Config.NATSConsumerDrainTimeout > 0 {
			drainTimeout = a.Config.NATSConsumerDrainTimeout
		}
		// Drain gets its own phase budget so earlier shutdown work does not silently
		// shorten the configured consumer drain window.
		var (
			drainCtx    context.Context
			drainCancel context.CancelFunc
		)
		if drainTimeout <= 0 {
			drainCtx, drainCancel = context.WithCancel(context.Background())
		} else {
			drainCtx, drainCancel = context.WithTimeout(context.Background(), drainTimeout)
		}
		if err := a.TapConsumer.Drain(drainCtx); err != nil {
			errs = append(errs, fmt.Errorf("nats graph consumer drain: %w", err))
			if a.Logger != nil {
				a.Logger.Warn("timed out draining nats graph consumer before graph shutdown", "timeout", drainTimeout, "error", err)
			}
		}
		drainCancel()
	}

	if a.graphCancel != nil {
		a.graphCancel()
	}
	if a.graphReady != nil {
		graphWaitCtx, graphWaitCancel := context.WithTimeout(context.Background(), appShutdownTimeout)
		defer graphWaitCancel()
		select {
		case <-a.graphReady:
		case <-graphWaitCtx.Done():
			if a.Logger != nil {
				a.Logger.Warn("timed out waiting for security graph shutdown", "timeout", appShutdownTimeout, "error", graphWaitCtx.Err())
			}
		}
	}

	a.stopSecretsReloader()

	a.stopThreatIntelSync()

	// Close Snowflake connection
	if a.Snowflake != nil {
		if err := a.Snowflake.Close(); err != nil {
			errs = append(errs, fmt.Errorf("snowflake: %w", err))
		}
	}

	if a.TapConsumer != nil {
		if err := a.TapConsumer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("nats graph consumer: %w", err))
		}
	}

	if a.RemoteTools != nil {
		if err := a.RemoteTools.Close(); err != nil {
			errs = append(errs, fmt.Errorf("remote tool provider: %w", err))
		}
	}
	if a.ToolPublisher != nil {
		if err := a.ToolPublisher.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tool publisher: %w", err))
		}
	}
	if a.AlertRouter != nil {
		if err := a.AlertRouter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("alert router: %w", err))
		}
	}

	// Close findings store if it implements io.Closer (e.g., SQLiteStore)
	if closer, ok := a.Findings.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("findings store: %w", err))
		}
	}

	if a.Webhooks != nil {
		if err := a.Webhooks.Close(); err != nil {
			errs = append(errs, fmt.Errorf("webhooks: %w", err))
		}
	}

	// Stop scheduler if running
	if a.Scheduler != nil {
		a.Scheduler.Stop()
	}

	if a.traceShutdown != nil {
		if err := a.traceShutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("otel shutdown: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func (a *App) stopThreatIntelSync() {
	if a == nil {
		return
	}
	if a.threatIntelSyncCancel != nil {
		a.threatIntelSyncCancel()
	}
	a.threatIntelSyncWG.Wait()
}
