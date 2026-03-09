package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/lineage"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (a *App) initRBAC() {
	if a.Config.RBACStateFile == "" {
		a.RBAC = auth.NewRBAC()
		a.Logger.Info("rbac service initialized")
		return
	}

	rbac, err := auth.NewRBACWithStateFile(a.Config.RBACStateFile)
	if err != nil {
		a.Logger.Warn("failed to load rbac state file; falling back to in-memory", "error", err, "path", a.Config.RBACStateFile)
		a.RBAC = auth.NewRBAC()
		a.Logger.Info("rbac service initialized")
		return
	}

	a.RBAC = rbac
	a.Logger.Info("rbac service initialized", "state_file", a.Config.RBACStateFile)
}

func (a *App) initThreatIntel(ctx context.Context) {
	a.ThreatIntel = threatintel.NewThreatIntelService()

	// Sync feeds in background
	// #nosec G118 -- background threat intel sync is intentionally detached from request context
	go func() {
		const (
			syncTimeout  = 2 * time.Minute
			syncMaxAge   = 12 * time.Hour
			syncAttempts = 3
			syncBackoff  = 5 * time.Second
		)
		if !a.ThreatIntel.ShouldSync(syncMaxAge) {
			stats := a.ThreatIntel.Stats()
			a.Logger.Info("threat intel feeds fresh", "last_updated", stats["last_updated"])
			return
		}

		syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
		defer cancel()

		err := a.ThreatIntel.SyncAllWithRetry(syncCtx, threatintel.SyncOptions{
			MaxAge:   syncMaxAge,
			Attempts: syncAttempts,
			Backoff:  syncBackoff,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || syncCtx.Err() != nil {
				a.Logger.Debug("threat intel sync canceled", "error", err)
			} else {
				a.Logger.Warn("failed to sync threat intel feeds", "error", err)
			}
			return
		}
		stats := a.ThreatIntel.Stats()
		if a.Webhooks != nil {
			if err := a.Webhooks.EmitWithErrors(syncCtx, webhooks.EventThreatIntelSynced, map[string]interface{}{
				"feed_count":       stats["feed_count"],
				"total_indicators": stats["total_indicators"],
			}); err != nil {
				a.Logger.Warn("failed to emit threat intel synced event", "error", err)
			}
		}
		a.Logger.Info("threat intel feeds synced", "indicators", stats["total_indicators"])
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

	a.Health.Register("sync_data", health.PingCheck("sync_data", func(ctx context.Context) error {
		if a.Snowflake == nil {
			return fmt.Errorf("not configured")
		}
		// Check that at least some tables have data
		tables, err := a.Snowflake.ListAvailableTables(ctx)
		if err != nil {
			return fmt.Errorf("cannot list tables: %w", err)
		}
		if len(tables) == 0 {
			return fmt.Errorf("no synced tables found - sync may be needed")
		}
		return nil
	}))

	a.Health.Register("event_publisher", health.PingCheck("event_publisher", func(ctx context.Context) error {
		if !a.Config.NATSJetStreamEnabled {
			return nil
		}
		if a.Webhooks == nil {
			return fmt.Errorf("webhook service not initialized")
		}
		if err := a.Webhooks.EventPublisherReady(ctx); err != nil {
			return fmt.Errorf("jetstream publisher not ready: %w", err)
		}
		return nil
	}))

	a.Health.Register("providers", health.PingCheck("providers", func(ctx context.Context) error {
		if a.Providers == nil {
			return fmt.Errorf("provider registry not initialized")
		}
		for _, provider := range a.Providers.List() {
			if err := provider.Test(ctx); err != nil {
				return fmt.Errorf("provider %s test failed: %w", provider.Name(), err)
			}
		}
		return nil
	}))

	a.Health.Register("graph_ontology_slo", a.graphOntologySLOHealthCheck())

	a.Logger.Info("health service initialized")
}

type graphOntologySLOThresholds struct {
	FallbackWarn        float64
	FallbackCritical    float64
	SchemaValidWarn     float64
	SchemaValidCritical float64
}

const (
	ontologyBurnFastWarn     = 1.0
	ontologyBurnFastCritical = 2.0
	ontologyBurnSlowWarn     = 0.5
	ontologyBurnSlowCritical = 1.0
)

func defaultGraphOntologySLOThresholds() graphOntologySLOThresholds {
	return graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}
}

func sanitizeGraphOntologySLOThresholds(raw graphOntologySLOThresholds) graphOntologySLOThresholds {
	defaults := defaultGraphOntologySLOThresholds()
	out := raw

	if out.FallbackWarn < 0 || out.FallbackWarn > 100 || out.FallbackWarn != out.FallbackWarn {
		out.FallbackWarn = defaults.FallbackWarn
	}
	if out.FallbackCritical < 0 || out.FallbackCritical > 100 || out.FallbackCritical != out.FallbackCritical {
		out.FallbackCritical = defaults.FallbackCritical
	}
	if out.FallbackCritical < out.FallbackWarn {
		out.FallbackCritical = out.FallbackWarn
	}

	if out.SchemaValidWarn < 0 || out.SchemaValidWarn > 100 || out.SchemaValidWarn != out.SchemaValidWarn {
		out.SchemaValidWarn = defaults.SchemaValidWarn
	}
	if out.SchemaValidCritical < 0 || out.SchemaValidCritical > 100 || out.SchemaValidCritical != out.SchemaValidCritical {
		out.SchemaValidCritical = defaults.SchemaValidCritical
	}
	if out.SchemaValidCritical > out.SchemaValidWarn {
		out.SchemaValidCritical = out.SchemaValidWarn
	}
	return out
}

func (a *App) graphOntologySLOThresholds() graphOntologySLOThresholds {
	if a == nil || a.Config == nil {
		return defaultGraphOntologySLOThresholds()
	}
	return sanitizeGraphOntologySLOThresholds(graphOntologySLOThresholds{
		FallbackWarn:        a.Config.GraphOntologyFallbackWarnPct,
		FallbackCritical:    a.Config.GraphOntologyFallbackCriticalPct,
		SchemaValidWarn:     a.Config.GraphOntologySchemaValidWarnPct,
		SchemaValidCritical: a.Config.GraphOntologySchemaValidCriticalPct,
	})
}

func (a *App) graphOntologySLOHealthCheck() health.Checker {
	return func(_ context.Context) health.CheckResult {
		start := time.Now()
		result := health.CheckResult{
			Name:      "graph_ontology_slo",
			Timestamp: start,
		}

		if a == nil || a.SecurityGraph == nil {
			result.Status = health.StatusUnknown
			result.Message = "security graph not initialized"
			result.Latency = time.Since(start)
			return result
		}

		thresholds := a.graphOntologySLOThresholds()
		slo := graph.BuildGraphOntologySLO(a.SecurityGraph, time.Now().UTC(), 7)
		status, message := evaluateGraphOntologySLOStatus(slo, thresholds)
		result.Status = status
		result.Message = message
		result.Latency = time.Since(start)
		return result
	}
}

func evaluateGraphOntologySLOStatus(slo graph.GraphOntologySLO, thresholds graphOntologySLOThresholds) (health.Status, string) {
	status := health.StatusHealthy
	issues := make([]string, 0, 4)

	if slo.FallbackActivityPercent >= thresholds.FallbackCritical {
		status = health.StatusUnhealthy
		issues = append(issues, fmt.Sprintf("fallback_activity_percent %.1f >= critical %.1f", slo.FallbackActivityPercent, thresholds.FallbackCritical))
	} else if slo.FallbackActivityPercent >= thresholds.FallbackWarn {
		status = health.StatusDegraded
		issues = append(issues, fmt.Sprintf("fallback_activity_percent %.1f >= warn %.1f", slo.FallbackActivityPercent, thresholds.FallbackWarn))
	}

	if slo.SchemaValidWritePercent <= thresholds.SchemaValidCritical {
		status = health.StatusUnhealthy
		issues = append(issues, fmt.Sprintf("schema_valid_write_percent %.1f <= critical %.1f", slo.SchemaValidWritePercent, thresholds.SchemaValidCritical))
	} else if slo.SchemaValidWritePercent <= thresholds.SchemaValidWarn {
		if status != health.StatusUnhealthy {
			status = health.StatusDegraded
		}
		issues = append(issues, fmt.Sprintf("schema_valid_write_percent %.1f <= warn %.1f", slo.SchemaValidWritePercent, thresholds.SchemaValidWarn))
	}

	fallbackBurnFast, fallbackBurnSlow := burnRatesForHigherIsWorse(slo.FallbackActivityPercent, thresholds.FallbackWarn, thresholds.FallbackCritical, slo.Trend)
	schemaBurnFast, schemaBurnSlow := burnRatesForLowerIsWorse(slo.SchemaValidWritePercent, thresholds.SchemaValidWarn, thresholds.SchemaValidCritical, slo.Trend)
	if fallbackBurnFast >= ontologyBurnFastCritical || fallbackBurnSlow >= ontologyBurnSlowCritical {
		status = health.StatusUnhealthy
		issues = append(issues, fmt.Sprintf("fallback_activity_burn_rate fast=%.2fx slow=%.2fx", fallbackBurnFast, fallbackBurnSlow))
	} else if fallbackBurnFast >= ontologyBurnFastWarn || fallbackBurnSlow >= ontologyBurnSlowWarn {
		if status != health.StatusUnhealthy {
			status = health.StatusDegraded
		}
		issues = append(issues, fmt.Sprintf("fallback_activity_burn_rate fast=%.2fx slow=%.2fx", fallbackBurnFast, fallbackBurnSlow))
	}
	if schemaBurnFast >= ontologyBurnFastCritical || schemaBurnSlow >= ontologyBurnSlowCritical {
		status = health.StatusUnhealthy
		issues = append(issues, fmt.Sprintf("schema_valid_burn_rate fast=%.2fx slow=%.2fx", schemaBurnFast, schemaBurnSlow))
	} else if schemaBurnFast >= ontologyBurnFastWarn || schemaBurnSlow >= ontologyBurnSlowWarn {
		if status != health.StatusUnhealthy {
			status = health.StatusDegraded
		}
		issues = append(issues, fmt.Sprintf("schema_valid_burn_rate fast=%.2fx slow=%.2fx", schemaBurnFast, schemaBurnSlow))
	}

	if len(issues) == 0 {
		return health.StatusHealthy, fmt.Sprintf("fallback_activity_percent %.1f, schema_valid_write_percent %.1f", slo.FallbackActivityPercent, slo.SchemaValidWritePercent)
	}
	return status, strings.Join(issues, "; ")
}

func burnRatesForHigherIsWorse(current, warn, critical float64, trend []graph.GraphOntologySLOPoint) (float64, float64) {
	budget := critical - warn
	if budget <= 0 {
		return 0, 0
	}
	fastValue := current
	slowValue := current
	if len(trend) > 0 {
		sum := 0.0
		count := 0
		for _, point := range trend {
			if point.Samples <= 0 {
				continue
			}
			sum += point.FallbackActivityPercent
			count++
		}
		if count > 0 {
			slowValue = sum / float64(count)
		}
	}
	return positiveBurnRate(fastValue-warn, budget), positiveBurnRate(slowValue-warn, budget)
}

func burnRatesForLowerIsWorse(current, warn, critical float64, trend []graph.GraphOntologySLOPoint) (float64, float64) {
	budget := warn - critical
	if budget <= 0 {
		return 0, 0
	}
	fastValue := current
	slowValue := current
	if len(trend) > 0 {
		sum := 0.0
		count := 0
		for _, point := range trend {
			if point.Samples <= 0 {
				continue
			}
			sum += point.SchemaValidWritePercent
			count++
		}
		if count > 0 {
			slowValue = sum / float64(count)
		}
	}
	return positiveBurnRate(warn-fastValue, budget), positiveBurnRate(warn-slowValue, budget)
}

func positiveBurnRate(excess, budget float64) float64 {
	if budget <= 0 || excess <= 0 {
		return 0
	}
	return excess / budget
}

func (a *App) initLineage() {
	a.Lineage = lineage.NewLineageMapper()
	a.Logger.Info("lineage mapper initialized")
}

func (a *App) initRemediation() {
	a.Remediation = remediation.NewEngine(a.Logger)
	a.RemediationExecutor = remediation.NewExecutor(a.Remediation, a.Ticketing, a.Notifications, a.Findings, a.Webhooks)
	if a.RemoteTools != nil {
		a.RemediationExecutor.SetRemoteCaller(a.RemoteTools)
	}
	a.Logger.Info("remediation engine initialized", "rules", len(a.Remediation.ListRules()))
}

func (a *App) initRuntime() {
	a.RuntimeDetect = runtime.NewDetectionEngine()
	a.RuntimeRespond = runtime.NewResponseEngine()
	a.Logger.Info("runtime detection initialized", "rules", len(a.RuntimeDetect.ListRules()))
	a.Logger.Info("runtime response initialized", "policies", len(a.RuntimeRespond.ListPolicies()))
}

func (a *App) initSecurityGraph(ctx context.Context) {
	a.graphReady = make(chan struct{})

	if a.Snowflake == nil {
		a.Logger.Warn("security graph disabled - snowflake not configured")
		a.Propagation = nil
		a.graphCancel = nil
		close(a.graphReady)
		return
	}

	source := graph.NewSnowflakeSource(a.Snowflake)
	a.SecurityGraphBuilder = graph.NewBuilder(source, a.Logger)
	a.SecurityGraph = a.SecurityGraphBuilder.Graph()
	a.configureGraphSchemaValidation(a.SecurityGraph)
	a.Propagation = graph.NewPropagationEngine(a.SecurityGraph)

	graphCtx := ctx
	if graphCtx == nil {
		graphCtx = context.Background()
	}
	graphCtx, cancel := context.WithCancel(graphCtx)
	a.graphCancel = cancel

	// Build initial graph in background
	go func() {
		defer close(a.graphReady)

		if err := a.SecurityGraphBuilder.Build(graphCtx); err != nil {
			a.Logger.Error("failed to build security graph", "error", err)
			return
		}
		meta := a.SecurityGraph.Metadata()
		a.Logger.Info("security graph built",
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", meta.BuildDuration,
		)
		if a.Config != nil && a.Config.GraphMigrateLegacyActivityOnStart {
			migration := graph.MigrateLegacyActivityNodes(a.SecurityGraph, graph.LegacyActivityMigrationOptions{Now: time.Now().UTC()})
			if migration.Migrated > 0 || migration.Scanned > 0 {
				a.Logger.Info("migrated legacy activity nodes",
					"scanned", migration.Scanned,
					"migrated", migration.Migrated,
					"marked_for_review", migration.MarkedForReview,
					"migrated_by_kind", migration.MigratedByKind,
				)
			}
		}

		a.emitGraphRebuiltEvent(ctx, meta, meta.BuildDuration)
		a.emitGraphMutationEvent(ctx, a.SecurityGraphBuilder.LastMutation(), "startup")
	}()
}

func (a *App) configureGraphSchemaValidation(g *graph.Graph) {
	if g == nil {
		return
	}

	mode := graph.SchemaValidationWarn
	if a != nil && a.Config != nil {
		mode = graph.ParseSchemaValidationMode(a.Config.GraphSchemaValidationMode)
	}
	g.SetSchemaValidationMode(mode)
}

// WaitForGraph blocks until the initial graph build completes (or ctx is cancelled).
// Returns true if the graph is ready and has nodes, false otherwise.

func (a *App) WaitForGraph(ctx context.Context) bool {
	if a.graphReady == nil {
		return false
	}
	select {
	case <-a.graphReady:
		return a.SecurityGraph != nil && a.SecurityGraph.NodeCount() > 0
	case <-ctx.Done():
		return false
	}
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

	duration := time.Since(start)
	a.emitGraphRebuiltEvent(ctx, meta, duration)
	a.emitGraphMutationEvent(ctx, a.SecurityGraphBuilder.LastMutation(), "manual_rebuild")

	return nil
}

func (a *App) emitGraphRebuiltEvent(ctx context.Context, meta graph.Metadata, duration time.Duration) {
	if a.Webhooks == nil {
		return
	}
	if err := a.Webhooks.EmitWithErrors(ctx, webhooks.EventGraphRebuilt, map[string]interface{}{
		"nodes":          meta.NodeCount,
		"edges":          meta.EdgeCount,
		"build_duration": duration.String(),
		"duration_ms":    duration.Milliseconds(),
	}); err != nil {
		a.Logger.Warn("failed to emit graph rebuilt webhook", "error", err)
	}
}

func (a *App) emitGraphMutationEvent(ctx context.Context, summary graph.GraphMutationSummary, trigger string) {
	if a.Webhooks == nil {
		return
	}
	if err := a.Webhooks.EmitWithErrors(ctx, webhooks.EventGraphMutated, summary.Payload(trigger)); err != nil {
		a.Logger.Warn("failed to emit graph mutation event", "error", err)
	}
}

// normalizePrivateKey cleans up PEM-encoded private key strings that may have
// escaped newlines or extra whitespace from environment variable storage.
