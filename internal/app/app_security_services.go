package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/actionengine"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graph/builders"
	reports "github.com/evalops/cerebro/internal/graph/reports"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/lineage"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (a *App) newSharedActionExecutor() *actionengine.Executor {
	if a != nil && a.ExecutionStore != nil {
		return actionengine.NewExecutor(actionengine.NewSQLiteStoreWithExecutionStore(a.ExecutionStore, actionengine.DefaultNamespace))
	}
	store, err := actionengine.NewSQLiteStore(a.Config.ExecutionStoreFile, actionengine.DefaultNamespace)
	if err != nil {
		a.Logger.Warn("failed to initialize shared action execution store; falling back to in-memory", "error", err, "path", a.Config.ExecutionStoreFile)
		return actionengine.NewExecutor(nil)
	}
	return actionengine.NewExecutor(store)
}

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
	syncCtx, syncCancel := context.WithCancel(backgroundWorkContext(ctx))
	a.threatIntelSyncCancel = syncCancel
	a.threatIntelSyncWG.Add(1)

	// Sync feeds in background
	go func() {
		defer a.threatIntelSyncWG.Done()
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

		runCtx, cancel := context.WithTimeout(syncCtx, syncTimeout)
		defer cancel()

		err := a.ThreatIntel.SyncAllWithRetry(runCtx, threatintel.SyncOptions{
			MaxAge:   syncMaxAge,
			Attempts: syncAttempts,
			Backoff:  syncBackoff,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || runCtx.Err() != nil {
				a.Logger.Debug("threat intel sync canceled", "error", err)
			} else {
				a.Logger.Warn("failed to sync threat intel feeds", "error", err)
			}
			return
		}
		stats := a.ThreatIntel.Stats()
		if a.Webhooks != nil {
			if err := a.Webhooks.EmitWithErrors(runCtx, webhooks.EventThreatIntelSynced, map[string]interface{}{
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
		if a.Warehouse == nil {
			return fmt.Errorf("not configured")
		}
		// Check that at least some tables have data
		tables, err := a.Warehouse.ListAvailableTables(ctx)
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
	a.Health.Register("graph_build", func(_ context.Context) health.CheckResult {
		start := time.Now().UTC()
		result := health.CheckResult{
			Name:      "graph_build",
			Timestamp: start,
		}
		if a.Warehouse == nil {
			result.Status = health.StatusHealthy
			result.Message = "graph disabled - warehouse not configured"
			result.Latency = time.Since(start)
			return result
		}
		snapshot := a.GraphBuildSnapshot()
		switch snapshot.State {
		case GraphBuildSuccess:
			result.Status = health.StatusHealthy
			result.Message = fmt.Sprintf("graph build succeeded at %s with %d nodes", snapshot.LastBuildAt.Format(time.RFC3339), snapshot.NodeCount)
		case GraphBuildFailed:
			result.Status = health.StatusUnhealthy
			result.Message = snapshot.LastError
		case GraphBuildBuilding:
			result.Status = health.StatusDegraded
			result.Message = "graph build in progress"
		default:
			result.Status = health.StatusUnknown
			result.Message = "graph build not started"
		}
		result.Latency = time.Since(start)
		return result
	})
	a.Health.Register("graph_freshness", func(_ context.Context) health.CheckResult {
		start := time.Now().UTC()
		result := health.CheckResult{
			Name:      "graph_freshness",
			Timestamp: start,
		}
		if a.CurrentSecurityGraph() == nil {
			result.Status = health.StatusUnknown
			result.Message = "graph not initialized"
			result.Latency = time.Since(start)
			return result
		}
		status := a.GraphFreshnessStatusSnapshot(start)
		if len(status.Breaches) == 0 {
			result.Status = health.StatusHealthy
			result.Message = "all providers within freshness SLA"
			result.Latency = time.Since(start)
			return result
		}
		parts := make([]string, 0, len(status.Breaches))
		for _, breach := range status.Breaches {
			parts = append(parts, fmt.Sprintf("%s %.0fs>%.0fs", breach.Provider, breach.LastSyncAgeSeconds, breach.StaleAfterSeconds))
			if len(parts) == 3 {
				break
			}
		}
		result.Status = health.StatusUnhealthy
		result.Message = "stale providers: " + strings.Join(parts, ", ")
		result.Latency = time.Since(start)
		return result
	})
	a.Health.Register("graph_persistence", func(_ context.Context) health.CheckResult {
		start := time.Now().UTC()
		result := health.CheckResult{
			Name:      "graph_persistence",
			Timestamp: start,
		}
		if a.Warehouse == nil {
			result.Status = health.StatusHealthy
			result.Message = "graph disabled - warehouse not configured"
			result.Latency = time.Since(start)
			return result
		}
		if a.GraphSnapshots == nil {
			result.Status = health.StatusDegraded
			result.Message = "graph persistence store not configured"
			result.Latency = time.Since(start)
			return result
		}
		status := a.GraphSnapshots.Status()
		switch {
		case status.ReplicaConfigured && status.LastReplicationError != "":
			result.Status = health.StatusDegraded
			result.Message = "local snapshot persistence healthy; replica sync failing"
		case status.ReplicaConfigured && status.LastReplicatedSnapshot == "":
			records, err := a.GraphSnapshots.ListGraphSnapshotRecords()
			switch {
			case err == nil && len(records) > 0:
				result.Status = health.StatusHealthy
				result.Message = "replicated snapshot persistence active"
			default:
				result.Status = health.StatusDegraded
				result.Message = "replica configured but not seeded yet"
			}
		default:
			result.Status = health.StatusHealthy
			message := "local snapshot persistence active"
			if status.ReplicaConfigured {
				message = "replicated snapshot persistence active"
			}
			if status.LastRecoverySource != "" {
				message += " (last recovery: " + status.LastRecoverySource + ")"
			}
			result.Message = message
		}
		result.Latency = time.Since(start)
		return result
	})

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

		if a == nil {
			result.Status = health.StatusUnknown
			result.Message = "security graph not initialized"
			result.Latency = time.Since(start)
			return result
		}
		securityGraph := a.CurrentSecurityGraph()
		if securityGraph == nil {
			result.Status = health.StatusUnknown
			result.Message = "security graph not initialized"
			result.Latency = time.Since(start)
			return result
		}

		thresholds := a.graphOntologySLOThresholds()
		slo := reports.BuildGraphOntologySLO(securityGraph, time.Now().UTC(), 7)
		status, message := evaluateGraphOntologySLOStatus(slo, thresholds)
		result.Status = status
		result.Message = message
		result.Latency = time.Since(start)
		return result
	}
}

func evaluateGraphOntologySLOStatus(slo reports.GraphOntologySLO, thresholds graphOntologySLOThresholds) (health.Status, string) {
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

func burnRatesForHigherIsWorse(current, warn, critical float64, trend []reports.GraphOntologySLOPoint) (float64, float64) {
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

func burnRatesForLowerIsWorse(current, warn, critical float64, trend []reports.GraphOntologySLOPoint) (float64, float64) {
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
	a.RemediationExecutor.SetSharedExecutor(a.newSharedActionExecutor())
	if a.RemoteTools != nil {
		a.RemediationExecutor.SetRemoteCaller(a.RemoteTools)
	}
	a.Logger.Info("remediation engine initialized", "rules", len(a.Remediation.ListRules()))
}

func (a *App) initRuntime() {
	a.RuntimeDetect = runtime.NewDetectionEngine()
	a.RuntimeRespond = runtime.NewResponseEngine()
	a.RuntimeRespond.SetSharedExecutor(a.newSharedActionExecutor())
	a.RuntimeRespond.SetActionHandler(runtime.NewDefaultActionHandler(runtime.DefaultActionHandlerOptions{
		Blocklist:    a.RuntimeRespond.Blocklist(),
		RemoteCaller: a.RemoteTools,
	}))
	a.Logger.Info("runtime detection initialized", "rules", len(a.RuntimeDetect.ListRules()))
	a.Logger.Info("runtime response initialized", "policies", len(a.RuntimeRespond.ListPolicies()))
}

func (a *App) initSecurityGraph(ctx context.Context) {
	a.graphReady = make(chan struct{})
	a.setGraphBuildState(GraphBuildNotStarted, time.Time{}, nil)

	if a.Warehouse == nil {
		a.Logger.Warn("security graph disabled - warehouse not configured")
		a.Propagation = nil
		a.graphCancel = nil
		close(a.graphReady)
		return
	}

	source := builders.NewSnowflakeSource(a.Warehouse)
	a.SecurityGraphBuilder = builders.NewBuilder(source, a.Logger)
	securityGraph := a.SecurityGraphBuilder.Graph()
	a.configureGraphSchemaValidation(securityGraph)
	a.setSecurityGraph(securityGraph)
	if a.GraphSnapshots != nil {
		recovered, record, recoverySource, err := a.GraphSnapshots.LoadLatestSnapshot()
		if err != nil {
			a.Logger.Warn("failed to recover persisted security graph snapshot", "error", err)
		} else if recovered != nil {
			recoveredGraph := graph.RestoreFromSnapshot(recovered)
			a.configureGraphSchemaValidation(recoveredGraph)
			a.setSecurityGraph(recoveredGraph)
			if record != nil && record.BuiltAt != nil {
				a.setGraphBuildState(GraphBuildSuccess, record.BuiltAt.UTC(), nil)
			}
			a.Logger.Info("recovered persisted security graph snapshot",
				"source", recoverySource,
				"snapshot_id", recordID(record),
				"nodes", recoveredGraph.NodeCount(),
				"edges", recoveredGraph.EdgeCount(),
			)
		}
	}

	graphCtx, cancel := context.WithCancel(backgroundWorkContext(ctx))
	a.graphCtx = graphCtx
	a.graphCancel = cancel
	a.setGraphBuildState(GraphBuildBuilding, time.Time{}, nil)

	// Build initial graph in background
	go func() {
		defer close(a.graphReady)
		a.graphUpdateMu.Lock()
		defer a.graphUpdateMu.Unlock()

		if err := a.SecurityGraphBuilder.Build(graphCtx); err != nil {
			a.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), err)
			a.Logger.Error("failed to build security graph", "error", err)
			return
		}
		builtGraph := a.SecurityGraphBuilder.Graph()
		meta, err := a.activateBuiltSecurityGraph(graphCtx, builtGraph)
		if err != nil {
			a.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), err)
			a.Logger.Error("failed to activate security graph", "error", err)
			return
		}
		a.Logger.Info("security graph built",
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", meta.BuildDuration,
		)
		if a.Config != nil && a.Config.GraphMigrateLegacyActivityOnStart {
			migration := graph.MigrateLegacyActivityNodes(builtGraph, graph.LegacyActivityMigrationOptions{Now: time.Now().UTC()})
			if migration.Migrated > 0 || migration.Scanned > 0 {
				a.Logger.Info("migrated legacy activity nodes",
					"scanned", migration.Scanned,
					"migrated", migration.Migrated,
					"marked_for_review", migration.MarkedForReview,
					"migrated_by_kind", migration.MigratedByKind,
				)
			}
		}

		emitCtx := graphCtx
		a.emitGraphRebuiltEvent(emitCtx, meta, meta.BuildDuration)
		a.emitGraphMutationEvent(emitCtx, a.SecurityGraphBuilder.LastMutation(), "startup")
	}()
}

func backgroundWorkContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
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
		securityGraph := a.CurrentSecurityGraph()
		return securityGraph != nil && securityGraph.NodeCount() > 0
	case <-ctx.Done():
		return false
	}
}

// RebuildSecurityGraph triggers a rebuild of the security graph

func (a *App) RebuildSecurityGraph(ctx context.Context) error {
	if a.SecurityGraphBuilder == nil {
		return fmt.Errorf("security graph not initialized")
	}

	a.graphUpdateMu.Lock()
	defer a.graphUpdateMu.Unlock()

	start := time.Now()
	a.setGraphBuildState(GraphBuildBuilding, time.Time{}, nil)
	if err := a.SecurityGraphBuilder.Build(ctx); err != nil {
		a.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), err)
		return err
	}

	securityGraph := a.SecurityGraphBuilder.Graph()
	meta, err := a.activateBuiltSecurityGraph(ctx, securityGraph)
	if err != nil {
		return err
	}
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

func (a *App) activateBuiltSecurityGraph(ctx context.Context, securityGraph *graph.Graph) (graph.Metadata, error) {
	if securityGraph == nil {
		err := fmt.Errorf("security graph not initialized")
		a.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), err)
		return graph.Metadata{}, err
	}
	if materialized, err := a.materializePersistedWorkloadScans(ctx, securityGraph); err != nil {
		a.Logger.Warn("failed to materialize persisted workload scans into security graph", "error", err)
	} else if materialized.RunsMaterialized > 0 {
		a.Logger.Info("materialized workload scans into security graph",
			"runs", materialized.RunsMaterialized,
			"scan_nodes", materialized.ScanNodesUpserted,
			"package_nodes", materialized.PackageNodesUpserted,
			"vulnerability_nodes", materialized.VulnNodesUpserted,
			"scan_package_edges", materialized.ScanPackageEdges,
			"scan_vulnerability_edges", materialized.ScanVulnEdges,
			"package_vulnerability_edges", materialized.PackageVulnEdges,
		)
	}
	a.rematerializeEventCorrelations(securityGraph, "graph_activation")
	a.configureGraphSchemaValidation(securityGraph)
	a.setSecurityGraph(securityGraph)
	if a.GraphSnapshots != nil {
		if record, err := a.GraphSnapshots.SaveGraph(securityGraph); err != nil {
			if record != nil {
				a.Logger.Warn("replicated security graph snapshot failed after local persist", "snapshot_id", record.ID, "error", err)
			} else {
				a.Logger.Warn("failed to persist security graph snapshot", "error", err)
			}
		} else if record != nil {
			a.Logger.Info("persisted security graph snapshot", "snapshot_id", record.ID)
		}
	}
	meta := securityGraph.Metadata()
	a.setGraphBuildState(GraphBuildSuccess, meta.BuiltAt, nil)
	return meta, nil
}

func recordID(record *graph.GraphSnapshotRecord) string {
	if record == nil {
		return ""
	}
	return record.ID
}

func (a *App) rematerializeEventCorrelations(securityGraph *graph.Graph, reason string) {
	if securityGraph == nil {
		return
	}
	summary := graph.MaterializeEventCorrelations(securityGraph, time.Now().UTC())
	if a == nil || a.Logger == nil {
		return
	}
	if summary.CorrelationsCreated == 0 && summary.CorrelationsRemoved == 0 {
		return
	}
	a.Logger.Info("materialized event correlations into security graph",
		"reason", strings.TrimSpace(reason),
		"patterns", summary.PatternsEvaluated,
		"created", summary.CorrelationsCreated,
		"removed", summary.CorrelationsRemoved,
	)
}

func (a *App) initEventCorrelationRefreshLoop(ctx context.Context) {
	if a == nil || a.eventCorrelationRefreshCh != nil {
		return
	}
	loopCtx, cancel := context.WithCancel(ctx) // #nosec G118 -- cancel is stored on App and invoked by stopEventCorrelationRefreshLoop during shutdown.
	a.eventCorrelationRefreshCh = make(chan string, 1)
	a.eventCorrelationRefreshCancel = cancel
	a.eventCorrelationRefreshWG.Add(1)
	go func() {
		defer a.eventCorrelationRefreshWG.Done()
		const debounce = 2 * time.Second
		pendingReasons := make(map[string]struct{})
		var (
			timer   *time.Timer
			timerCh <-chan time.Time
		)
		flush := func() {
			if len(pendingReasons) == 0 {
				return
			}
			reasons := make([]string, 0, len(pendingReasons))
			for reason := range pendingReasons {
				reasons = append(reasons, reason)
			}
			sort.Strings(reasons)
			pendingReasons = make(map[string]struct{})
			a.refreshCurrentEventCorrelations(strings.Join(reasons, ","))
		}
		for {
			select {
			case <-loopCtx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case reason := <-a.eventCorrelationRefreshCh:
				reason = strings.TrimSpace(reason)
				if reason == "" {
					reason = "tap_mapping"
				}
				pendingReasons[reason] = struct{}{}
				if timer == nil {
					timer = time.NewTimer(debounce)
					timerCh = timer.C
					continue
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounce)
			case <-timerCh:
				timerCh = nil
				if timer != nil {
					timer.Stop()
					timer = nil
				}
				flush()
			}
		}
	}()
}

func (a *App) queueEventCorrelationRefresh(reason string) {
	if a == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "tap_mapping"
	}
	if a.eventCorrelationRefreshCh == nil {
		a.refreshCurrentEventCorrelations(reason)
		return
	}
	select {
	case a.eventCorrelationRefreshCh <- reason:
	default:
	}
}

func (a *App) stopEventCorrelationRefreshLoop() {
	if a == nil {
		return
	}
	if a.eventCorrelationRefreshCancel != nil {
		a.eventCorrelationRefreshCancel()
	}
	done := make(chan struct{})
	go func() {
		a.eventCorrelationRefreshWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(appShutdownTimeout):
		if a.Logger != nil {
			a.Logger.Warn("timed out waiting for event correlation refresh loop to stop", "timeout", appShutdownTimeout)
		}
	}
	a.eventCorrelationRefreshCh = nil
	a.eventCorrelationRefreshCancel = nil
}

func (a *App) refreshCurrentEventCorrelations(reason string) {
	if a == nil {
		return
	}
	baseCtx := a.graphCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	var summary graph.EventCorrelationMaterializationSummary
	_, err := a.MutateSecurityGraphMaybe(baseCtx, func(candidate *graph.Graph) (bool, error) {
		summary = graph.MaterializeEventCorrelations(candidate, time.Now().UTC())
		return summary.CorrelationsCreated > 0 || summary.CorrelationsRemoved > 0, nil
	})
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to refresh event correlations on live graph", "reason", strings.TrimSpace(reason), "error", err)
		}
		return
	}
	if a.Logger == nil {
		return
	}
	if summary.CorrelationsCreated == 0 && summary.CorrelationsRemoved == 0 {
		return
	}
	a.Logger.Info("materialized event correlations into security graph",
		"reason", strings.TrimSpace(reason),
		"patterns", summary.PatternsEvaluated,
		"created", summary.CorrelationsCreated,
		"removed", summary.CorrelationsRemoved,
	)
}

func shouldRefreshEventCorrelations(securityGraph *graph.Graph, nodeIDs []string) bool {
	if securityGraph == nil || len(nodeIDs) == 0 {
		return false
	}
	for _, nodeID := range nodeIDs {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}
		node, ok := securityGraph.GetNode(nodeID)
		if !ok || node == nil {
			continue
		}
		if graph.IsEventCorrelationNodeKind(node.Kind) {
			return true
		}
	}
	return false
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
