package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	apicontract "github.com/evalops/cerebro/api"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
	reports "github.com/evalops/cerebro/internal/graph/reports"
	risk "github.com/evalops/cerebro/internal/graph/risk"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/identity"
	"github.com/evalops/cerebro/internal/metrics"
	cerebroruntime "github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/snowflake"
)

// Server is the fully wired API server
type Server struct {
	app                      *serverDependencies
	findingsCompliance       findingsComplianceService
	entitiesImpact           entitiesImpactService
	graphSimulation          graphSimulationService
	graphRisk                graphRiskService
	graphIntelligence        graphIntelligenceService
	graphWriteback           graphWritebackService
	agentSDKAdmin            agentSDKAdminService
	lineage                  lineageService
	orgAnalysis              orgAnalysisService
	platformExecutions       platformExecutionService
	platformKnowledge        platformKnowledgeService
	platformWorkloadScan     platformWorkloadScanService
	rbacAdmin                rbacAdminService
	remediationOperations    remediationOperationsService
	schedulerOperations      schedulerOperationsService
	syncHandlers             syncHandlerService
	ticketingOps             ticketingService
	threatRuntime            threatRuntimeService
	router                   *chi.Mux
	auditLogger              auditLogWriter
	rateLimiter              *RateLimiter
	riskEngineMu             sync.Mutex
	riskEngine               *risk.RiskEngine
	riskEngineSource         *graph.Graph
	riskEngineSnapshotKey    string
	crossTenantReplayMu      sync.Mutex
	crossTenantReplay        map[string]time.Time
	platformJobMu            sync.RWMutex
	platformJobWG            sync.WaitGroup
	platformJobs             map[string]*platformJob
	platformReportHandlers   map[string]http.HandlerFunc
	platformReportRunMu      sync.RWMutex
	platformReportRuns       map[string]*reports.ReportRun
	platformReportStore      *reports.ReportRunStore
	platformReportSaveMu     sync.Mutex
	platformReportStreamMu   sync.RWMutex
	platformReportStreams    map[string]map[chan platformReportStreamMessage]struct{}
	agentSDKMCPSessionMu     sync.RWMutex
	agentSDKMCPSessions      map[string]*agentSDKMCPSession
	agentSDKReportProgressMu sync.RWMutex
	agentSDKReportProgress   map[string]agentSDKReportProgressSubscription
}

type auditLogWriter interface {
	Log(ctx context.Context, entry *snowflake.AuditEntry) error
}

var runtimeNumGoroutine = goruntime.NumGoroutine

// NewServer creates a new server with all services wired
func NewServer(application *app.App) *Server {
	return NewServerWithDependencies(newServerDependenciesFromApp(application))
}

// NewServerWithDependencies creates a new server from an explicit dependency
// bundle. This keeps App as the composition root while allowing tests and
// future workers to construct only the services they actually need.
func NewServerWithDependencies(deps serverDependencies) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if deps.RuntimeIngest == nil && deps.ExecutionStore != nil {
		ingestStore, err := cerebroruntime.NewSQLiteIngestStoreWithExecutionStore(deps.ExecutionStore)
		if err != nil {
			deps.Logger.Warn("failed to initialize runtime ingest bloom fast path; using durable dedupe only", "error", err)
			ingestStore = cerebroruntime.NewSQLiteIngestStoreWithoutBloom(deps.ExecutionStore)
		}
		deps.RuntimeIngest = ingestStore
	}
	if adapter, ok := deps.graphRuntime.(*graphRuntimeAdapter); ok {
		adapter.deps = &deps
	}
	if deps.Identity == nil {
		deps.Identity = identity.NewService(
			identity.WithExecutionStore(deps.ExecutionStore),
			identity.WithGraphResolver(func(ctx context.Context) *graph.Graph {
				view, err := currentOrStoredTenantGraphView(ctx, &deps)
				if err != nil {
					return nil
				}
				return view
			}),
		)
	}
	platformKnowledge := deps.platformKnowledge
	if platformKnowledge == nil {
		platformKnowledge = newPlatformKnowledgeService(&deps)
	}
	rbacAdmin := deps.rbacAdmin
	if rbacAdmin == nil {
		rbacAdmin = newRBACAdminService(&deps)
	}
	agentSDKAdmin := deps.agentSDKAdmin
	if agentSDKAdmin == nil {
		agentSDKAdmin = newAgentSDKAdminService(&deps)
	}
	entitiesImpact := deps.entitiesImpact
	if entitiesImpact == nil {
		entitiesImpact = newEntitiesImpactService(&deps)
	}
	lineage := deps.lineage
	if lineage == nil {
		lineage = newLineageService(&deps)
	}
	remediationOperations := deps.remediationOperations
	if remediationOperations == nil {
		remediationOperations = newRemediationOperationsService(&deps)
	}
	schedulerOperations := deps.schedulerOperations
	if schedulerOperations == nil {
		schedulerOperations = newSchedulerOperationsService(&deps)
	}
	orgAnalysis := deps.orgAnalysis
	if orgAnalysis == nil {
		orgAnalysis = newOrgAnalysisService(&deps)
	}
	platformExecutions := deps.platformExecutions
	if platformExecutions == nil {
		platformExecutions = newPlatformExecutionService(&deps)
	}
	platformWorkloadScan := deps.platformWorkloadScan
	if platformWorkloadScan == nil {
		platformWorkloadScan = newPlatformWorkloadScanService(&deps)
	}
	graphSimulation := deps.graphSimulation
	if graphSimulation == nil {
		graphSimulation = newGraphSimulationService(&deps)
	}
	ticketingOps := deps.ticketingOps
	if ticketingOps == nil {
		ticketingOps = newTicketingService(&deps)
	}
	threatRuntime := deps.threatRuntime
	if threatRuntime == nil {
		threatRuntime = newThreatRuntimeService(&deps)
	}
	syncHandlers := deps.syncHandlers
	if syncHandlers == nil {
		syncHandlers = newSyncHandlerService(&deps)
	}
	graphWriteback := deps.graphWriteback
	s := &Server{
		app:                    &deps,
		agentSDKAdmin:          agentSDKAdmin,
		entitiesImpact:         entitiesImpact,
		findingsCompliance:     newFindingsComplianceService(&deps),
		graphSimulation:        graphSimulation,
		graphIntelligence:      newGraphIntelligenceService(&deps),
		lineage:                lineage,
		orgAnalysis:            orgAnalysis,
		platformExecutions:     platformExecutions,
		platformKnowledge:      platformKnowledge,
		platformWorkloadScan:   platformWorkloadScan,
		rbacAdmin:              rbacAdmin,
		remediationOperations:  remediationOperations,
		schedulerOperations:    schedulerOperations,
		syncHandlers:           syncHandlers,
		ticketingOps:           ticketingOps,
		threatRuntime:          threatRuntime,
		router:                 chi.NewRouter(),
		auditLogger:            deps.AuditRepo,
		crossTenantReplay:      make(map[string]time.Time),
		platformJobs:           make(map[string]*platformJob),
		platformReportHandlers: make(map[string]http.HandlerFunc),
		platformReportRuns:     make(map[string]*reports.ReportRun),
		platformReportStreams:  make(map[string]map[chan platformReportStreamMessage]struct{}),
		agentSDKMCPSessions:    make(map[string]*agentSDKMCPSession),
		agentSDKReportProgress: make(map[string]agentSDKReportProgressSubscription),
	}
	s.graphRisk = newGraphRiskService(s, &deps)
	if graphWriteback == nil {
		graphWriteback = newGraphWritebackService(s, &deps)
	}
	s.graphWriteback = graphWriteback
	if cfg := deps.Config; cfg != nil {
		var (
			store *reports.ReportRunStore
			err   error
		)
		if deps.ExecutionStore != nil {
			store = reports.NewReportRunStoreWithExecutionStore(deps.ExecutionStore, cfg.ExecutionStoreFile, cfg.PlatformReportSnapshotPath, cfg.PlatformReportRunStateFile)
		} else {
			store, err = reports.NewReportRunStore(cfg.ExecutionStoreFile, cfg.PlatformReportSnapshotPath, cfg.PlatformReportRunStateFile)
		}
		if err != nil {
			if deps.Logger != nil {
				deps.Logger.Warn("failed to initialize shared platform report execution store", "execution_store", cfg.ExecutionStoreFile, "legacy_state_file", cfg.PlatformReportRunStateFile, "snapshot_dir", cfg.PlatformReportSnapshotPath, "error", err)
			}
		} else if store != nil {
			s.platformReportStore = store
			if restoredRuns, err := s.platformReportStore.Load(); err != nil {
				if deps.Logger != nil {
					deps.Logger.Warn("failed to load persisted platform report runs", "execution_store", s.platformReportStore.StateFile(), "legacy_state_file", s.platformReportStore.LegacyStateFile(), "snapshot_dir", s.platformReportStore.SnapshotDir(), "error", err)
				}
			} else {
				s.platformReportRuns = restoredRuns
			}
		}
	}
	s.platformReportHandlers = map[string]http.HandlerFunc{
		"insights":           s.graphIntelligenceInsights,
		"quality":            s.graphIntelligenceQuality,
		"metadata-quality":   s.graphIntelligenceMetadataQuality,
		"claim-conflicts":    s.graphIntelligenceClaimConflicts,
		"entity-summary":     s.graphIntelligenceEntitySummary,
		"leverage":           s.graphIntelligenceLeverage,
		"calibration-weekly": s.graphIntelligenceWeeklyCalibration,
	}
	s.setupMiddleware()
	s.setupRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Close() {
	if s == nil {
		return
	}
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	jobIDs := make([]string, 0)
	s.platformJobMu.RLock()
	for jobID, job := range s.platformJobs {
		if job == nil {
			continue
		}
		switch job.Status {
		case "succeeded", "failed", "canceled":
			continue
		default:
			jobIDs = append(jobIDs, jobID)
		}
	}
	s.platformJobMu.RUnlock()
	for _, jobID := range jobIDs {
		s.cancelPlatformJob(jobID, "server shutdown")
	}
	s.platformJobWG.Wait()
	if s.platformReportStore != nil {
		_ = s.platformReportStore.Close()
	}
}

func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.app.Config.Port)
	s.app.Logger.Info("starting server", "addr", addr)
	defer s.Close()

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

// Health endpoints

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	liveness := health.NewRegistry()
	liveness.Register("goroutines", health.ThresholdCheck(
		"goroutines",
		func() (float64, error) { return float64(runtimeNumGoroutine()), nil },
		10000,
		20000,
	))

	status, checks := runHealthChecks(r.Context(), liveness, s.healthCheckTimeout())

	s.json(w, healthHTTPStatus(status), map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"checks":    formatHealthChecks(checks),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	status := health.StatusUnknown
	checks := map[string]health.CheckResult{}

	if s.app.Health != nil {
		status, checks = runHealthChecks(r.Context(), s.app.Health, s.healthCheckTimeout())
	}

	s.json(w, healthHTTPStatus(status), map[string]interface{}{
		"status":    status,
		"ready":     status == health.StatusHealthy,
		"timestamp": time.Now().UTC(),
		"checks":    formatHealthChecks(checks),
	})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	body := map[string]any{
		"timestamp": now,
	}
	if s.app != nil {
		graphBuild := s.app.GraphBuildSnapshot()
		body["graph_build"] = graphBuild
		body["retention"] = s.app.CurrentRetentionStatus()
		body["freshness"] = s.app.GraphFreshnessStatusSnapshot(now)
	}
	if s.app != nil && s.app.Health != nil {
		status, checks := runHealthChecks(r.Context(), s.app.Health, s.healthCheckTimeout())
		body["health"] = map[string]any{
			"status": status,
			"checks": formatHealthChecks(checks),
		}
	}
	s.json(w, http.StatusOK, body)
}

func (s *Server) statusFreshness(w http.ResponseWriter, r *http.Request) {
	if s.app == nil {
		s.error(w, http.StatusServiceUnavailable, "app not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.GraphFreshnessStatusSnapshot(time.Now().UTC()))
}

func (s *Server) graphBuildWarningHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skipGraphBuildWarningHeaders(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s != nil && s.app != nil {
			snapshot := s.app.GraphBuildSnapshot()
			if snapshot.State == app.GraphBuildFailed {
				w.Header().Set("X-Cerebro-Graph-Build-Status", string(snapshot.State))
				if snapshot.LastError != "" {
					w.Header().Set("X-Cerebro-Graph-Build-Error", snapshot.LastError)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func skipGraphBuildWarningHeaders(path string) bool {
	switch strings.TrimSpace(path) {
	case "/health", "/ready", "/status", "/metrics",
		"/api/v1/status/freshness",
		"/api/v1/admin/health", "/api/v1/admin/sync/status",
		"/api/v1/scheduler/status", "/api/v1/graph/ingest/health",
		"/api/v1/graph/schema/health":
		return true
	default:
		return false
	}
}

func runHealthChecks(ctx context.Context, registry *health.Registry, timeout time.Duration) (health.Status, map[string]health.CheckResult) {
	if registry == nil {
		return health.StatusUnknown, map[string]health.CheckResult{}
	}
	if timeout <= 0 {
		timeout = (*app.Config)(nil).HealthCheckTimeoutOrDefault()
	}
	if ctx == nil {
		ctx = context.Background()
	}

	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	results := registry.RunAll(checkCtx)
	return overallHealthStatus(results), results
}

func (s *Server) apiRequestTimeout() time.Duration {
	if s == nil || s.app == nil {
		return (*app.Config)(nil).APIRequestTimeoutOrDefault()
	}
	return s.app.Config.APIRequestTimeoutOrDefault()
}

func (s *Server) apiMaxBodyBytes() int64 {
	if s == nil || s.app == nil {
		return (*app.Config)(nil).APIMaxBodyBytesOrDefault()
	}
	return s.app.Config.APIMaxBodyBytesOrDefault()
}

func (s *Server) healthCheckTimeout() time.Duration {
	if s == nil || s.app == nil {
		return (*app.Config)(nil).HealthCheckTimeoutOrDefault()
	}
	return s.app.Config.HealthCheckTimeoutOrDefault()
}

func (s *Server) riskEngineStateTimeout() time.Duration {
	if s == nil || s.app == nil {
		return (*app.Config)(nil).GraphRiskEngineStateTimeoutOrDefault()
	}
	return s.app.Config.GraphRiskEngineStateTimeoutOrDefault()
}

func overallHealthStatus(results map[string]health.CheckResult) health.Status {
	if len(results) == 0 {
		return health.StatusHealthy
	}

	hasDegraded := false
	hasUnknown := false
	for _, result := range results {
		switch result.Status {
		case health.StatusUnhealthy:
			return health.StatusUnhealthy
		case health.StatusDegraded:
			hasDegraded = true
		case health.StatusUnknown:
			hasUnknown = true
		}
	}

	if hasDegraded {
		return health.StatusDegraded
	}
	if hasUnknown {
		return health.StatusUnknown
	}
	return health.StatusHealthy
}

func healthHTTPStatus(status health.Status) int {
	if status == health.StatusHealthy {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}

func formatHealthChecks(checks map[string]health.CheckResult) map[string]map[string]interface{} {
	out := make(map[string]map[string]interface{}, len(checks))
	for name, result := range checks {
		out[name] = map[string]interface{}{
			"name":       result.Name,
			"status":     result.Status,
			"message":    result.Message,
			"latency_ms": result.Latency.Milliseconds(),
			"timestamp":  result.Timestamp,
		}
	}
	return out
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	// Use Prometheus metrics handler
	metrics.Handler().ServeHTTP(w, r)
}

func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(apicontract.OpenAPIYAML)
}

func (s *Server) swaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cerebro API Documentation</title>
  <style>
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      max-width: 900px;
      margin: 2rem auto;
      padding: 0 1rem;
      line-height: 1.5;
      color: #0f172a;
      background: #f8fafc;
    }
    .panel {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    code {
      background: #f1f5f9;
      border-radius: 6px;
      padding: 0.15rem 0.35rem;
    }
    a {
      color: #0f4c81;
    }
    h1, h2 {
      margin-top: 0;
    }
    ul {
      padding-left: 1.1rem;
    }
  </style>
</head>
<body>
  <h1>Cerebro API Docs</h1>
  <div class="panel">
    <p>
      Download the OpenAPI contract directly at
      <a href="/openapi.yaml"><code>/openapi.yaml</code></a>.
    </p>
    <p>
      This page is intentionally self-hosted and does not depend on external CDNs.
    </p>
  </div>
  <div class="panel">
    <h2>Quick Links</h2>
    <ul>
      <li><a href="/health"><code>/health</code></a></li>
      <li><a href="/ready"><code>/ready</code></a></li>
      <li><a href="/metrics"><code>/metrics</code></a></li>
      <li><a href="/api/v1/tables"><code>/api/v1/tables</code></a></li>
      <li><a href="/api/v1/findings"><code>/api/v1/findings</code></a></li>
    </ul>
  </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(html))
}

// Admin health dashboard
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"timestamp": time.Now().UTC(),
	}

	// Snowflake status
	if s.app.Snowflake != nil {
		ctx, cancel := context.WithTimeout(r.Context(), s.healthCheckTimeout())
		start := time.Now()
		err := s.app.Snowflake.Ping(ctx)
		cancel()
		latency := time.Since(start).Milliseconds()

		if err != nil {
			health["snowflake"] = map[string]interface{}{
				"status":     "unhealthy",
				"error":      err.Error(),
				"latency_ms": latency,
			}
		} else {
			health["snowflake"] = map[string]interface{}{
				"status":     "healthy",
				"latency_ms": latency,
			}
		}
	} else {
		health["snowflake"] = map[string]interface{}{"status": "not_configured"}
	}

	// Findings stats
	stats := s.app.Findings.Stats()
	health["findings"] = map[string]interface{}{
		"total":    stats.Total,
		"open":     stats.ByStatus["OPEN"],
		"critical": stats.BySeverity["critical"],
		"high":     stats.BySeverity["high"],
		"medium":   stats.BySeverity["medium"],
		"low":      stats.BySeverity["low"],
	}

	// Cache stats
	cacheStats := s.app.Cache.Stats()
	health["cache"] = cacheStats

	// Policies and agents
	health["policies"] = map[string]interface{}{
		"loaded": len(s.app.Policy.ListPolicies()),
	}
	health["agents"] = map[string]interface{}{
		"registered": len(s.app.Agents.ListAgents()),
	}
	health["providers"] = map[string]interface{}{
		"registered": len(s.app.Providers.List()),
	}

	// Scheduler status
	if s.app.Scheduler != nil {
		health["scheduler"] = map[string]interface{}{
			"configured": true,
		}
	}

	if s.app.Webhooks != nil {
		health["event_publisher"] = s.app.Webhooks.EventPublisherStatus(r.Context())
	}

	s.json(w, http.StatusOK, health)
}
