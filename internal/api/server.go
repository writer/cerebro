package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/compliance"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"
	"github.com/writerinternal/cerebro/internal/metrics"
)

// Server is the fully wired API server
type Server struct {
	app    *app.App
	router *chi.Mux
}

// NewServer creates a new server with all services wired
func NewServer(application *app.App) *Server {
	s := &Server{
		app:    application,
		router: chi.NewRouter(),
	}
	s.setupMiddleware()
	s.setupRoutes()
	return s
}

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Timeout(60 * time.Second))
	s.router.Use(middleware.Compress(5))
	s.router.Use(MetricsMiddleware)

	// Add rate limiting if configured
	if s.app.Config.RateLimitEnabled {
		s.router.Use(RateLimitMiddleware(RateLimitConfig{
			RequestsPerWindow: s.app.Config.RateLimitRequests,
			Window:            s.app.Config.RateLimitWindow,
			Enabled:           true,
		}))
	}
}

func (s *Server) setupRoutes() {
	s.router.Get("/health", s.health)
	s.router.Get("/ready", s.ready)
	s.router.Get("/metrics", s.metrics)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Query endpoints
		r.Get("/tables", s.listTables)
		r.Post("/query", s.executeQuery)

		// Asset endpoints
		r.Route("/assets", func(r chi.Router) {
			r.Get("/{table}", s.listAssets)
			r.Get("/{table}/{id}", s.getAsset)
		})

		// Policy endpoints
		r.Route("/policies", func(r chi.Router) {
			r.Get("/", s.listPolicies)
			r.Get("/{id}", s.getPolicy)
			r.Post("/", s.createPolicy)
			r.Post("/evaluate", s.evaluatePolicy)
		})

		// Finding endpoints
		r.Route("/findings", func(r chi.Router) {
			r.Get("/", s.listFindings)
			r.Get("/stats", s.findingsStats)
			r.Get("/{id}", s.getFinding)
			r.Post("/scan", s.scanFindings)
			r.Post("/{id}/resolve", s.resolveFinding)
			r.Post("/{id}/suppress", s.suppressFinding)
		})

		// Compliance endpoints
		r.Route("/compliance", func(r chi.Router) {
			r.Get("/frameworks", s.listFrameworks)
			r.Get("/frameworks/{id}", s.getFramework)
			r.Get("/frameworks/{id}/report", s.generateComplianceReport)
			r.Get("/frameworks/{id}/pre-audit", s.preAuditCheck)
			r.Get("/frameworks/{id}/export", s.exportAuditPackage)
		})

		// Agent endpoints
		r.Route("/agents", func(r chi.Router) {
			r.Get("/", s.listAgents)
			r.Get("/{id}", s.getAgent)
			r.Post("/sessions", s.createSession)
			r.Get("/sessions/{id}", s.getSession)
			r.Post("/sessions/{id}/messages", s.sendMessage)
			r.Get("/sessions/{id}/messages", s.getMessages)
		})

		// Ticketing endpoints
		r.Route("/tickets", func(r chi.Router) {
			r.Get("/", s.listTickets)
			r.Post("/", s.createTicket)
			r.Get("/{id}", s.getTicket)
			r.Put("/{id}", s.updateTicket)
			r.Post("/{id}/comments", s.addComment)
			r.Post("/{id}/close", s.closeTicket)
		})

		// Identity/Access Review endpoints
		r.Route("/identity", func(r chi.Router) {
			r.Get("/reviews", s.listReviews)
			r.Post("/reviews", s.createReview)
			r.Get("/reviews/{id}", s.getReview)
			r.Post("/reviews/{id}/start", s.startReview)
			r.Get("/reviews/{id}/items", s.listReviewItems)
			r.Post("/reviews/{id}/items", s.addReviewItem)
			r.Post("/reviews/{id}/items/{itemId}/decide", s.recordDecision)

			// Stale access detection
			r.Get("/stale-access", s.detectStaleAccess)
			r.Get("/report", s.identityReport)
		})

		// Attack Path endpoints
		r.Route("/attack-paths", func(r chi.Router) {
			r.Get("/", s.listAttackPaths)
			r.Post("/analyze", s.analyzeAttackPaths)
			r.Get("/{id}", s.getAttackPath)
			r.Get("/graph", s.getGraph)
			r.Post("/graph/nodes", s.addNode)
			r.Post("/graph/edges", s.addEdge)
		})

		// Provider endpoints
		r.Route("/providers", func(r chi.Router) {
			r.Get("/", s.listProviders)
			r.Get("/{name}", s.getProvider)
			r.Post("/{name}/configure", s.configureProvider)
			r.Post("/{name}/sync", s.syncProvider)
			r.Get("/{name}/schema", s.getProviderSchema)
			r.Post("/{name}/test", s.testProvider)
		})

		// Webhook endpoints
		r.Route("/webhooks", func(r chi.Router) {
			r.Get("/", s.listWebhooks)
			r.Post("/", s.createWebhook)
			r.Get("/{id}", s.getWebhook)
			r.Delete("/{id}", s.deleteWebhook)
			r.Get("/{id}/deliveries", s.getWebhookDeliveries)
			r.Post("/test", s.testWebhook)
		})

		// Audit log endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Get("/", s.listAuditLogs)
		})

		// Scheduler endpoints
		r.Route("/scheduler", func(r chi.Router) {
			r.Get("/status", s.schedulerStatus)
			r.Get("/jobs", s.listJobs)
			r.Post("/jobs/{name}/run", s.runJob)
			r.Post("/jobs/{name}/enable", s.enableJob)
			r.Post("/jobs/{name}/disable", s.disableJob)
		})

		// Notification endpoints
		r.Route("/notifications", func(r chi.Router) {
			r.Get("/", s.listNotifiers)
			r.Post("/test", s.testNotifications)
		})

		// Admin/health endpoints
		r.Route("/admin", func(r chi.Router) {
			r.Get("/health", s.adminHealth)
			r.Get("/sync/status", s.syncStatus)
		})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.app.Config.Port)
	s.app.Logger.Info("starting server", "addr", addr)
	return http.ListenAndServe(addr, s.router)
}

// Health endpoints

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	ready := true

	if s.app.Snowflake != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.app.Snowflake.Ping(ctx); err != nil {
			checks["snowflake"] = "unhealthy: " + err.Error()
			ready = false
		} else {
			checks["snowflake"] = "healthy"
		}
	} else {
		checks["snowflake"] = "not configured"
	}

	checks["policies"] = fmt.Sprintf("%d loaded", len(s.app.Policy.ListPolicies()))
	checks["agents"] = fmt.Sprintf("%d registered", len(s.app.Agents.ListAgents()))
	checks["providers"] = fmt.Sprintf("%d registered", len(s.app.Providers.List()))

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	s.json(w, status, map[string]interface{}{
		"ready":  ready,
		"checks": checks,
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	// Use Prometheus metrics handler
	metrics.Handler().ServeHTTP(w, r)
}

// Admin health dashboard
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"timestamp": time.Now().UTC(),
	}

	// Snowflake status
	if s.app.Snowflake != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
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
		"open":     stats.ByStatus["open"],
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

	s.json(w, http.StatusOK, health)
}

// Sync status - data freshness from CloudQuery
func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	// Query _cq_sync_time from key tables to determine freshness
	tables := []string{
		"aws_s3_buckets",
		"aws_iam_users",
		"aws_ec2_instances",
		"gcp_storage_buckets",
		"gcp_compute_instances",
		"azure_storage_accounts",
		"k8s_core_pods",
	}

	sources := make(map[string]interface{})
	staleThreshold := 6 * time.Hour

	for _, table := range tables {
		query := fmt.Sprintf("SELECT MAX(_cq_sync_time) as last_sync FROM %s", table)
		result, err := s.app.Snowflake.Query(r.Context(), query)
		if err != nil {
			continue // Table might not exist
		}

		if len(result.Rows) > 0 && result.Rows[0]["LAST_SYNC"] != nil {
			var lastSync time.Time
			switch v := result.Rows[0]["LAST_SYNC"].(type) {
			case time.Time:
				lastSync = v
			case string:
				lastSync, _ = time.Parse(time.RFC3339, v)
			}

			if !lastSync.IsZero() {
				status := "fresh"
				if time.Since(lastSync) > staleThreshold {
					status = "stale"
				}

				// Extract provider from table name
				provider := "unknown"
				if len(table) > 4 {
					switch {
					case table[:3] == "aws":
						provider = "aws"
					case table[:3] == "gcp":
						provider = "gcp"
					case table[:5] == "azure":
						provider = "azure"
					case table[:3] == "k8s":
						provider = "kubernetes"
					}
				}

				if existing, ok := sources[provider].(map[string]interface{}); ok {
					// Keep the most recent sync time
					if existingTime, ok := existing["last_sync"].(time.Time); ok {
						if lastSync.After(existingTime) {
							sources[provider] = map[string]interface{}{
								"last_sync": lastSync,
								"status":    status,
								"age":       time.Since(lastSync).String(),
							}
						}
					}
				} else {
					sources[provider] = map[string]interface{}{
						"last_sync": lastSync,
						"status":    status,
						"age":       time.Since(lastSync).String(),
					}
				}
			}
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"sources":         sources,
		"stale_threshold": staleThreshold.String(),
		"checked_at":      time.Now().UTC(),
	})
}

// Query endpoints

func (s *Server) listTables(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	tables, err := s.app.Snowflake.ListTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tables": tables, "count": len(tables)})
}

func (s *Server) executeQuery(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := s.app.Snowflake.Query(r.Context(), req.Query)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, result)
}

// Asset endpoints

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 100
	}

	assets, err := s.app.Snowflake.GetAssets(r.Context(), table, snowflake.AssetFilter{
		Limit:   limit,
		Account: r.URL.Query().Get("account"),
		Region:  r.URL.Query().Get("region"),
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"assets": assets, "count": len(assets)})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	id := chi.URLParam(r, "id")

	asset, err := s.app.Snowflake.GetAssetByID(r.Context(), table, id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, asset)
}

// Policy endpoints

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.app.Policy.ListPolicies()
	s.json(w, http.StatusOK, map[string]interface{}{"policies": policies, "count": len(policies)})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, ok := s.app.Policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}
	s.json(w, http.StatusOK, p)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.app.Policy.AddPolicy(&p)
	s.json(w, http.StatusCreated, p)
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req policy.EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := s.app.Policy.Evaluate(r.Context(), &req)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, resp)
}

// Finding endpoints

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	filter := findings.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		PolicyID: r.URL.Query().Get("policy_id"),
	}
	list := s.app.Findings.List(filter)
	s.json(w, http.StatusOK, map[string]interface{}{"findings": list, "count": len(list)})
}

func (s *Server) findingsStats(w http.ResponseWriter, r *http.Request) {
	stats := s.app.Findings.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f, ok := s.app.Findings.Get(id)
	if !ok {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Table string `json:"table"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Limit == 0 {
		req.Limit = 100
	}

	assets, err := s.app.Snowflake.GetAssets(r.Context(), req.Table, snowflake.AssetFilter{Limit: req.Limit})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := s.app.Scanner.ScanAssets(r.Context(), assets)

	// Persist findings
	for _, f := range result.Findings {
		s.app.Findings.Upsert(r.Context(), f)
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned":    result.Scanned,
		"violations": result.Violations,
		"duration":   result.Duration.String(),
		"findings":   result.Findings,
	})
}

func (s *Server) resolveFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.app.Findings.Resolve(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "resolved"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) suppressFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.app.Findings.Suppress(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "suppressed"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

// Compliance endpoints

func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := compliance.GetFrameworks()
	s.json(w, http.StatusOK, map[string]interface{}{"frameworks": frameworks, "count": len(frameworks)})
}

func (s *Server) getFramework(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := compliance.GetFramework(id)
	if f == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) generateComplianceReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	// Generate report based on current findings
	findingsStats := s.app.Findings.Stats()
	
	report := compliance.ComplianceReport{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Summary: compliance.ComplianceSummary{
			TotalControls: len(framework.Controls),
		},
		Controls: make([]compliance.ControlStatus, len(framework.Controls)),
	}

	passing := 0
	for i, ctrl := range framework.Controls {
		// Check if any policies for this control have findings
		hasFailing := false
		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := findingsStats.ByPolicy[policyID]; ok && count > 0 {
				hasFailing = true
				break
			}
		}

		status := "passing"
		if hasFailing {
			status = "failing"
		} else {
			passing++
		}

		report.Controls[i] = compliance.ControlStatus{
			ControlID: ctrl.ID,
			Status:    status,
		}
	}

	report.Summary.PassingControls = passing
	report.Summary.FailingControls = len(framework.Controls) - passing
	if len(framework.Controls) > 0 {
		report.Summary.ComplianceScore = float64(passing) / float64(len(framework.Controls)) * 100
	}

	s.json(w, http.StatusOK, report)
}

// Pre-audit health check - predicts audit outcome
func (s *Server) preAuditCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	findingsStats := s.app.Findings.Stats()

	type ControlCheck struct {
		ControlID   string   `json:"control_id"`
		Title       string   `json:"title"`
		Status      string   `json:"status"` // passing, failing, at_risk
		Issues      []string `json:"issues,omitempty"`
		Findings    []string `json:"findings,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
	}

	var checks []ControlCheck
	passing, failing, atRisk := 0, 0, 0

	for _, ctrl := range framework.Controls {
		check := ControlCheck{
			ControlID: ctrl.ID,
			Title:     ctrl.Title,
			Status:    "passing",
		}

		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := findingsStats.ByPolicy[policyID]; ok && count > 0 {
				check.Status = "failing"
				check.Issues = append(check.Issues, fmt.Sprintf("%d findings for policy %s", count, policyID))
				check.Findings = append(check.Findings, policyID)
			}
		}

		switch check.Status {
		case "passing":
			passing++
		case "failing":
			failing++
			check.Remediation = "Review and remediate findings before audit"
		case "at_risk":
			atRisk++
		}

		checks = append(checks, check)
	}

	// Determine estimated outcome
	outcome := "PASS"
	if failing > 0 {
		outcome = fmt.Sprintf("PASS WITH %d EXCEPTIONS", failing)
	}
	if float64(failing)/float64(len(framework.Controls)) > 0.2 {
		outcome = "AT RISK - RECOMMEND POSTPONING"
	}

	score := 0.0
	if len(framework.Controls) > 0 {
		score = float64(passing) / float64(len(framework.Controls)) * 100
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"framework_id":      framework.ID,
		"framework_name":    framework.Name,
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"estimated_outcome": outcome,
		"summary": map[string]interface{}{
			"total_controls":   len(framework.Controls),
			"passing":          passing,
			"failing":          failing,
			"at_risk":          atRisk,
			"compliance_score": fmt.Sprintf("%.1f%%", score),
		},
		"controls": checks,
		"recommendations": s.generateAuditRecommendations(failing, atRisk, len(framework.Controls)),
	})
}

func (s *Server) generateAuditRecommendations(failing, atRisk, total int) []string {
	var recs []string

	if failing > 0 {
		recs = append(recs, fmt.Sprintf("Remediate %d failing controls before audit", failing))
	}
	if atRisk > 0 {
		recs = append(recs, fmt.Sprintf("Review %d at-risk controls", atRisk))
	}
	if failing == 0 && atRisk == 0 {
		recs = append(recs, "All controls passing - ready for audit")
	}
	if float64(failing)/float64(total) > 0.1 {
		recs = append(recs, "Consider postponing audit until critical issues are resolved")
	}

	return recs
}

// Export audit package with evidence
func (s *Server) exportAuditPackage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	// Generate manifest
	manifest := map[string]interface{}{
		"framework_id":   framework.ID,
		"framework_name": framework.Name,
		"version":        framework.Version,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"generated_by":   "cerebro",
	}

	// Gather evidence for each control
	findingsStats := s.app.Findings.Stats()
	controlEvidence := make([]map[string]interface{}, len(framework.Controls))

	for i, ctrl := range framework.Controls {
		status := "passing"
		var relatedFindings []string

		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := findingsStats.ByPolicy[policyID]; ok && count > 0 {
				status = "failing"
				relatedFindings = append(relatedFindings, policyID)
			}
		}

		controlEvidence[i] = map[string]interface{}{
			"control_id":  ctrl.ID,
			"title":       ctrl.Title,
			"description": ctrl.Description,
			"status":      status,
			"policies":    ctrl.PolicyIDs,
			"findings":    relatedFindings,
		}
	}

	// In a real implementation, this would:
	// 1. Query Snowflake for actual asset data
	// 2. Bundle findings as JSON evidence
	// 3. Create a ZIP file with manifest + evidence
	// 4. Stream the ZIP to the client

	// For now, return JSON that could be used to build the package
	s.json(w, http.StatusOK, map[string]interface{}{
		"manifest": manifest,
		"controls": controlEvidence,
		"note":     "Use CLI 'cerebro compliance export' to generate downloadable ZIP package",
	})
}

// Agent endpoints

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agentList := s.app.Agents.ListAgents()
	result := make([]map[string]interface{}, len(agentList))
	for i, a := range agentList {
		result[i] = map[string]interface{}{
			"id":          a.ID,
			"name":        a.Name,
			"description": a.Description,
			"tools":       len(a.Tools),
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"agents": result, "count": len(result)})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, ok := s.app.Agents.GetAgent(id)
	if !ok {
		s.error(w, http.StatusNotFound, "agent not found")
		return
	}

	tools := make([]map[string]interface{}, len(agent.Tools))
	for i, t := range agent.Tools {
		tools[i] = map[string]interface{}{
			"name":              t.Name,
			"description":       t.Description,
			"requires_approval": t.RequiresApproval,
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"id":          agent.ID,
		"name":        agent.Name,
		"description": agent.Description,
		"tools":       tools,
	})
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID    string                 `json:"agent_id"`
		UserID     string                 `json:"user_id"`
		FindingIDs []string               `json:"finding_ids,omitempty"`
		Context    map[string]interface{} `json:"context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	session, err := s.app.Agents.CreateSession(req.AgentID, req.UserID, agents.SessionContext{
		FindingIDs: req.FindingIDs,
		Metadata:   req.Context,
	})
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusCreated, session)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(id)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	s.json(w, http.StatusOK, session)
}

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(sessionID)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Add user message
	session.Messages = append(session.Messages, agents.Message{
		Role:    "user",
		Content: req.Content,
	})

	// Get agent and generate response
	agent, ok := s.app.Agents.GetAgent(session.AgentID)
	if !ok || agent.Provider == nil {
		// Return placeholder if no LLM configured
		session.Messages = append(session.Messages, agents.Message{
			Role:    "assistant",
			Content: "I understand you want help with: " + req.Content + ". However, no LLM provider is configured. Please set ANTHROPIC_API_KEY or OPENAI_API_KEY.",
		})
		s.app.Agents.UpdateSession(session)
		s.json(w, http.StatusOK, session.Messages[len(session.Messages)-1])
		return
	}

	// Build messages with system prompt
	messages := []agents.Message{
		{Role: "system", Content: "You are a security analyst assistant. Help investigate security findings and incidents. Use the available tools to query data and take actions."},
	}
	messages = append(messages, session.Messages...)

	// Call LLM
	resp, err := agent.Provider.Complete(r.Context(), messages, agent.Tools)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	session.Messages = append(session.Messages, resp.Message)
	s.app.Agents.UpdateSession(session)

	s.json(w, http.StatusOK, resp.Message)
}

func (s *Server) getMessages(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(sessionID)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"messages": session.Messages, "count": len(session.Messages)})
}

// Ticketing endpoints

func (s *Server) listTickets(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.json(w, http.StatusOK, map[string]interface{}{"tickets": []interface{}{}, "count": 0, "message": "no ticketing provider configured"})
		return
	}

	tickets, err := s.app.Ticketing.Primary().ListTickets(r.Context(), ticketing.TicketFilter{
		Status:   r.URL.Query().Get("status"),
		Priority: r.URL.Query().Get("priority"),
		Limit:    50,
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tickets": tickets, "count": len(tickets)})
}

func (s *Server) createTicket(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Priority    string   `json:"priority"`
		FindingIDs  []string `json:"finding_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	ticket := &ticketing.Ticket{
		Title:       req.Title,
		Description: req.Description,
		Priority:    req.Priority,
		FindingIDs:  req.FindingIDs,
		Type:        "finding",
	}

	created, err := s.app.Ticketing.CreateTicket(r.Context(), ticket)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	ticket, err := s.app.Ticketing.Primary().GetTicket(r.Context(), id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, ticket)
}

func (s *Server) updateTicket(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var update ticketing.TicketUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	ticket, err := s.app.Ticketing.Primary().UpdateTicket(r.Context(), id, &update)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, ticket)
}

func (s *Server) addComment(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	err := s.app.Ticketing.Primary().AddComment(r.Context(), id, &ticketing.Comment{Body: req.Body})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusCreated, map[string]string{"status": "comment added"})
}

func (s *Server) closeTicket(w http.ResponseWriter, r *http.Request) {
	if s.app.Ticketing.Primary() == nil {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var req struct {
		Resolution string `json:"resolution"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	err := s.app.Ticketing.Primary().Close(r.Context(), id, req.Resolution)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "closed"})
}

// Identity/Access Review endpoints

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	status := identity.ReviewStatus(r.URL.Query().Get("status"))
	reviews := s.app.Identity.ListReviews(r.Context(), status)
	s.json(w, http.StatusOK, map[string]interface{}{"reviews": reviews, "count": len(reviews)})
}

func (s *Server) createReview(w http.ResponseWriter, r *http.Request) {
	var review identity.AccessReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	created, err := s.app.Identity.CreateReview(r.Context(), &review)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) getReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, review)
}

func (s *Server) startReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Identity.StartReview(r.Context(), id); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "started"})
}

func (s *Server) listReviewItems(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": review.Items, "count": len(review.Items)})
}

func (s *Server) addReviewItem(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
	var item identity.ReviewItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Identity.AddReviewItem(r.Context(), reviewID, &item); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) recordDecision(w http.ResponseWriter, r *http.Request) {
	itemID := chi.URLParam(r, "itemId")
	var decision identity.ReviewDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Identity.RecordDecision(r.Context(), itemID, &decision); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}

func (s *Server) detectStaleAccess(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	detector := identity.NewStaleAccessDetector(identity.DefaultThresholds())

	// Fetch users from Snowflake
	users, err := s.app.Snowflake.GetAssets(r.Context(), "aws_iam_users", snowflake.AssetFilter{Limit: 1000})
	if err != nil {
		users = []map[string]interface{}{}
	}

	// Fetch credentials
	creds, err := s.app.Snowflake.GetAssets(r.Context(), "aws_iam_credential_reports", snowflake.AssetFilter{Limit: 1000})
	if err != nil {
		creds = []map[string]interface{}{}
	}

	// Fetch service accounts
	sas, err := s.app.Snowflake.GetAssets(r.Context(), "gcp_iam_service_accounts", snowflake.AssetFilter{Limit: 1000})
	if err != nil {
		sas = []map[string]interface{}{}
	}

	var allFindings []identity.StaleAccessFinding
	allFindings = append(allFindings, detector.DetectStaleUsers(r.Context(), users)...)
	allFindings = append(allFindings, detector.DetectUnusedAccessKeys(r.Context(), creds)...)
	allFindings = append(allFindings, detector.DetectStaleServiceAccounts(r.Context(), sas)...)

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": allFindings,
		"count":    len(allFindings),
		"summary": map[string]int{
			"inactive_users":     countByType(allFindings, identity.StaleAccessInactiveUser),
			"unused_keys":        countByType(allFindings, identity.StaleAccessUnusedAccessKey),
			"stale_service_accts": countByType(allFindings, identity.StaleAccessStaleServiceAccount),
		},
	})
}

func countByType(findings []identity.StaleAccessFinding, t identity.StaleAccessType) int {
	count := 0
	for _, f := range findings {
		if f.Type == t {
			count++
		}
	}
	return count
}

func (s *Server) identityReport(w http.ResponseWriter, r *http.Request) {
	generator := identity.NewReportGenerator()

	data := identity.IdentityData{}

	if s.app.Snowflake != nil {
		// Load identity data from various tables
		if users, err := s.app.Snowflake.GetAssets(r.Context(), "aws_iam_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if users, err := s.app.Snowflake.GetAssets(r.Context(), "okta_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if users, err := s.app.Snowflake.GetAssets(r.Context(), "azure_ad_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if sas, err := s.app.Snowflake.GetAssets(r.Context(), "gcp_iam_service_accounts", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.ServiceAccounts = sas
		}
		if creds, err := s.app.Snowflake.GetAssets(r.Context(), "aws_iam_credential_reports", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Credentials = creds
		}
		if roles, err := s.app.Snowflake.GetAssets(r.Context(), "aws_iam_roles", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Roles = roles
		}
	}

	report, err := generator.GenerateReport(r.Context(), data)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, report)
}

// Attack Path endpoints

func (s *Server) listAttackPaths(w http.ResponseWriter, r *http.Request) {
	finder := attackpath.NewPathFinder(s.app.AttackPath, 10)
	paths := finder.FindPaths(r.Context())
	s.json(w, http.StatusOK, map[string]interface{}{"paths": paths, "count": len(paths)})
}

func (s *Server) analyzeAttackPaths(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HighValueTargets []string `json:"high_value_targets"`
		MaxDepth         int      `json:"max_depth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.MaxDepth == 0 {
		req.MaxDepth = 10
	}

	finder := attackpath.NewPathFinder(s.app.AttackPath, req.MaxDepth)
	finder.SetHighValueTargets(req.HighValueTargets)
	paths := finder.FindPaths(r.Context())

	s.json(w, http.StatusOK, map[string]interface{}{
		"paths": paths,
		"count": len(paths),
		"analyzed_at": time.Now().UTC(),
	})
}

func (s *Server) getAttackPath(w http.ResponseWriter, r *http.Request) {
	// For now, return path from analysis
	s.json(w, http.StatusOK, map[string]interface{}{"id": chi.URLParam(r, "id")})
}

func (s *Server) getGraph(w http.ResponseWriter, r *http.Request) {
	nodes := s.app.AttackPath.GetAllNodes()
	s.json(w, http.StatusOK, map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	})
}

func (s *Server) addNode(w http.ResponseWriter, r *http.Request) {
	var node attackpath.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.app.AttackPath.AddNode(&node)
	s.json(w, http.StatusCreated, node)
}

func (s *Server) addEdge(w http.ResponseWriter, r *http.Request) {
	var edge attackpath.Edge
	if err := json.NewDecoder(r.Body).Decode(&edge); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.app.AttackPath.AddEdge(&edge)
	s.json(w, http.StatusCreated, edge)
}

// Provider endpoints

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	providerList := s.app.Providers.List()
	result := make([]map[string]interface{}, len(providerList))
	for i, p := range providerList {
		result[i] = map[string]interface{}{
			"name":   p.Name(),
			"type":   p.Type(),
			"tables": len(p.Schema()),
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"providers": result, "count": len(result)})
}

func (s *Server) getProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"name":   p.Name(),
		"type":   p.Type(),
		"schema": p.Schema(),
	})
}

func (s *Server) configureProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Providers.Configure(r.Context(), name, config); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "configured"})
}

func (s *Server) syncProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	result, err := p.Sync(r.Context(), providers.SyncOptions{FullSync: true})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) getProviderSchema(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tables": p.Schema()})
}

func (s *Server) testProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	if err := p.Test(r.Context()); err != nil {
		s.json(w, http.StatusOK, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"status": "success"})
}

// Helpers

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) error(w http.ResponseWriter, status int, message string) {
	s.json(w, status, map[string]string{"error": message})
}

// Webhook endpoints

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	hooks := s.app.Webhooks.ListWebhooks()
	// Redact secrets
	result := make([]map[string]interface{}, len(hooks))
	for i, h := range hooks {
		result[i] = map[string]interface{}{
			"id":         h.ID,
			"url":        h.URL,
			"events":     h.Events,
			"enabled":    h.Enabled,
			"created_at": h.CreatedAt,
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"webhooks": result, "count": len(result)})
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string              `json:"url"`
		Events []webhooks.EventType `json:"events"`
		Secret string              `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	hook := s.app.Webhooks.RegisterWebhook(req.URL, req.Events, req.Secret)
	s.json(w, http.StatusCreated, map[string]interface{}{
		"id":         hook.ID,
		"url":        hook.URL,
		"events":     hook.Events,
		"enabled":    hook.Enabled,
		"created_at": hook.CreatedAt,
	})
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	hook, ok := s.app.Webhooks.GetWebhook(id)
	if !ok {
		s.error(w, http.StatusNotFound, "webhook not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"id":         hook.ID,
		"url":        hook.URL,
		"events":     hook.Events,
		"enabled":    hook.Enabled,
		"created_at": hook.CreatedAt,
	})
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.app.Webhooks.DeleteWebhook(id) {
		w.WriteHeader(http.StatusNoContent)
	} else {
		s.error(w, http.StatusNotFound, "webhook not found")
	}
}

func (s *Server) getWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	deliveries := s.app.Webhooks.GetDeliveries(id, 100)
	s.json(w, http.StatusOK, map[string]interface{}{"deliveries": deliveries, "count": len(deliveries)})
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Send test event
	s.app.Webhooks.Emit(r.Context(), "test", map[string]interface{}{
		"message": "Test webhook from Cerebro",
	})
	s.json(w, http.StatusOK, map[string]string{"status": "test event sent"})
}

// Audit log endpoints

func (s *Server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	if s.app.AuditRepo == nil {
		s.json(w, http.StatusOK, map[string]interface{}{"logs": []interface{}{}, "message": "snowflake not configured"})
		return
	}

	resourceType := r.URL.Query().Get("resource_type")
	resourceID := r.URL.Query().Get("resource_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 100
	}

	logs, err := s.app.AuditRepo.List(r.Context(), resourceType, resourceID, limit)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"logs": logs, "count": len(logs)})
}

// Scheduler endpoints

func (s *Server) schedulerStatus(w http.ResponseWriter, r *http.Request) {
	status := s.app.Scheduler.Status()
	s.json(w, http.StatusOK, status)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	jobs := s.app.Scheduler.ListJobs()
	result := make([]map[string]interface{}, len(jobs))
	for i, j := range jobs {
		result[i] = map[string]interface{}{
			"name":     j.Name,
			"interval": j.Interval.String(),
			"enabled":  j.Enabled,
			"running":  j.Running,
			"next_run": j.NextRun,
		}
		if !j.LastRun.IsZero() {
			result[i]["last_run"] = j.LastRun
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"jobs": result, "count": len(result)})
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.app.Scheduler.RunNow(name); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusAccepted, map[string]string{"status": "job triggered"})
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s.app.Scheduler.EnableJob(name)
	s.json(w, http.StatusOK, map[string]string{"status": "job enabled"})
}

func (s *Server) disableJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s.app.Scheduler.DisableJob(name)
	s.json(w, http.StatusOK, map[string]string{"status": "job disabled"})
}

// Notification endpoints

func (s *Server) listNotifiers(w http.ResponseWriter, r *http.Request) {
	notifiers := s.app.Notifications.ListNotifiers()
	s.json(w, http.StatusOK, map[string]interface{}{"notifiers": notifiers, "count": len(notifiers)})
}

func (s *Server) testNotifications(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Message = "Test notification from Cerebro"
		req.Severity = "info"
	}

	err := s.app.Notifications.Send(r.Context(), notifications.Event{
		Type:     "test",
		Title:    "Test Notification",
		Message:  req.Message,
		Severity: req.Severity,
	})
	if err != nil {
		s.json(w, http.StatusOK, map[string]interface{}{"status": "partial", "error": err.Error()})
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "sent"})
}
