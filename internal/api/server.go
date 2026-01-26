package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/auth"
	"github.com/writerinternal/cerebro/internal/compliance"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/graph"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/lineage"
	"github.com/writerinternal/cerebro/internal/metrics"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/remediation"
	"github.com/writerinternal/cerebro/internal/runtime"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"github.com/writerinternal/cerebro/internal/threatintel"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"
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

	if s.app.Config.APIAuthEnabled {
		s.router.Use(APIKeyAuth(AuthConfig{Enabled: true, APIKeys: s.app.Config.APIKeys}))
	}

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
	s.router.Get("/openapi.yaml", s.openAPISpec)
	s.router.Get("/docs", s.swaggerUI)

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
			r.Get("/export", s.exportFindings)
			r.Get("/{id}", s.getFinding)
			r.Post("/scan", s.scanFindings)
			r.Post("/{id}/resolve", s.resolveFinding)
			r.Post("/{id}/suppress", s.suppressFinding)
			r.Put("/{id}/assign", s.assignFinding)
			r.Put("/{id}/due", s.setFindingDueDate)
			r.Post("/{id}/notes", s.addFindingNote)
			r.Post("/{id}/tickets", s.linkFindingTicket)
		})

		// Reporting endpoints
		r.Route("/reports", func(r chi.Router) {
			r.Get("/executive-summary", s.executiveSummary)
			r.Get("/risk-summary", s.riskSummary)
			r.Get("/compliance/{framework}", s.frameworkComplianceReport)
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

		// Incident response endpoints
		r.Route("/incidents", func(r chi.Router) {
			r.Post("/", s.createIncident)
			r.Get("/playbooks", s.listPlaybooks)
			r.Get("/playbooks/{id}", s.getPlaybook)
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
			// CloudQuery sync webhook - trigger graph rebuild
			r.Post("/cloudquery/sync", s.cloudQuerySyncWebhook)
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
			r.Get("/digest", s.dailyDigest)
		})

		// Slack integration
		r.Post("/slack/commands", s.slackCommands)

		// Remediation/automation endpoints
		r.Route("/remediation", func(r chi.Router) {
			r.Get("/rules", s.listRemediationRules)
			r.Post("/rules", s.createRemediationRule)
			r.Get("/rules/{id}", s.getRemediationRule)
			r.Post("/rules/{id}/enable", s.enableRemediationRule)
			r.Post("/rules/{id}/disable", s.disableRemediationRule)
			r.Get("/executions", s.listRemediationExecutions)
			r.Get("/executions/{id}", s.getRemediationExecution)
			r.Post("/executions/{id}/approve", s.approveExecution)
			r.Post("/executions/{id}/reject", s.rejectExecution)
		})

		// Admin/health endpoints
		r.Route("/admin", func(r chi.Router) {
			r.Get("/health", s.adminHealth)
			r.Get("/sync/status", s.syncStatus)
		})

		// Threat Intelligence endpoints
		r.Route("/threatintel", func(r chi.Router) {
			r.Get("/feeds", s.listThreatFeeds)
			r.Post("/feeds/{id}/sync", s.syncThreatFeed)
			r.Get("/stats", s.threatIntelStats)
			r.Get("/lookup/ip/{ip}", s.lookupIP)
			r.Get("/lookup/domain/{domain}", s.lookupDomain)
			r.Get("/lookup/cve/{cve}", s.lookupCVE)
		})

		// Runtime Detection endpoints
		r.Route("/runtime", func(r chi.Router) {
			r.Get("/detections", s.listDetectionRules)
			r.Post("/events", s.ingestRuntimeEvent)
			r.Get("/findings", s.listRuntimeFindings)
			r.Get("/responses", s.listResponsePolicies)
			r.Post("/responses/{id}/enable", s.enableResponsePolicy)
			r.Post("/responses/{id}/disable", s.disableResponsePolicy)
		})

		// Lineage endpoints
		r.Route("/lineage", func(r chi.Router) {
			r.Get("/{assetId}", s.getAssetLineage)
			r.Get("/by-commit/{sha}", s.getLineageByCommit)
			r.Get("/by-image/{digest}", s.getLineageByImage)
			r.Post("/drift/{assetId}", s.detectDrift)
		})

		// RBAC endpoints
		r.Route("/rbac", func(r chi.Router) {
			r.Get("/roles", s.listRoles)
			r.Get("/permissions", s.listPermissions)
			r.Post("/users", s.createUser)
			r.Get("/users/{id}", s.getUser)
			r.Post("/users/{id}/roles", s.assignRole)
			r.Get("/tenants", s.listTenants)
			r.Post("/tenants", s.createTenant)
		})

		// CloudQuery table management endpoints
		r.Route("/cloudquery", func(r chi.Router) {
			r.Get("/tables", s.listCloudQueryTables)
			r.Get("/inventory", s.getAssetInventory)
			r.Get("/freshness/{table}", s.checkDataFreshness)
			r.Get("/stats/{table}", s.getTableStats)
			r.Post("/ensure-tables", s.ensureCloudQueryTables)
		})

		// Scan management endpoints
		r.Route("/scan", func(r chi.Router) {
			r.Get("/watermarks", s.getScanWatermarks)
			r.Get("/coverage", s.getPolicyCoverage)
		})

		// Telemetry ingestion (for agents)
		r.Route("/telemetry", func(r chi.Router) {
			r.Post("/ingest", s.ingestTelemetry)
		})

		// Security Graph endpoints
		r.Route("/graph", func(r chi.Router) {
			r.Get("/stats", s.graphStats)
			r.Get("/blast-radius/{principalId}", s.blastRadius)
			r.Get("/reverse-access/{resourceId}", s.reverseAccess)
			r.Post("/rebuild", s.rebuildGraph)

			// Risk Intelligence endpoints
			r.Get("/risk-report", s.riskReport)
			r.Get("/toxic-combinations", s.listToxicCombinations)
			r.Get("/attack-paths", s.listGraphAttackPaths)
			r.Get("/attack-paths/{id}/simulate-fix", s.simulateAttackPathFix)
			r.Get("/chokepoints", s.listChokepoints)
			r.Get("/privilege-escalation/{principalId}", s.detectPrivilegeEscalation)

			// Peer Groups and Access Analysis endpoints
			r.Get("/peer-groups", s.analyzePeerGroups)
			r.Get("/effective-permissions/{principalId}", s.getEffectivePermissions)
			r.Get("/compare-permissions", s.comparePermissions)

			// Graph-based Access Review endpoints
			r.Post("/access-reviews", s.createGraphAccessReview)
			r.Get("/access-reviews", s.listGraphAccessReviews)
			r.Get("/access-reviews/{id}", s.getGraphAccessReview)
			r.Post("/access-reviews/{id}/start", s.startGraphAccessReview)
			r.Post("/access-reviews/{id}/items/{itemId}/decide", s.decideGraphAccessReviewItem)

			// Visualization endpoints
			r.Get("/visualize/attack-path/{id}", s.visualizeAttackPath)
			r.Get("/visualize/toxic-combination/{id}", s.visualizeToxicCombination)
			r.Get("/visualize/blast-radius/{principalId}", s.visualizeBlastRadius)
			r.Get("/visualize/report", s.visualizeReport)
		})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.app.Config.Port)
	s.app.Logger.Info("starting server", "addr", addr)

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

func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	http.ServeFile(w, r, "api/openapi.yaml")
}

func (s *Server) swaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Cerebro API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
        layout: "BaseLayout"
      });
    }
  </script>
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
		// Validate table name (these are hardcoded above, but validate for safety)
		if err := snowflake.ValidateTableName(table); err != nil {
			continue
		}
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

	// Validate query - only allow SELECT statements for safety
	if err := validateQuery(req.Query); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := s.app.Snowflake.Query(r.Context(), req.Query)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "query execution failed")
		return
	}
	s.json(w, http.StatusOK, result)
}

// validateQuery ensures only safe read-only queries are executed
func validateQuery(query string) error {
	// Normalize: remove comments, collapse whitespace
	q := normalizeSQL(query)
	q = strings.ToUpper(q)

	// Must start with SELECT or WITH (for CTEs)
	if !strings.HasPrefix(q, "SELECT") && !strings.HasPrefix(q, "WITH") {
		return fmt.Errorf("only SELECT queries are allowed")
	}

	// Block dangerous keywords with word boundary detection
	// Use regex-like matching by checking for word boundaries
	dangerous := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
		"CREATE", "ALTER", "GRANT", "REVOKE", "EXECUTE",
		"CALL", "MERGE", "COPY", "PUT", "GET", "EXEC",
	}
	for _, kw := range dangerous {
		if containsKeyword(q, kw) {
			return fmt.Errorf("query contains forbidden keyword: %s", kw)
		}
	}

	// Block semicolons which could allow statement chaining
	if strings.Contains(q, ";") {
		return fmt.Errorf("query contains forbidden character: semicolon")
	}

	return nil
}

// normalizeSQL removes SQL comments and normalizes whitespace
func normalizeSQL(query string) string {
	// Remove block comments /* ... */
	for {
		start := strings.Index(query, "/*")
		if start == -1 {
			break
		}
		end := strings.Index(query[start:], "*/")
		if end == -1 {
			query = query[:start]
			break
		}
		query = query[:start] + " " + query[start+end+2:]
	}

	// Remove line comments -- ...
	lines := strings.Split(query, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "--"); idx != -1 {
			lines[i] = line[:idx]
		}
	}
	query = strings.Join(lines, " ")

	// Collapse all whitespace to single spaces
	fields := strings.Fields(query)
	return strings.Join(fields, " ")
}

// containsKeyword checks if a SQL keyword exists as a whole word
func containsKeyword(sql, keyword string) bool {
	idx := 0
	for {
		pos := strings.Index(sql[idx:], keyword)
		if pos == -1 {
			return false
		}
		pos += idx

		// Check word boundary before
		validBefore := pos == 0 || !isAlphaNum(sql[pos-1])
		// Check word boundary after
		validAfter := pos+len(keyword) >= len(sql) || !isAlphaNum(sql[pos+len(keyword)])

		if validBefore && validAfter {
			return true
		}
		idx = pos + 1
		if idx >= len(sql) {
			return false
		}
	}
}

func isAlphaNum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
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
	pagination := ParsePagination(r, 100, 1000)

	filter := findings.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		PolicyID: r.URL.Query().Get("policy_id"),
		Limit:    pagination.Limit,
		Offset:   pagination.Offset,
	}

	total := s.app.Findings.Count(filter)
	list := s.app.Findings.List(filter)
	paginationResp := BuildPaginationResponse(int64(total), pagination, len(list))

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings":   list,
		"count":      len(list),
		"pagination": paginationResp,
	})
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

func (s *Server) exportFindings(w http.ResponseWriter, r *http.Request) {
	filter := findings.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		PolicyID: r.URL.Query().Get("policy_id"),
	}
	list := s.app.Findings.List(filter)

	// Enrich findings with cloud URLs, tags, etc.
	for _, f := range list {
		findings.EnrichFinding(f)
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	var data []byte
	var err error
	var contentType string

	switch format {
	case "json":
		exporter := findings.NewJSONExporter(r.URL.Query().Get("pretty") == "true")
		data, err = exporter.Export(list)
		contentType = "application/json"
	default:
		exporter := findings.NewCSVExporter()
		data, err = exporter.Export(list)
		contentType = "text/csv"
	}

	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings.%s", format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) assignFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.Assign(id, req.Assignee); err != nil {
		if err == findings.ErrIssueNotFound {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "assigned", "assignee": req.Assignee})
}

func (s *Server) setFindingDueDate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		DueAt time.Time `json:"due_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.SetDueDate(id, req.DueAt); err != nil {
		if err == findings.ErrIssueNotFound {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) addFindingNote(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.AddNote(id, req.Note); err != nil {
		if err == findings.ErrIssueNotFound {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "note added"})
}

func (s *Server) linkFindingTicket(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		URL        string `json:"url"`
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.LinkTicket(id, req.URL, req.Name, req.ExternalID); err != nil {
		if err == findings.ErrIssueNotFound {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ticket linked"})
}

// Reporting endpoints

func (s *Server) executiveSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	summary := reporter.GenerateExecutiveSummary()
	s.json(w, http.StatusOK, summary)
}

func (s *Server) riskSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	risks := reporter.GenerateRiskSummary()
	s.json(w, http.StatusOK, map[string]interface{}{"risks": risks, "count": len(risks)})
}

func (s *Server) frameworkComplianceReport(w http.ResponseWriter, r *http.Request) {
	framework := chi.URLParam(r, "framework")
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	report := reporter.GenerateFrameworkReport(framework)
	s.json(w, http.StatusOK, report)
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

	// Build evidence map for failing controls
	type Evidence struct {
		Resource   string `json:"resource"`
		FindingID  string `json:"finding_id"`
		Severity   string `json:"severity"`
		DetectedAt string `json:"detected_at"`
	}
	controlEvidence := make(map[string][]Evidence)

	passing := 0
	totalFindings := 0
	for i, ctrl := range framework.Controls {
		// Count findings for this control and gather evidence
		failCount := 0
		var evidence []Evidence
		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := findingsStats.ByPolicy[policyID]; ok {
				failCount += count
			}
			// Get sample findings for evidence (limit to 5 per policy)
			policyFindings := s.app.Findings.List(findings.FindingFilter{PolicyID: policyID, Status: "open"})
			for j, f := range policyFindings {
				if j >= 5 {
					break
				}
				resourceName := f.ResourceID
				if resourceName == "" {
					if arn, ok := f.Resource["arn"].(string); ok {
						resourceName = arn
					} else if name, ok := f.Resource["name"].(string); ok {
						resourceName = name
					}
				}
				evidence = append(evidence, Evidence{
					Resource:   resourceName,
					FindingID:  f.ID,
					Severity:   f.Severity,
					DetectedAt: f.FirstSeen.Format(time.RFC3339),
				})
			}
		}
		totalFindings += failCount

		status := "passing"
		if failCount > 0 {
			status = "failing"
			if len(evidence) > 10 {
				evidence = evidence[:10] // Limit evidence per control
			}
			controlEvidence[ctrl.ID] = evidence
		} else {
			passing++
		}

		report.Controls[i] = compliance.ControlStatus{
			ControlID: ctrl.ID,
			Status:    status,
			FailCount: failCount,
		}
	}

	report.Summary.PassingControls = passing
	report.Summary.FailingControls = len(framework.Controls) - passing
	if len(framework.Controls) > 0 {
		report.Summary.ComplianceScore = float64(passing) / float64(len(framework.Controls)) * 100
	}

	// Calculate weighted score based on control severity
	failingControlIDs := make(map[string]bool)
	for _, ctrl := range report.Controls {
		if ctrl.Status == "failing" {
			failingControlIDs[ctrl.ControlID] = true
		}
	}
	report.Summary.WeightedScore, _, _ = compliance.CalculateWeightedScore(framework.Controls, failingControlIDs)

	// Return enhanced response with evidence
	var dataWarning string
	response := map[string]interface{}{
		"report":         report,
		"total_findings": totalFindings,
		"evidence":       controlEvidence,
	}
	if dataWarning != "" {
		response["data_warning"] = dataWarning
	}

	s.json(w, http.StatusOK, response)
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

	checks := make([]ControlCheck, 0, len(framework.Controls))
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
		"controls":        checks,
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
	messages := make([]agents.Message, 0, len(session.Messages)+1)
	messages = append(messages, agents.Message{Role: "system", Content: "You are a security analyst assistant. Help investigate security findings and incidents. Use the available tools to query data and take actions."})
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

// Incident response endpoints

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req agents.CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Title == "" {
		s.error(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}

	ir := agents.NewIncidentResponse(s.app.Agents)
	incident, err := ir.CreateIncident(r.Context(), req)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusCreated, incident)
}

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	ir := agents.NewIncidentResponse(s.app.Agents)
	playbooks := ir.ListPlaybooks()
	s.json(w, http.StatusOK, map[string]interface{}{
		"playbooks": playbooks,
		"count":     len(playbooks),
	})
}

func (s *Server) getPlaybook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ir := agents.NewIncidentResponse(s.app.Agents)
	playbook := ir.GetPlaybook(id)
	if playbook == nil {
		s.error(w, http.StatusNotFound, "playbook not found")
		return
	}
	s.json(w, http.StatusOK, playbook)
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

	staleUsers := detector.DetectStaleUsers(r.Context(), users)
	unusedKeys := detector.DetectUnusedAccessKeys(r.Context(), creds)
	staleSAs := detector.DetectStaleServiceAccounts(r.Context(), sas)
	allFindings := make([]identity.StaleAccessFinding, 0, len(staleUsers)+len(unusedKeys)+len(staleSAs))
	allFindings = append(allFindings, staleUsers...)
	allFindings = append(allFindings, unusedKeys...)
	allFindings = append(allFindings, staleSAs...)

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": allFindings,
		"count":    len(allFindings),
		"summary": map[string]int{
			"inactive_users":      countByType(allFindings, identity.StaleAccessInactiveUser),
			"unused_keys":         countByType(allFindings, identity.StaleAccessUnusedAccessKey),
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
		"paths":       paths,
		"count":       len(paths),
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
	code := httpStatusToCode(status)
	s.json(w, status, APIError{Error: message, Code: code})
}

func httpStatusToCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "validation_error"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "error"
	}
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
		URL    string               `json:"url"`
		Events []webhooks.EventType `json:"events"`
		Secret string               `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	hook, err := s.app.Webhooks.RegisterWebhook(req.URL, req.Events, req.Secret)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
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
	if err := s.app.Webhooks.EmitWithErrors(r.Context(), "test", map[string]interface{}{
		"message": "Test webhook from Cerebro",
	}); err != nil {
		s.app.Logger.Warn("failed to emit test webhook", "error", err)
	}
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

func (s *Server) dailyDigest(w http.ResponseWriter, r *http.Request) {
	handler := notifications.NewSlackCommandHandler(
		notifications.SlackCommandConfig{},
		s.app.Findings,
	)
	digest := handler.DailyDigest()
	s.json(w, http.StatusOK, digest)
}

func (s *Server) slackCommands(w http.ResponseWriter, r *http.Request) {
	handler := notifications.NewSlackCommandHandler(
		notifications.SlackCommandConfig{
			SigningSecret: s.app.Config.SlackSigningSecret,
		},
		s.app.Findings,
	)
	handler.ServeHTTP(w, r)
}

// Remediation endpoints

func (s *Server) listRemediationRules(w http.ResponseWriter, r *http.Request) {
	engine := remediation.NewEngine(s.app.Logger)
	rules := engine.ListRules()
	s.json(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

func (s *Server) createRemediationRule(w http.ResponseWriter, r *http.Request) {
	var rule remediation.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	engine := remediation.NewEngine(s.app.Logger)
	if err := engine.AddRule(rule); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusCreated, rule)
}

func (s *Server) getRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	engine := remediation.NewEngine(s.app.Logger)
	rule, ok := engine.GetRule(id)
	if !ok {
		s.error(w, http.StatusNotFound, "rule not found")
		return
	}
	s.json(w, http.StatusOK, rule)
}

func (s *Server) enableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	engine := remediation.NewEngine(s.app.Logger)
	if err := engine.EnableRule(id); err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	engine := remediation.NewEngine(s.app.Logger)
	if err := engine.DisableRule(id); err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (s *Server) listRemediationExecutions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	engine := remediation.NewEngine(s.app.Logger)
	executions := engine.ListExecutions(limit)
	s.json(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

func (s *Server) getRemediationExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	engine := remediation.NewEngine(s.app.Logger)
	execution, ok := engine.GetExecution(id)
	if !ok {
		s.error(w, http.StatusNotFound, "execution not found")
		return
	}
	s.json(w, http.StatusOK, execution)
}

func (s *Server) approveExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req struct {
		ApproverID string `json:"approver_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	engine := remediation.NewEngine(s.app.Logger)
	executor := remediation.NewExecutor(engine, s.app.Ticketing, s.app.Notifications, s.app.Findings)

	if err := executor.Approve(r.Context(), id, req.ApproverID); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) rejectExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req struct {
		RejecterID string `json:"rejecter_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	engine := remediation.NewEngine(s.app.Logger)
	executor := remediation.NewExecutor(engine, s.app.Ticketing, s.app.Notifications, s.app.Findings)

	if err := executor.Reject(r.Context(), id, req.RejecterID, req.Reason); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// Threat Intelligence handlers

func (s *Server) listThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.ThreatIntel.ListFeeds())
}

func (s *Server) syncThreatFeed(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.ThreatIntel.SyncFeed(r.Context(), id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (s *Server) threatIntelStats(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.ThreatIntel.Stats())
}

func (s *Server) lookupIP(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	ip := chi.URLParam(r, "ip")
	ind, found := s.app.ThreatIntel.LookupIP(ip)
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "ip": ip})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupDomain(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	domain := chi.URLParam(r, "domain")
	ind, found := s.app.ThreatIntel.LookupDomain(domain)
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "domain": domain})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupCVE(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	cve := chi.URLParam(r, "cve")
	ind, found := s.app.ThreatIntel.LookupCVE(cve)
	isKEV := s.app.ThreatIntel.IsKEV(cve)
	s.json(w, http.StatusOK, map[string]interface{}{
		"found":     found,
		"cve":       cve,
		"is_kev":    isKEV,
		"indicator": ind,
	})
}

// Runtime Detection handlers

func (s *Server) listDetectionRules(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeDetect == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime detection not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RuntimeDetect.ListRules())
}

func (s *Server) ingestRuntimeEvent(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeDetect == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime detection not initialized")
		return
	}

	var event runtime.RuntimeEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.error(w, http.StatusBadRequest, "invalid event")
		return
	}

	findings := s.app.RuntimeDetect.ProcessEvent(r.Context(), &event)

	// Process findings through response engine
	if s.app.RuntimeRespond != nil {
		for _, f := range findings {
			_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"processed": true,
		"findings":  len(findings),
	})
}

func (s *Server) listRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	// Would return recent runtime findings from store
	s.json(w, http.StatusOK, []interface{}{})
}

func (s *Server) listResponsePolicies(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RuntimeRespond.ListPolicies())
}

func (s *Server) enableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.RuntimeRespond.EnablePolicy(id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.RuntimeRespond.DisablePolicy(id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// Lineage handlers

func (s *Server) getAssetLineage(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	assetID := chi.URLParam(r, "assetId")
	lineage, found := s.app.Lineage.GetLineage(assetID)
	if !found {
		s.error(w, http.StatusNotFound, "lineage not found")
		return
	}
	s.json(w, http.StatusOK, lineage)
}

func (s *Server) getLineageByCommit(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	sha := chi.URLParam(r, "sha")
	assets := s.app.Lineage.GetLineageByCommit(sha)
	s.json(w, http.StatusOK, assets)
}

func (s *Server) getLineageByImage(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	digest := chi.URLParam(r, "digest")
	assets := s.app.Lineage.GetLineageByImage(digest)
	s.json(w, http.StatusOK, assets)
}

func (s *Server) detectDrift(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	assetID := chi.URLParam(r, "assetId")

	var req struct {
		CurrentState map[string]interface{} `json:"current_state"`
		IaCState     map[string]interface{} `json:"iac_state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	drifts := s.app.Lineage.DetectDrift(r.Context(), assetID, req.CurrentState, req.IaCState)
	s.json(w, http.StatusOK, map[string]interface{}{
		"asset_id":       assetID,
		"drift_detected": len(drifts) > 0,
		"drifts":         drifts,
	})
}

// RBAC handlers

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RBAC.ListRoles())
}

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	// Return default permissions
	s.json(w, http.StatusOK, []string{
		"findings:read", "findings:write",
		"policies:read", "policies:write",
		"assets:read", "compliance:read", "compliance:export",
		"admin:users", "admin:roles",
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}

	// Require admin:users permission
	userID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), userID, "admin:users") {
		s.error(w, http.StatusForbidden, "permission denied: admin:users required")
		return
	}

	var user auth.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		s.error(w, http.StatusBadRequest, "invalid user")
		return
	}

	if err := s.app.RBAC.CreateUser(&user); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusCreated, user)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	user, found := s.app.RBAC.GetUser(id)
	if !found {
		s.error(w, http.StatusNotFound, "user not found")
		return
	}
	s.json(w, http.StatusOK, user)
}

func (s *Server) assignRole(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}

	// Require admin:roles permission
	currentUserID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), currentUserID, "admin:roles") {
		s.error(w, http.StatusForbidden, "permission denied: admin:roles required")
		return
	}

	targetUserID := chi.URLParam(r, "id")

	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.RBAC.AssignRole(targetUserID, req.RoleID); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RBAC.ListTenants())
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}

	// Require admin:users permission for tenant management
	userID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), userID, "admin:users") {
		s.error(w, http.StatusForbidden, "permission denied: admin:users required")
		return
	}

	var tenant auth.Tenant
	if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
		s.error(w, http.StatusBadRequest, "invalid tenant")
		return
	}

	if err := s.app.RBAC.CreateTenant(&tenant); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusCreated, tenant)
}

// Telemetry ingestion handler

func (s *Server) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Events       []runtime.RuntimeEvent `json:"events"`
		Node         string                 `json:"node"`
		Cluster      string                 `json:"cluster"`
		AgentVersion string                 `json:"agent_version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.error(w, http.StatusBadRequest, "invalid payload")
		return
	}

	totalFindings := 0
	if s.app.RuntimeDetect != nil {
		for _, event := range payload.Events {
			findings := s.app.RuntimeDetect.ProcessEvent(r.Context(), &event)
			totalFindings += len(findings)

			// Process through response engine
			if s.app.RuntimeRespond != nil {
				for _, f := range findings {
					_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
				}
			}
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"processed": len(payload.Events),
		"findings":  totalFindings,
	})
}

// CloudQuery handlers

func (s *Server) listCloudQueryTables(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not initialized")
		return
	}

	tables, err := s.app.Snowflake.ListAvailableTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"tables": tables,
		"count":  len(tables),
	})
}

func (s *Server) getAssetInventory(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not initialized")
		return
	}

	tables, err := s.app.Snowflake.ListAvailableTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	inventory := make(map[string]int)
	for _, table := range tables {
		result, err := s.app.Snowflake.Query(r.Context(), "SELECT COUNT(*) as cnt FROM "+table)
		if err == nil && len(result.Rows) > 0 {
			if cnt, ok := result.Rows[0]["CNT"].(int64); ok {
				inventory[table] = int(cnt)
			}
		}
	}

	s.json(w, http.StatusOK, inventory)
}

func (s *Server) checkDataFreshness(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not initialized")
		return
	}

	table := chi.URLParam(r, "table")
	if table == "" {
		s.error(w, http.StatusBadRequest, "table name required")
		return
	}

	// Check when data was last synced by looking at _cq_sync_time
	result, err := s.app.Snowflake.Query(r.Context(), "SELECT MAX(_cq_sync_time) as last_sync FROM "+table)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"table":     table,
		"last_sync": result.Rows,
	})
}

func (s *Server) getTableStats(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not initialized")
		return
	}

	table := chi.URLParam(r, "table")
	if table == "" {
		s.error(w, http.StatusBadRequest, "table name required")
		return
	}

	result, err := s.app.Snowflake.Query(r.Context(), "SELECT COUNT(*) as count FROM "+table)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"table": table,
		"stats": result.Rows,
	})
}

func (s *Server) ensureCloudQueryTables(w http.ResponseWriter, r *http.Request) {
	// Tables are now auto-created by the sync engine
	s.json(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "tables are auto-created by sync engine",
	})
}

// Scan management handlers

func (s *Server) getScanWatermarks(w http.ResponseWriter, r *http.Request) {
	if s.app.ScanWatermarks == nil {
		s.error(w, http.StatusServiceUnavailable, "scan watermarks not initialized")
		return
	}

	stats := s.app.ScanWatermarks.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) getPolicyCoverage(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not initialized")
		return
	}

	// Get available tables
	availableTables, err := s.app.Snowflake.ListAvailableTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Check which policies can be evaluated
	gaps := s.app.Policy.ValidateTableCoverage(availableTables)

	// Calculate coverage stats
	totalPolicies := len(s.app.Policy.ListPolicies())
	coveredPolicies := totalPolicies - len(gaps)
	coveragePercent := 0.0
	if totalPolicies > 0 {
		coveragePercent = float64(coveredPolicies) / float64(totalPolicies) * 100
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"total_policies":   totalPolicies,
		"covered_policies": coveredPolicies,
		"coverage_percent": coveragePercent,
		"available_tables": len(availableTables),
		"gaps":             gaps,
	})
}

// Security Graph handlers

func (s *Server) graphStats(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	meta := s.app.SecurityGraph.Metadata()
	s.json(w, http.StatusOK, map[string]interface{}{
		"built_at":       meta.BuiltAt,
		"node_count":     meta.NodeCount,
		"edge_count":     meta.EdgeCount,
		"providers":      meta.Providers,
		"accounts":       meta.Accounts,
		"build_duration": meta.BuildDuration.String(),
	})
}

func (s *Server) blastRadius(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := graph.BlastRadius(s.app.SecurityGraph, principalID, maxDepth)
	s.json(w, http.StatusOK, result)
}

func (s *Server) reverseAccess(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	resourceID := chi.URLParam(r, "resourceId")
	if resourceID == "" {
		s.error(w, http.StatusBadRequest, "resource ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := graph.ReverseAccess(s.app.SecurityGraph, resourceID, maxDepth)
	s.json(w, http.StatusOK, result)
}

func (s *Server) rebuildGraph(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraphBuilder == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	if err := s.app.RebuildSecurityGraph(r.Context()); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	meta := s.app.SecurityGraph.Metadata()
	s.json(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"built_at":       meta.BuiltAt,
		"node_count":     meta.NodeCount,
		"edge_count":     meta.EdgeCount,
		"build_duration": meta.BuildDuration.String(),
	})
}

// CloudQuery sync webhook handler - triggers graph rebuild when IAM data is synced
func (s *Server) cloudQuerySyncWebhook(w http.ResponseWriter, r *http.Request) {
	// Parse the webhook payload
	var payload struct {
		Tables []string `json:"tables"`
		Status string   `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.error(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Emit cloudquery synced event
	if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventCloudQuerySynced, map[string]interface{}{
		"tables": payload.Tables,
		"status": payload.Status,
	}); err != nil {
		s.app.Logger.Warn("failed to emit cloudquery webhook", "error", err)
	}

	// Check if any IAM tables were synced - if so, rebuild the graph
	iamTables := []string{
		"aws_iam_users", "aws_iam_roles", "aws_iam_groups",
		"aws_iam_policies", "aws_iam_user_attached_policies",
		"aws_iam_role_attached_policies", "aws_iam_user_policies",
		"aws_iam_role_policies", "aws_iam_group_policies",
		"aws_iam_user_groups",
	}

	shouldRebuild := false
	for _, table := range payload.Tables {
		for _, iamTable := range iamTables {
			if table == iamTable {
				shouldRebuild = true
				break
			}
		}
		if shouldRebuild {
			break
		}
	}

	if shouldRebuild && s.app.SecurityGraphBuilder != nil {
		// Rebuild graph asynchronously
		go func() {
			ctx := context.Background()
			if err := s.app.RebuildSecurityGraph(ctx); err != nil {
				s.app.Logger.Error("failed to rebuild graph after cloudquery sync", "error", err)
			}
		}()
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"received":       true,
		"tables":         payload.Tables,
		"rebuild_queued": shouldRebuild,
	})
}

// Risk Intelligence endpoints

func (s *Server) riskReport(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	engine := graph.NewRiskEngine(s.app.SecurityGraph)
	report := engine.Analyze()
	s.json(w, http.StatusOK, report)
}

func (s *Server) listToxicCombinations(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	engine := graph.NewToxicCombinationEngine()
	results := engine.Analyze(s.app.SecurityGraph)

	// Filter by severity if requested
	severityFilter := r.URL.Query().Get("severity")
	if severityFilter != "" {
		filtered := make([]*graph.ToxicCombination, 0)
		for _, tc := range results {
			if string(tc.Severity) == severityFilter {
				filtered = append(filtered, tc)
			}
		}
		results = filtered
	}

	// Limit results
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}
	if len(results) > limit {
		results = results[:limit]
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"total":   len(results),
		"results": results,
	})
}

func (s *Server) listGraphAttackPaths(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)

	maxDepth := 6
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := simulator.Simulate(maxDepth)

	// Filter by score threshold
	threshold := 0.0
	if threshStr := r.URL.Query().Get("threshold"); threshStr != "" {
		if t, err := strconv.ParseFloat(threshStr, 64); err == nil {
			threshold = t
		}
	}

	if threshold > 0 {
		filtered := make([]*graph.ScoredAttackPath, 0)
		for _, path := range result.Paths {
			if path.TotalScore >= threshold {
				filtered = append(filtered, path)
			}
		}
		result.Paths = filtered
	}

	// Limit results
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}
	if len(result.Paths) > limit {
		result.Paths = result.Paths[:limit]
	}

	s.json(w, http.StatusOK, result)
}

func (s *Server) simulateAttackPathFix(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	nodeID := chi.URLParam(r, "id")
	if nodeID == "" {
		s.error(w, http.StatusBadRequest, "node ID required")
		return
	}

	simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)
	result := simulator.Simulate(6)
	fixSim := simulator.SimulateFix(result, nodeID)

	s.json(w, http.StatusOK, fixSim)
}

func (s *Server) listChokepoints(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)
	result := simulator.Simulate(6)

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	chokepoints := result.Chokepoints
	if len(chokepoints) > limit {
		chokepoints = chokepoints[:limit]
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"total":       len(result.Chokepoints),
		"chokepoints": chokepoints,
	})
}

func (s *Server) detectPrivilegeEscalation(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	risks := graph.DetectPrivilegeEscalationRisks(s.app.SecurityGraph, principalID)

	s.json(w, http.StatusOK, map[string]interface{}{
		"principal_id": principalID,
		"risk_count":   len(risks),
		"risks":        risks,
	})
}

// Peer Groups and Access Analysis endpoints

func (s *Server) analyzePeerGroups(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	minSimilarity := 0.7
	if simStr := r.URL.Query().Get("min_similarity"); simStr != "" {
		if sim, err := strconv.ParseFloat(simStr, 64); err == nil && sim > 0 && sim <= 1 {
			minSimilarity = sim
		}
	}

	minGroupSize := 2
	if sizeStr := r.URL.Query().Get("min_group_size"); sizeStr != "" {
		if size, err := strconv.Atoi(sizeStr); err == nil && size > 1 {
			minGroupSize = size
		}
	}

	analysis := graph.AnalyzePeerGroups(s.app.SecurityGraph, minSimilarity, minGroupSize)
	privilegeCreep := graph.FindPrivilegeCreep(s.app.SecurityGraph, 1.5)

	s.json(w, http.StatusOK, map[string]interface{}{
		"total_principals": analysis.TotalPrincipals,
		"groups":           analysis.Groups,
		"ungrouped":        analysis.Ungrouped,
		"outliers":         analysis.Outliers,
		"privilege_creep":  privilegeCreep,
	})
}

func (s *Server) getEffectivePermissions(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	calc := graph.NewEffectivePermissionsCalculator(s.app.SecurityGraph)
	perms := calc.Calculate(principalID)

	s.json(w, http.StatusOK, perms)
}

func (s *Server) comparePermissions(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principal1 := r.URL.Query().Get("principal1")
	principal2 := r.URL.Query().Get("principal2")
	if principal1 == "" || principal2 == "" {
		s.error(w, http.StatusBadRequest, "principal1 and principal2 query params required")
		return
	}

	comparison := graph.CompareAccess(s.app.SecurityGraph, principal1, principal2)

	s.json(w, http.StatusOK, comparison)
}

// Graph-based Access Review endpoints

var graphAccessReviews = make(map[string]*graph.AccessReview)
var graphAccessReviewsMu sync.RWMutex

func (s *Server) createGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Scope       graph.ReviewScope `json:"scope"`
		CreatedBy   string            `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	review := graph.CreateAccessReview(s.app.SecurityGraph, req.Name, req.Scope, req.CreatedBy)
	review.Description = req.Description

	graphAccessReviewsMu.Lock()
	graphAccessReviews[review.ID] = review
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusCreated, review)
}

func (s *Server) listGraphAccessReviews(w http.ResponseWriter, r *http.Request) {
	graphAccessReviewsMu.RLock()
	reviews := make([]*graph.AccessReview, 0, len(graphAccessReviews))
	for _, review := range graphAccessReviews {
		reviews = append(reviews, review)
	}
	graphAccessReviewsMu.RUnlock()

	s.json(w, http.StatusOK, map[string]interface{}{
		"reviews": reviews,
		"count":   len(reviews),
	})
}

func (s *Server) getGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	graphAccessReviewsMu.RLock()
	review, ok := graphAccessReviews[id]
	graphAccessReviewsMu.RUnlock()

	if !ok {
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	s.json(w, http.StatusOK, review)
}

func (s *Server) startGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	id := chi.URLParam(r, "id")

	graphAccessReviewsMu.Lock()
	review, ok := graphAccessReviews[id]
	if !ok {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	review.Start()
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusOK, review)
}

func (s *Server) decideGraphAccessReviewItem(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
	itemID := chi.URLParam(r, "itemId")

	var decision graph.ReviewDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	graphAccessReviewsMu.Lock()
	review, ok := graphAccessReviews[reviewID]
	if !ok {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	if !review.RecordDecision(itemID, decision) {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "review item not found")
		return
	}
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}

// Visualization endpoints (Mermaid)

func (s *Server) visualizeAttackPath(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	pathIndex := chi.URLParam(r, "id")
	idx, err := strconv.Atoi(pathIndex)
	if err != nil || idx < 0 {
		s.error(w, http.StatusBadRequest, "valid path index required")
		return
	}

	simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)
	result := simulator.Simulate(6)

	if idx >= len(result.Paths) {
		s.error(w, http.StatusNotFound, "attack path not found")
		return
	}

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportAttackPath(result.Paths[idx])

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid))
}

func (s *Server) visualizeToxicCombination(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	tcID := chi.URLParam(r, "id")
	if tcID == "" {
		s.error(w, http.StatusBadRequest, "toxic combination ID required")
		return
	}

	engine := graph.NewToxicCombinationEngine()
	results := engine.Analyze(s.app.SecurityGraph)

	var targetTC *graph.ToxicCombination
	for _, tc := range results {
		if tc.ID == tcID {
			targetTC = tc
			break
		}
	}

	if targetTC == nil {
		s.error(w, http.StatusNotFound, "toxic combination not found")
		return
	}

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportToxicCombination(targetTC)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid))
}

func (s *Server) visualizeBlastRadius(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := graph.BlastRadius(s.app.SecurityGraph, principalID, maxDepth)
	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportBlastRadius(result)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid))
}

func (s *Server) visualizeReport(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	engine := graph.NewRiskEngine(s.app.SecurityGraph)
	report := engine.Analyze()

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportSecurityReport(report)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid))
}

// Ensure imports are used
var (
	_ = auth.User{}
	_ = lineage.AssetLineage{}
	_ = runtime.RuntimeEvent{}
	_ = threatintel.Feed{}
)
