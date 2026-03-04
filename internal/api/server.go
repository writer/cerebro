package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/auth"
	"github.com/writerinternal/cerebro/internal/graph"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/metrics"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/remediation"
	"github.com/writerinternal/cerebro/internal/runtime"
	"github.com/writerinternal/cerebro/internal/scheduler"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"github.com/writerinternal/cerebro/internal/webhooks"
)

// Server is the fully wired API server
type Server struct {
	app         *app.App
	router      *chi.Mux
	auditLogger auditLogWriter
}

type auditLogWriter interface {
	Log(ctx context.Context, entry *snowflake.AuditEntry) error
}

// NewServer creates a new server with all services wired
func NewServer(application *app.App) *Server {
	s := &Server{
		app:         application,
		router:      chi.NewRouter(),
		auditLogger: application.AuditRepo,
	}
	s.setupMiddleware()
	s.setupRoutes()
	return s
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

// Sync status - data freshness from asset tables
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

		if len(result.Rows) > 0 {
			lastSync := parseLastSyncRow(result.Rows[0])
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

func parseLastSyncRow(row map[string]interface{}) time.Time {
	value, ok := queryRowValue(row, "last_sync")
	if !ok {
		return time.Time{}
	}
	return parseLastSyncValue(value)
}

func parseLastSyncValue(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case *time.Time:
		if typed == nil {
			return time.Time{}
		}
		return *typed
	case string:
		if typed == "" {
			return time.Time{}
		}
		if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed
		}
	}

	return time.Time{}
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
		Query          string `json:"query"`
		Limit          int    `json:"limit"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	boundedQuery, boundedLimit, err := snowflake.BuildReadOnlyLimitedQuery(req.Query, req.Limit)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	queryCtx, cancel := context.WithTimeout(r.Context(), snowflake.ClampReadOnlyQueryTimeout(req.TimeoutSeconds))
	defer cancel()

	result, err := s.app.Snowflake.Query(queryCtx, boundedQuery)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "query execution failed")
		return
	}

	if result != nil && result.Count > boundedLimit {
		result.Rows = result.Rows[:boundedLimit]
		result.Count = len(result.Rows)
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

// Identity/Access Review endpoints

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
	pathID := chi.URLParam(r, "id")
	if pathID == "" {
		s.error(w, http.StatusBadRequest, "path ID required")
		return
	}

	maxDepth := 10
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 {
			maxDepth = d
		}
	}

	highValueTargets := make([]string, 0)
	if rawTargets := strings.TrimSpace(r.URL.Query().Get("targets")); rawTargets != "" {
		for _, target := range strings.Split(rawTargets, ",") {
			target = strings.TrimSpace(target)
			if target != "" {
				highValueTargets = append(highValueTargets, target)
			}
		}
	}

	if len(highValueTargets) == 0 {
		for _, node := range s.app.AttackPath.GetAllNodes() {
			if node.Type != attackpath.NodeTypeExternal {
				highValueTargets = append(highValueTargets, node.ID)
			}
		}
	}

	finder := attackpath.NewPathFinder(s.app.AttackPath, maxDepth)
	finder.SetHighValueTargets(highValueTargets)

	for _, path := range finder.FindPaths(r.Context()) {
		if path.ID == pathID {
			s.json(w, http.StatusOK, path)
			return
		}
	}

	s.error(w, http.StatusNotFound, "attack path not found")
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
		switch {
		case errors.Is(err, scheduler.ErrJobNotFound):
			s.error(w, http.StatusNotFound, err.Error())
		case errors.Is(err, scheduler.ErrJobAlreadyRunning):
			s.error(w, http.StatusConflict, err.Error())
		default:
			s.error(w, http.StatusInternalServerError, err.Error())
		}
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
	rules := s.app.Remediation.ListRules()
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

	if err := s.app.Remediation.AddRule(rule); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusCreated, rule)
}

func (s *Server) getRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, ok := s.app.Remediation.GetRule(id)
	if !ok {
		s.error(w, http.StatusNotFound, "rule not found")
		return
	}
	s.json(w, http.StatusOK, rule)
}

func (s *Server) enableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Remediation.EnableRule(id); err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Remediation.DisableRule(id); err != nil {
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

	executions := s.app.Remediation.ListExecutions(limit)
	s.json(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

func (s *Server) getRemediationExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	execution, ok := s.app.Remediation.GetExecution(id)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.RemediationExecutor.Approve(r.Context(), id, req.ApproverID); err != nil {
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

	if err := s.app.RemediationExecutor.Reject(r.Context(), id, req.RejecterID, req.Reason); err != nil {
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
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	findings := s.app.RuntimeDetect.RecentFindings(limit)
	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
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
		"agents:read", "agents:write",
		"tickets:read", "tickets:write",
		"runtime:read", "runtime:write",
		"graph:read", "graph:write",
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

	report := s.app.Policy.CoverageReport(availableTables)

	s.json(w, http.StatusOK, map[string]interface{}{
		"total_policies":            report.TotalPolicies,
		"covered_policies":          report.CoveredPolicies,
		"uncovered_policies":        report.UncoveredPolicies,
		"unknown_resource_policies": report.UnknownResourcePolicies,
		"coverage_percent":          report.CoveragePercent,
		"known_coverage_percent":    report.KnownCoveragePercent,
		"available_tables":          len(availableTables),
		"gaps":                      report.Gaps,
		"missing_tables":            report.MissingTables,
		"missing_by_provider":       report.MissingByProvider,
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

func (s *Server) cascadingBlastRadius(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 6
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := graph.CascadingBlastRadius(s.app.SecurityGraph, principalID, maxDepth)
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
