package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/webhooks"
)

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

	if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventWebhookCreated, map[string]interface{}{
		"webhook_id": hook.ID,
		"events":     hook.Events,
		"created_by": GetUserID(r.Context()),
	}); err != nil {
		s.app.Logger.Warn("failed to emit webhook created event", "webhook_id", hook.ID, "error", err)
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
