package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/webhooks"
)

func (s *Server) detectStaleAccess(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	detector := identity.NewStaleAccessDetector(identity.DefaultThresholds())
	fetch := func(table string) []map[string]interface{} {
		rows, err := s.app.Warehouse.GetAssets(r.Context(), table, snowflake.AssetFilter{Limit: 1000})
		if err != nil {
			return []map[string]interface{}{}
		}
		return rows
	}

	users := make([]map[string]interface{}, 0)
	users = append(users, fetch("aws_iam_users")...)
	users = append(users, fetch("okta_users")...)
	users = append(users, fetch("azure_ad_users")...)
	users = append(users, fetch("entra_users")...)
	users = append(users, fetch("google_workspace_users")...)

	credentials := fetch("aws_iam_credential_reports")

	serviceAccounts := make([]map[string]interface{}, 0)
	serviceAccounts = append(serviceAccounts, fetch("gcp_iam_service_accounts")...)
	serviceAccounts = append(serviceAccounts, fetch("k8s_core_service_accounts")...)

	hrData := make([]map[string]interface{}, 0)
	hrData = append(hrData, fetch("bamboohr_employees")...)
	hrData = append(hrData, fetch("workday_workers")...)

	roleBindings := make([]map[string]interface{}, 0)
	roleBindings = append(roleBindings, fetch("azure_rbac_role_assignments")...)
	roleBindings = append(roleBindings, fetch("k8s_rbac_risky_bindings")...)

	allFindings := collectStaleAccessFindings(r.Context(), detector, users, credentials, serviceAccounts, hrData, roleBindings)
	persistedCount, remediatedCount := s.persistStaleAccessFindings(r.Context(), allFindings)

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings":           allFindings,
		"count":              len(allFindings),
		"persisted_findings": persistedCount,
		"remediation_runs":   remediatedCount,
		"summary": map[string]int{
			"inactive_users":      countByType(allFindings, identity.StaleAccessInactiveUser),
			"unused_keys":         countByType(allFindings, identity.StaleAccessUnusedAccessKey),
			"orphaned_accounts":   countByType(allFindings, identity.StaleAccessOrphanedAccount),
			"excessive_privilege": countByType(allFindings, identity.StaleAccessExcessivePrivilege),
			"stale_service_accts": countByType(allFindings, identity.StaleAccessStaleServiceAccount),
		},
	})
}

func collectStaleAccessFindings(
	ctx context.Context,
	detector *identity.StaleAccessDetector,
	users []map[string]interface{},
	credentials []map[string]interface{},
	serviceAccounts []map[string]interface{},
	hrData []map[string]interface{},
	roleBindings []map[string]interface{},
) []identity.StaleAccessFinding {
	if detector == nil {
		return nil
	}

	collected := make([]identity.StaleAccessFinding, 0)
	seen := make(map[string]bool)
	appendUnique := func(items []identity.StaleAccessFinding) {
		for _, finding := range items {
			if seen[finding.ID] {
				continue
			}
			seen[finding.ID] = true
			collected = append(collected, finding)
		}
	}

	appendUnique(detector.DetectStaleUsers(ctx, users))
	appendUnique(detector.DetectUnusedAccessKeys(ctx, credentials))
	appendUnique(detector.DetectStaleServiceAccounts(ctx, serviceAccounts))
	if len(hrData) > 0 {
		appendUnique(detector.DetectOrphanedAccounts(ctx, users, hrData))
	}
	if len(roleBindings) > 0 {
		appendUnique(detector.DetectExcessivePrivileges(ctx, roleBindings))
	}
	return collected
}

func (s *Server) persistStaleAccessFindings(ctx context.Context, staleFindings []identity.StaleAccessFinding) (int, int) {
	if s.app.Findings == nil || len(staleFindings) == 0 {
		return 0, 0
	}

	persistedCount := 0
	remediationRuns := 0
	for _, staleFinding := range staleFindings {
		policyFinding := staleFinding.ToPolicyFinding()
		finding := s.app.Findings.Upsert(ctx, policyFinding)
		persistedCount++

		// Only trigger remediation on first observation.
		if !finding.FirstSeen.Equal(finding.LastSeen) {
			continue
		}
		if s.app.Remediation == nil || s.app.RemediationExecutor == nil {
			continue
		}

		event := remediation.Event{
			Type:       remediation.TriggerFindingCreated,
			FindingID:  finding.ID,
			Severity:   strings.ToLower(strings.TrimSpace(finding.Severity)),
			PolicyID:   finding.PolicyID,
			SignalType: finding.SignalType,
			Domain:     finding.Domain,
			EntityID:   finding.ResourceID,
			Data: map[string]any{
				"resource_id":   finding.ResourceID,
				"resource_type": finding.ResourceType,
				"provider":      staleFinding.Provider,
				"account":       staleFinding.Account,
				"days_since":    staleFinding.DaysSince,
			},
		}

		executions, err := s.app.Remediation.Evaluate(ctx, event)
		if err != nil {
			s.app.Logger.Warn("failed to evaluate stale-access remediation", "finding_id", finding.ID, "error", err)
			continue
		}
		for _, execution := range executions {
			if err := s.app.RemediationExecutor.Execute(ctx, execution); err != nil {
				s.app.Logger.Warn("failed to execute stale-access remediation", "execution_id", execution.ID, "error", err)
				continue
			}
			remediationRuns++
		}
	}

	return persistedCount, remediationRuns
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

	if s.app.Warehouse != nil {
		// Load identity data from various tables
		if users, err := s.app.Warehouse.GetAssets(r.Context(), "aws_iam_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if users, err := s.app.Warehouse.GetAssets(r.Context(), "okta_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if users, err := s.app.Warehouse.GetAssets(r.Context(), "azure_ad_users", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Users = append(data.Users, users...)
		}
		if sas, err := s.app.Warehouse.GetAssets(r.Context(), "gcp_iam_service_accounts", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.ServiceAccounts = sas
		}
		if creds, err := s.app.Warehouse.GetAssets(r.Context(), "aws_iam_credential_reports", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Credentials = creds
		}
		if roles, err := s.app.Warehouse.GetAssets(r.Context(), "aws_iam_roles", snowflake.AssetFilter{Limit: 1000}); err == nil {
			data.Roles = roles
		}
	}

	report, err := generator.GenerateReport(r.Context(), data)
	if err != nil {
		s.errorFromErr(w, err)
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
	pagination := ParsePagination(r, 100, 1000)
	hooks := s.app.Webhooks.ListWebhooks()
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].ID < hooks[j].ID })

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
	paged, paginationResp := paginateSlice(result, pagination)
	s.json(w, http.StatusOK, map[string]interface{}{
		"webhooks":    paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(result),
	})
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
	pagination := ParsePagination(r, 100, 1000)
	resourceType := r.URL.Query().Get("resource_type")
	resourceID := r.URL.Query().Get("resource_id")

	limit := pagination.Limit
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsedLimit, err := strconv.Atoi(rawLimit)
		if err != nil || parsedLimit <= 0 {
			s.error(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if parsedLimit > pagination.Limit {
			limit = pagination.Limit
		} else {
			limit = parsedLimit
		}
	}

	offset := pagination.Offset
	if rawOffset := strings.TrimSpace(r.URL.Query().Get("offset")); rawOffset != "" {
		parsedOffset, err := strconv.Atoi(rawOffset)
		if err != nil || parsedOffset < 0 {
			s.error(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = parsedOffset
	}

	if s.app.AuditRepo == nil {
		s.json(w, http.StatusOK, map[string]interface{}{
			"logs":       []interface{}{},
			"count":      0,
			"message":    "snowflake not configured",
			"pagination": PaginationResponse{Limit: limit, Offset: offset, HasMore: false},
		})
		return
	}

	fetchLimit := limit + offset + 1
	if fetchLimit > 1000 {
		fetchLimit = 1000
	}

	logs, err := s.app.AuditRepo.List(r.Context(), resourceType, resourceID, fetchLimit)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	if offset > len(logs) {
		offset = len(logs)
	}

	window := logs[offset:]
	hasMore := len(window) > limit
	if hasMore {
		window = window[:limit]
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"logs":       window,
		"count":      len(window),
		"pagination": PaginationResponse{Limit: limit, Offset: offset, HasMore: hasMore},
	})
}

// Scheduler endpoints
