package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/webhooks"
)

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
	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventThreatIntelSynced, map[string]interface{}{
			"feed_id":      id,
			"triggered_by": GetUserID(r.Context()),
		}); err != nil {
			s.app.Logger.Warn("failed to emit threat intel sync event", "feed_id", id, "error", err)
		}
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

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, map[string]interface{}{
			"source":   "runtime_event",
			"findings": len(findings),
		}); err != nil {
			s.app.Logger.Warn("failed to emit runtime ingest event", "error", err)
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

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRbacUserCreated, map[string]interface{}{
			"user_id":    user.ID,
			"tenant_id":  user.TenantID,
			"created_by": userID,
		}); err != nil {
			s.app.Logger.Warn("failed to emit RBAC user event", "user_id", user.ID, "error", err)
		}
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

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRbacRoleAssigned, map[string]interface{}{
			"target_user_id": targetUserID,
			"role_id":        req.RoleID,
			"assigned_by":    currentUserID,
		}); err != nil {
			s.app.Logger.Warn("failed to emit RBAC role assignment event", "target_user_id", targetUserID, "role_id", req.RoleID, "error", err)
		}
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

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRbacTenantCreated, map[string]interface{}{
			"tenant_id":  tenant.ID,
			"created_by": userID,
		}); err != nil {
			s.app.Logger.Warn("failed to emit RBAC tenant event", "tenant_id", tenant.ID, "error", err)
		}
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

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, map[string]interface{}{
			"source":           "telemetry",
			"events_processed": len(payload.Events),
			"findings":         totalFindings,
			"node":             payload.Node,
			"cluster":          payload.Cluster,
		}); err != nil {
			s.app.Logger.Warn("failed to emit telemetry ingest event", "error", err)
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
