package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/webhooks"
)

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RBAC.ListRoles())
}

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RBAC.ListPermissionIDs())
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if s.app.RBAC == nil {
		s.error(w, http.StatusServiceUnavailable, "rbac not initialized")
		return
	}

	userID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), userID, "admin.rbac.users.manage") {
		s.error(w, http.StatusForbidden, "permission denied: admin.rbac.users.manage required")
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

	currentUserID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), currentUserID, "admin.rbac.roles.manage") {
		s.error(w, http.StatusForbidden, "permission denied: admin.rbac.roles.manage required")
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

	userID := GetUserID(r.Context())
	if !s.app.RBAC.HasPermission(r.Context(), userID, "admin.rbac.users.manage") {
		s.error(w, http.StatusForbidden, "permission denied: admin.rbac.users.manage required")
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

	availableTables, err := s.app.Snowflake.ListAvailableTables(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
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
