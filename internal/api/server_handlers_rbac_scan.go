package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/auth"
)

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.rbacAdmin.ListRoles(r.Context())
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, roles)
}

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := s.rbacAdmin.ListPermissions(r.Context())
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, permissions)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var user auth.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		s.error(w, http.StatusBadRequest, "invalid user")
		return
	}

	created, err := s.rbacAdmin.CreateUser(r.Context(), GetUserID(r.Context()), user)
	if err != nil {
		switch {
		case errors.Is(err, errRBACUnavailable):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, errRBACUsersManageRequired):
			s.error(w, http.StatusForbidden, err.Error())
		default:
			s.error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.json(w, http.StatusCreated, created)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, found, err := s.rbacAdmin.GetUser(r.Context(), id)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !found {
		s.error(w, http.StatusNotFound, "user not found")
		return
	}
	s.json(w, http.StatusOK, user)
}

func (s *Server) assignRole(w http.ResponseWriter, r *http.Request) {
	targetUserID := chi.URLParam(r, "id")

	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.rbacAdmin.AssignRole(r.Context(), GetUserID(r.Context()), targetUserID, req.RoleID); err != nil {
		switch {
		case errors.Is(err, errRBACUnavailable):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, errRBACRolesManageRequired):
			s.error(w, http.StatusForbidden, err.Error())
		default:
			s.error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.rbacAdmin.ListTenants(r.Context())
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, tenants)
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var tenant auth.Tenant
	if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
		s.error(w, http.StatusBadRequest, "invalid tenant")
		return
	}

	created, err := s.rbacAdmin.CreateTenant(r.Context(), GetUserID(r.Context()), tenant)
	if err != nil {
		switch {
		case errors.Is(err, errRBACUnavailable):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, errRBACUsersManageRequired):
			s.error(w, http.StatusForbidden, err.Error())
		default:
			s.error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.json(w, http.StatusCreated, created)
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
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "warehouse not initialized")
		return
	}

	availableTables, err := s.app.Warehouse.ListAvailableTables(r.Context())
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
