package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) listOrgPolicyTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.orgPolicies.ListTemplates(r.Context(), strings.TrimSpace(r.URL.Query().Get("framework")))
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":     len(templates),
		"templates": templates,
	})
}

func (s *Server) upsertOrgPolicy(w http.ResponseWriter, r *http.Request) {
	var req orgPolicyWriteRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.orgPolicies.UpsertPolicy(r.Context(), req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) acknowledgeOrgPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		s.error(w, http.StatusBadRequest, "policy id is required")
		return
	}

	var req graph.OrganizationalPolicyAcknowledgmentRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if current := strings.TrimSpace(req.PolicyID); current != "" && current != policyID {
		s.error(w, http.StatusBadRequest, "policy_id must match path id")
		return
	}
	req.PolicyID = policyID

	result, err := s.orgPolicies.AcknowledgePolicy(r.Context(), req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) orgPolicyProgramStatus(w http.ResponseWriter, r *http.Request) {
	report, err := s.orgPolicies.ProgramStatus(r.Context(), strings.TrimSpace(r.URL.Query().Get("framework")))
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgPolicyReviewSchedule(w http.ResponseWriter, r *http.Request) {
	asOf := time.Time{}
	if raw := strings.TrimSpace(r.URL.Query().Get("as_of")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "as_of must be RFC3339")
			return
		}
		asOf = parsed
	}

	report, err := s.orgPolicies.ReviewSchedule(r.Context(), asOf)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgPolicyAcknowledgmentStatus(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		s.error(w, http.StatusBadRequest, "policy id is required")
		return
	}

	report, err := s.orgPolicies.PolicyStatus(r.Context(), policyID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgPolicyAssignees(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		s.error(w, http.StatusBadRequest, "policy id is required")
		return
	}

	report, err := s.orgPolicies.PolicyAssignees(r.Context(), policyID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgPolicyReminders(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		s.error(w, http.StatusBadRequest, "policy id is required")
		return
	}

	report, err := s.orgPolicies.PolicyReminders(r.Context(), policyID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgPolicyVersionHistory(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		s.error(w, http.StatusBadRequest, "policy id is required")
		return
	}

	history, err := s.orgPolicies.PolicyVersionHistory(r.Context(), policyID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":   len(history),
		"history": history,
	})
}
