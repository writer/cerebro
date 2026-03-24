package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/workloadscan"
)

type forensicsCaptureRequest struct {
	ID            string                `json:"id,omitempty"`
	IncidentID    string                `json:"incident_id,omitempty"`
	WorkloadID    string                `json:"workload_id,omitempty"`
	RequestedBy   string                `json:"requested_by,omitempty"`
	Reason        string                `json:"reason,omitempty"`
	RetentionDays int                   `json:"retention_days,omitempty"`
	Target        workloadscan.VMTarget `json:"target"`
	Metadata      map[string]any        `json:"metadata,omitempty"`
}

type forensicsRemediationEvidenceRequest struct {
	ID                     string         `json:"id,omitempty"`
	IncidentID             string         `json:"incident_id,omitempty"`
	WorkloadID             string         `json:"workload_id,omitempty"`
	BeforeCaptureID        string         `json:"before_capture_id,omitempty"`
	AfterCaptureID         string         `json:"after_capture_id,omitempty"`
	RemediationExecutionID string         `json:"remediation_execution_id,omitempty"`
	ActionSummary          string         `json:"action_summary,omitempty"`
	Actor                  string         `json:"actor,omitempty"`
	Status                 string         `json:"status,omitempty"`
	Notes                  string         `json:"notes,omitempty"`
	Metadata               map[string]any `json:"metadata,omitempty"`
}

type forensicsCaptureCollection struct {
	GeneratedAt time.Time                 `json:"generated_at"`
	Count       int                       `json:"count"`
	Captures    []forensics.CaptureRecord `json:"captures"`
}

func (s *Server) createForensicCapture(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	var req forensicsCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.IncidentID = strings.TrimSpace(req.IncidentID)
	req.WorkloadID = strings.TrimSpace(req.WorkloadID)
	req.RequestedBy = firstNonEmpty(strings.TrimSpace(req.RequestedBy), strings.TrimSpace(GetUserID(r.Context())))
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Target.Provider == "" || strings.TrimSpace(req.Target.Identity()) == "" {
		s.error(w, http.StatusBadRequest, "target with provider and identity is required")
		return
	}
	record, err := s.forensics.CreateCapture(r.Context(), req)
	if err != nil {
		if errors.Is(err, errForensicsUnavailable) {
			s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, record)
}

func (s *Server) listForensicCaptures(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	limit, err := parseOptionalIntQuery(r, "limit", 50, 1, 200)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	statuses, err := parseCaptureStatuses(queryCSVValues(r, "status"))
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	captures, err := s.forensics.ListCaptures(r.Context(), forensics.CaptureListOptions{
		Statuses:   statuses,
		IncidentID: strings.TrimSpace(r.URL.Query().Get("incident_id")),
		WorkloadID: strings.TrimSpace(r.URL.Query().Get("workload_id")),
		Limit:      limit,
	})
	if err != nil {
		if errors.Is(err, errForensicsUnavailable) {
			s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, forensicsCaptureCollection{
		GeneratedAt: time.Now().UTC(),
		Count:       len(captures),
		Captures:    captures,
	})
}

func (s *Server) getForensicCapture(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	captureID := strings.TrimSpace(chi.URLParam(r, "capture_id"))
	if captureID == "" {
		s.error(w, http.StatusBadRequest, "capture id required")
		return
	}
	record, ok, err := s.forensics.GetCapture(r.Context(), captureID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "forensic capture not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) recordRemediationEvidence(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	var req forensicsRemediationEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Actor = firstNonEmpty(strings.TrimSpace(req.Actor), strings.TrimSpace(GetUserID(r.Context())))
	if strings.TrimSpace(req.BeforeCaptureID) == "" && strings.TrimSpace(req.AfterCaptureID) == "" && strings.TrimSpace(req.RemediationExecutionID) == "" {
		s.error(w, http.StatusBadRequest, "before_capture_id, after_capture_id, or remediation_execution_id is required")
		return
	}
	record, err := s.forensics.RecordRemediationEvidence(r.Context(), req)
	if err != nil {
		if errors.Is(err, errForensicsUnavailable) {
			s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, record)
}

func (s *Server) getRemediationEvidence(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	evidenceID := strings.TrimSpace(chi.URLParam(r, "evidence_id"))
	if evidenceID == "" {
		s.error(w, http.StatusBadRequest, "evidence id required")
		return
	}
	record, ok, err := s.forensics.GetRemediationEvidence(r.Context(), evidenceID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "remediation evidence not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) exportForensicEvidence(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.forensics == nil {
		s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
		return
	}
	evidenceID := strings.TrimSpace(chi.URLParam(r, "evidence_id"))
	if evidenceID == "" {
		s.error(w, http.StatusBadRequest, "evidence id required")
		return
	}
	pkg, err := s.forensics.ExportEvidencePackage(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, errForensicsUnavailable) {
			s.error(w, http.StatusServiceUnavailable, "forensics not initialized")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, pkg)
}

func parseCaptureStatuses(values []string) ([]forensics.CaptureStatus, error) {
	if len(values) == 0 {
		return nil, nil
	}
	statuses := make([]forensics.CaptureStatus, 0, len(values))
	seen := make(map[forensics.CaptureStatus]struct{}, len(values))
	for _, value := range values {
		status := forensics.CaptureStatus(strings.ToLower(strings.TrimSpace(value)))
		switch status {
		case forensics.CaptureStatusPending, forensics.CaptureStatusCaptured, forensics.CaptureStatusPartial, forensics.CaptureStatusFailed:
		default:
			return nil, errBadRequest("status must be one of pending, captured, partial, failed")
		}
		if _, ok := seen[status]; ok {
			continue
		}
		seen[status] = struct{}{}
		statuses = append(statuses, status)
	}
	return statuses, nil
}
