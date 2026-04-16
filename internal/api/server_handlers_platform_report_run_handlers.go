package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

type platformReportRunRequest struct {
	ExecutionMode     string                         `json:"execution_mode,omitempty"`
	MaterializeResult *bool                          `json:"materialize_result,omitempty"`
	Parameters        []reports.ReportParameterValue `json:"parameters,omitempty"`
	RetryPolicy       *reports.ReportRetryPolicy     `json:"retry_policy,omitempty"`
}

type platformReportRetryRequest struct {
	ExecutionMode     string                         `json:"execution_mode,omitempty"`
	MaterializeResult *bool                          `json:"materialize_result,omitempty"`
	Parameters        []reports.ReportParameterValue `json:"parameters,omitempty"`
	RetryPolicy       *reports.ReportRetryPolicy     `json:"retry_policy,omitempty"`
	Reason            string                         `json:"reason,omitempty"`
}

type platformReportCancelRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (s *Server) listPlatformIntelligenceReportRuns(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	if _, ok := reports.GetReportDefinition(reportID); !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	runs := s.platformReportRunSummaries(reportID)
	s.json(w, http.StatusOK, reports.ReportRunCollection{
		ReportID: reportID,
		Count:    len(runs),
		Runs:     runs,
	})
}

func (s *Server) createPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	var req platformReportRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	run, status, err := s.startPlatformReportRun(r.Context(), reportID, req, strings.TrimSpace(GetUserID(r.Context())), "api.request")
	if err != nil {
		if run != nil {
			w.Header().Set("Location", run.StatusURL)
			s.json(w, status, run)
			return
		}
		s.error(w, status, err.Error())
		return
	}
	if run == nil {
		s.error(w, http.StatusInternalServerError, "report run not created")
		return
	}
	w.Header().Set("Location", run.StatusURL)
	s.json(w, status, run)
}

func (s *Server) getPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	s.json(w, http.StatusOK, run)
}

func (s *Server) listPlatformIntelligenceReportRunAttempts(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	s.json(w, http.StatusOK, reports.ReportRunAttemptCollectionSnapshot(reportID, runID, run.Attempts))
}

func (s *Server) listPlatformIntelligenceReportRunEvents(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	s.json(w, http.StatusOK, reports.ReportRunEventCollectionSnapshot(reportID, runID, run.Events))
}

func (s *Server) getPlatformIntelligenceReportRunControl(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	s.json(w, http.StatusOK, reports.ReportRunControlSnapshot(reportID, run))
}

func (s *Server) getPlatformIntelligenceReportRunRetryPolicy(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	s.json(w, http.StatusOK, reports.ReportRunRetryPolicyStateSnapshot(reportID, run))
}

func (s *Server) updatePlatformIntelligenceReportRunRetryPolicy(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	if _, ok := reports.GetReportDefinition(reportID); !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	if _, ok := s.platformReportRunSnapshot(reportID, runID); !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	var policy reports.ReportRetryPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy = reports.NormalizeReportRetryPolicy(policy)
	stored, err := s.updatePlatformReportRunSnapshot(runID, func(updated *reports.ReportRun) {
		updated.RetryPolicy = policy
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after retry policy update")
		return
	}
	s.json(w, http.StatusOK, reports.ReportRunRetryPolicyStateSnapshot(reportID, stored))
}

func platformReportRunIDParam(r *http.Request) string {
	runID := strings.TrimSpace(chi.URLParam(r, "run_id"))
	if runID != "" && !strings.HasPrefix(runID, "report_run:") {
		runID = "report_run:" + runID
	}
	return runID
}
