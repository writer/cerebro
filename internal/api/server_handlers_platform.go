package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/evalops/cerebro/internal/graph"
)

type platformGraphQueryRequest struct {
	Mode      string     `json:"mode,omitempty"`
	NodeID    string     `json:"node_id"`
	Direction string     `json:"direction,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	TargetID  string     `json:"target_id,omitempty"`
	K         int        `json:"k,omitempty"`
	MaxDepth  int        `json:"max_depth,omitempty"`
	AsOf      *time.Time `json:"as_of,omitempty"`
	From      *time.Time `json:"from,omitempty"`
	To        *time.Time `json:"to,omitempty"`
}

type securityAttackPathJobRequest struct {
	MaxDepth  int     `json:"max_depth,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`
	Limit     int     `json:"limit,omitempty"`
}

type platformJob struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Status      string         `json:"status"`
	SubmittedAt time.Time      `json:"submitted_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	RequestedBy string         `json:"requested_by,omitempty"`
	Input       map[string]any `json:"input,omitempty"`
	Result      any            `json:"result,omitempty"`
	Error       string         `json:"error,omitempty"`
	StatusURL   string         `json:"status_url"`
}

func (s *Server) platformGraphQueries(w http.ResponseWriter, r *http.Request) {
	var req platformGraphQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.NodeID) == "" {
		s.error(w, http.StatusBadRequest, "node_id is required")
		return
	}

	values := url.Values{}
	values.Set("node_id", strings.TrimSpace(req.NodeID))
	if mode := strings.TrimSpace(req.Mode); mode != "" {
		values.Set("mode", mode)
	}
	if direction := strings.TrimSpace(req.Direction); direction != "" {
		values.Set("direction", direction)
	}
	if req.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", req.Limit))
	}
	if targetID := strings.TrimSpace(req.TargetID); targetID != "" {
		values.Set("target_id", targetID)
	}
	if req.K > 0 {
		values.Set("k", fmt.Sprintf("%d", req.K))
	}
	if req.MaxDepth > 0 {
		values.Set("max_depth", fmt.Sprintf("%d", req.MaxDepth))
	}
	if req.AsOf != nil && !req.AsOf.IsZero() {
		values.Set("as_of", req.AsOf.UTC().Format(time.RFC3339))
	}
	if req.From != nil && !req.From.IsZero() {
		values.Set("from", req.From.UTC().Format(time.RFC3339))
	}
	if req.To != nil && !req.To.IsZero() {
		values.Set("to", req.To.UTC().Format(time.RFC3339))
	}

	reqCopy := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.RawQuery = values.Encode()
	reqCopy.URL = &urlCopy
	reqCopy.Method = http.MethodGet
	reqCopy.Body = http.NoBody
	s.graphQuery(w, reqCopy)
}

func (s *Server) platformWriteClaim(w http.ResponseWriter, r *http.Request) {
	s.graphWriteClaim(w, r)
}

func (s *Server) platformWriteDecision(w http.ResponseWriter, r *http.Request) {
	s.graphWriteDecision(w, r)
}

func (s *Server) createSecurityAttackPathJob(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req securityAttackPathJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	maxDepth := req.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 6
	}
	if maxDepth > 10 {
		s.error(w, http.StatusBadRequest, "max_depth must be between 1 and 10")
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
		return
	}
	if req.Threshold < 0 {
		s.error(w, http.StatusBadRequest, "threshold must be greater than or equal to 0")
		return
	}

	job := s.newPlatformJob("security.attack_path_analysis", map[string]any{
		"max_depth": maxDepth,
		"threshold": req.Threshold,
		"limit":     limit,
	}, GetUserID(r.Context()))

	go s.runPlatformJob(job.ID, func() (any, error) {
		simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)
		result := simulator.Simulate(maxDepth)
		if req.Threshold > 0 {
			filtered := make([]*graph.ScoredAttackPath, 0, len(result.Paths))
			for _, path := range result.Paths {
				if path.TotalScore >= req.Threshold {
					filtered = append(filtered, path)
				}
			}
			result.Paths = filtered
		}
		if len(result.Paths) > limit {
			result.Paths = result.Paths[:limit]
		}
		result.TotalPaths = len(result.Paths)
		return result, nil
	})

	s.json(w, http.StatusAccepted, job)
}

func (s *Server) getPlatformJob(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimSpace(chi.URLParam(r, "id"))
	if jobID == "" {
		s.error(w, http.StatusBadRequest, "job id required")
		return
	}
	job, ok := s.platformJobSnapshot(jobID)
	if !ok {
		s.error(w, http.StatusNotFound, "job not found")
		return
	}
	s.json(w, http.StatusOK, job)
}

func (s *Server) listPlatformIntelligenceReports(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.ReportCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceReport(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	report, ok := graph.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) newPlatformJob(kind string, input map[string]any, requestedBy string) *platformJob {
	now := time.Now().UTC()
	job := &platformJob{
		ID:          "job:" + uuid.NewString(),
		Kind:        kind,
		Status:      "queued",
		SubmittedAt: now,
		RequestedBy: strings.TrimSpace(requestedBy),
		Input:       cloneJSONMap(input),
	}
	job.StatusURL = "/api/v1/platform/jobs/" + job.ID

	s.platformJobMu.Lock()
	s.platformJobs[job.ID] = job
	s.platformJobMu.Unlock()

	return clonePlatformJob(job)
}

func (s *Server) runPlatformJob(jobID string, runner func() (any, error)) {
	now := time.Now().UTC()
	s.platformJobMu.Lock()
	job, ok := s.platformJobs[jobID]
	if ok {
		job.Status = "running"
		job.StartedAt = &now
	}
	s.platformJobMu.Unlock()
	if !ok {
		return
	}

	result, err := runner()
	completedAt := time.Now().UTC()

	s.platformJobMu.Lock()
	defer s.platformJobMu.Unlock()
	job, ok = s.platformJobs[jobID]
	if !ok {
		return
	}
	job.CompletedAt = &completedAt
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		return
	}
	job.Status = "succeeded"
	job.Result = result
}

func (s *Server) platformJobSnapshot(jobID string) (*platformJob, bool) {
	s.platformJobMu.RLock()
	defer s.platformJobMu.RUnlock()
	job, ok := s.platformJobs[jobID]
	if !ok {
		return nil, false
	}
	return clonePlatformJob(job), true
}

func clonePlatformJob(job *platformJob) *platformJob {
	if job == nil {
		return nil
	}
	cloned := *job
	if cloned.Input != nil {
		cloned.Input = cloneJSONMap(cloned.Input)
	}
	return &cloned
}
