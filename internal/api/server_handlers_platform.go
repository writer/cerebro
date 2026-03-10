package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
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

type platformReportRunRequest struct {
	ExecutionMode     string                       `json:"execution_mode,omitempty"`
	MaterializeResult *bool                        `json:"materialize_result,omitempty"`
	Parameters        []graph.ReportParameterValue `json:"parameters,omitempty"`
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
	platformGraphQueryFromValues(w, r, values, s.graphQuery)
}

func (s *Server) platformGraphQueriesGet(w http.ResponseWriter, r *http.Request) {
	s.graphQuery(w, r)
}

func (s *Server) platformGraphTemplates(w http.ResponseWriter, r *http.Request) {
	s.graphQueryTemplates(w, r)
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

func (s *Server) listPlatformIntelligenceMeasures(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.ReportMeasureCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceChecks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.ReportCheckCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceReportRuns(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	if _, ok := graph.GetReportDefinition(reportID); !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	runs := s.platformReportRunSummaries(reportID)
	s.json(w, http.StatusOK, graph.ReportRunCollection{
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
	definition, ok := graph.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}

	var req platformReportRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := graph.ValidateReportParameterValues(definition, req.Parameters); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	executionMode := strings.ToLower(strings.TrimSpace(req.ExecutionMode))
	if executionMode == "" {
		executionMode = graph.ReportExecutionModeSync
	}
	if executionMode != graph.ReportExecutionModeSync && executionMode != graph.ReportExecutionModeAsync {
		s.error(w, http.StatusBadRequest, "execution_mode must be one of sync, async")
		return
	}
	materializeResult := true
	if req.MaterializeResult != nil {
		materializeResult = *req.MaterializeResult
	}

	cacheKey, err := graph.BuildReportRunCacheKey(reportID, req.Parameters)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	run := &graph.ReportRun{
		ID:            "report_run:" + uuid.NewString(),
		ReportID:      reportID,
		Status:        graph.ReportRunStatusQueued,
		ExecutionMode: executionMode,
		SubmittedAt:   now,
		RequestedBy:   strings.TrimSpace(GetUserID(r.Context())),
		Parameters:    graph.CloneReportParameterValues(req.Parameters),
		TimeSlice:     graph.ExtractReportTimeSlice(req.Parameters),
		CacheKey:      cacheKey,
	}
	run.StatusURL = "/api/v1/platform/intelligence/reports/" + reportID + "/runs/" + run.ID

	if executionMode == graph.ReportExecutionModeAsync {
		job := s.newPlatformJob("platform.report_run", map[string]any{
			"report_id":       reportID,
			"run_id":          run.ID,
			"cache_key":       cacheKey,
			"parameter_count": len(req.Parameters),
		}, run.RequestedBy)
		run.JobID = job.ID
		run.JobStatusURL = job.StatusURL
		s.storePlatformReportRun(run)

		go s.runPlatformJob(job.ID, func() (any, error) {
			if err := s.executePlatformReportRun(run.ID, definition, req.Parameters, materializeResult); err != nil {
				return nil, err
			}
			stored, ok := s.platformReportRunSnapshot(reportID, run.ID)
			if !ok {
				return nil, fmt.Errorf("report run %q disappeared during execution", run.ID)
			}
			return graph.SummarizeReportRun(*stored), nil
		})

		w.Header().Set("Location", run.StatusURL)
		s.json(w, http.StatusAccepted, run)
		return
	}

	s.storePlatformReportRun(run)
	if err := s.executePlatformReportRun(run.ID, definition, req.Parameters, materializeResult); err != nil {
		stored, _ := s.platformReportRunSnapshot(reportID, run.ID)
		if stored != nil {
			w.Header().Set("Location", stored.StatusURL)
			s.json(w, http.StatusInternalServerError, stored)
			return
		}
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored, _ := s.platformReportRunSnapshot(reportID, run.ID)
	w.Header().Set("Location", stored.StatusURL)
	s.json(w, http.StatusCreated, stored)
}

func (s *Server) getPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := strings.TrimSpace(chi.URLParam(r, "run_id"))
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

func (s *Server) executePlatformReportRun(runID string, definition graph.ReportDefinition, parameters []graph.ReportParameterValue, materializeResult bool) error {
	startedAt := time.Now().UTC()
	s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
		run.Status = graph.ReportRunStatusRunning
		run.StartedAt = &startedAt
		run.Error = ""
	})

	result, err := s.executePlatformReport(definition.ID, parameters)
	completedAt := time.Now().UTC()
	if err != nil {
		s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
			run.Status = graph.ReportRunStatusFailed
			run.CompletedAt = &completedAt
			run.Error = err.Error()
		})
		return err
	}

	sections := graph.BuildReportSectionResults(definition, result)
	var snapshot *graph.ReportSnapshot
	if materializeResult {
		snapshot, err = graph.BuildReportSnapshot(runID, definition, result, true, completedAt)
		if err != nil {
			s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
				run.Status = graph.ReportRunStatusFailed
				run.CompletedAt = &completedAt
				run.Error = err.Error()
			})
			return err
		}
	}

	s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
		run.Status = graph.ReportRunStatusSucceeded
		run.CompletedAt = &completedAt
		run.Sections = graph.CloneReportSectionResults(sections)
		run.Snapshot = snapshot
		run.Result = cloneJSONObject(result)
	})
	return nil
}

func (s *Server) executePlatformReport(reportID string, parameters []graph.ReportParameterValue) (map[string]any, error) {
	definition, ok := graph.GetReportDefinition(reportID)
	if !ok {
		return nil, fmt.Errorf("report definition not found: %s", reportID)
	}
	handler, ok := s.platformReportHandler(reportID)
	if !ok {
		return nil, fmt.Errorf("no report executor registered for %s", reportID)
	}
	values, err := reportParameterValuesToQuery(parameters)
	if err != nil {
		return nil, err
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, definition.Endpoint.Path, nil)
	if encoded := values.Encode(); encoded != "" {
		req.URL.RawQuery = encoded
	}
	resp := httptest.NewRecorder()
	handler(resp, req)
	result := resp.Result()
	defer func() { _ = result.Body.Close() }()
	body, _ := io.ReadAll(result.Body)
	if result.StatusCode >= 400 {
		message := decodePlatformAPIError(body)
		if message == "" {
			message = strings.TrimSpace(string(body))
		}
		if message == "" {
			message = fmt.Sprintf("report execution failed with status %d", result.StatusCode)
		}
		return nil, fmt.Errorf("%s", message)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode report payload: %w", err)
	}
	return payload, nil
}

func (s *Server) platformReportHandler(reportID string) (http.HandlerFunc, bool) {
	switch reportID {
	case "insights":
		return s.graphIntelligenceInsights, true
	case "quality":
		return s.graphIntelligenceQuality, true
	case "metadata-quality":
		return s.graphIntelligenceMetadataQuality, true
	case "claim-conflicts":
		return s.graphIntelligenceClaimConflicts, true
	case "leverage":
		return s.graphIntelligenceLeverage, true
	case "calibration-weekly":
		return s.graphIntelligenceWeeklyCalibration, true
	default:
		return nil, false
	}
}

func reportParameterValuesToQuery(values []graph.ReportParameterValue) (url.Values, error) {
	query := url.Values{}
	for _, value := range values {
		encoded, err := value.QueryValue()
		if err != nil {
			return nil, err
		}
		query.Set(strings.TrimSpace(value.Name), encoded)
	}
	return query, nil
}

func platformGraphQueryFromValues(w http.ResponseWriter, r *http.Request, values url.Values, next http.HandlerFunc) {
	reqCopy := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.RawQuery = values.Encode()
	reqCopy.URL = &urlCopy
	reqCopy.Method = http.MethodGet
	reqCopy.Body = http.NoBody
	next(w, reqCopy)
}

func decodePlatformAPIError(payload []byte) string {
	var apiErr APIError
	if err := json.Unmarshal(payload, &apiErr); err == nil {
		return strings.TrimSpace(apiErr.Error)
	}
	return ""
}

func cloneJSONObject(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return cloneJSONMap(value)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return cloneJSONMap(value)
	}
	return decoded
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
	job.Result = cloneJSONValue(result)
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
	cloned.Result = cloneJSONValue(job.Result)
	return &cloned
}

func cloneJSONValue(value any) any {
	if value == nil {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return value
	}
	return decoded
}

func (s *Server) storePlatformReportRun(run *graph.ReportRun) {
	if run == nil {
		return
	}
	s.platformReportRunMu.Lock()
	defer s.platformReportRunMu.Unlock()
	s.platformReportRuns[run.ID] = graph.CloneReportRun(run)
}

func (s *Server) updatePlatformReportRun(runID string, apply func(*graph.ReportRun)) {
	s.platformReportRunMu.Lock()
	defer s.platformReportRunMu.Unlock()
	run, ok := s.platformReportRuns[runID]
	if !ok {
		return
	}
	apply(run)
}

func (s *Server) platformReportRunSnapshot(reportID, runID string) (*graph.ReportRun, bool) {
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	run, ok := s.platformReportRuns[runID]
	if !ok || run.ReportID != reportID {
		return nil, false
	}
	return graph.CloneReportRun(run), true
}

func (s *Server) platformReportRunSummaries(reportID string) []graph.ReportRunSummary {
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	runs := make([]graph.ReportRunSummary, 0)
	for _, run := range s.platformReportRuns {
		if run.ReportID != reportID {
			continue
		}
		runs = append(runs, graph.SummarizeReportRun(*run))
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].SubmittedAt.Equal(runs[j].SubmittedAt) {
			return runs[i].ID > runs[j].ID
		}
		return runs[i].SubmittedAt.After(runs[j].SubmittedAt)
	})
	return runs
}
