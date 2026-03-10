package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/webhooks"
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
	RetryPolicy       *graph.ReportRetryPolicy     `json:"retry_policy,omitempty"`
}

type platformReportRetryRequest struct {
	ExecutionMode     string                       `json:"execution_mode,omitempty"`
	MaterializeResult *bool                        `json:"materialize_result,omitempty"`
	Parameters        []graph.ReportParameterValue `json:"parameters,omitempty"`
	RetryPolicy       *graph.ReportRetryPolicy     `json:"retry_policy,omitempty"`
	Reason            string                       `json:"reason,omitempty"`
}

type platformReportCancelRequest struct {
	Reason string `json:"reason,omitempty"`
}

type securityAttackPathJobRequest struct {
	MaxDepth  int     `json:"max_depth,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`
	Limit     int     `json:"limit,omitempty"`
}

type platformJob struct {
	ID                string             `json:"id"`
	Kind              string             `json:"kind"`
	Status            string             `json:"status"`
	SubmittedAt       time.Time          `json:"submitted_at"`
	StartedAt         *time.Time         `json:"started_at,omitempty"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty"`
	CancelRequestedAt *time.Time         `json:"cancel_requested_at,omitempty"`
	CancelReason      string             `json:"cancel_reason,omitempty"`
	RequestedBy       string             `json:"requested_by,omitempty"`
	Input             map[string]any     `json:"input,omitempty"`
	Result            any                `json:"result,omitempty"`
	Error             string             `json:"error,omitempty"`
	StatusURL         string             `json:"status_url"`
	cancel            context.CancelFunc `json:"-"`
	ctx               context.Context    `json:"-"`
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

	job := s.newPlatformJob(r.Context(), "security.attack_path_analysis", map[string]any{
		"max_depth": maxDepth,
		"threshold": req.Threshold,
		"limit":     limit,
	}, GetUserID(r.Context()))

	// #nosec G118 -- platform jobs intentionally outlive the originating request and use job-owned cancellation.
	go s.runPlatformJob(job.ID, func(_ context.Context) (any, error) {
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

func (s *Server) listPlatformIntelligenceSectionEnvelopes(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.ReportSectionEnvelopeCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceSectionEnvelope(w http.ResponseWriter, r *http.Request) {
	envelopeID := strings.TrimSpace(chi.URLParam(r, "envelope_id"))
	if envelopeID == "" {
		s.error(w, http.StatusBadRequest, "envelope id required")
		return
	}
	envelope, ok := graph.GetReportSectionEnvelopeDefinition(envelopeID)
	if !ok {
		s.error(w, http.StatusNotFound, "section envelope definition not found")
		return
	}
	s.json(w, http.StatusOK, envelope)
}

func (s *Server) listPlatformIntelligenceBenchmarkPacks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.BenchmarkPackCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceBenchmarkPack(w http.ResponseWriter, r *http.Request) {
	packID := strings.TrimSpace(chi.URLParam(r, "pack_id"))
	if packID == "" {
		s.error(w, http.StatusBadRequest, "benchmark pack id required")
		return
	}
	pack, ok := graph.GetBenchmarkPack(packID)
	if !ok {
		s.error(w, http.StatusNotFound, "benchmark pack not found")
		return
	}
	s.json(w, http.StatusOK, pack)
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
	retryPolicy := graph.ReportRetryPolicy{}
	if req.RetryPolicy != nil {
		retryPolicy = *req.RetryPolicy
	}
	retryPolicy = graph.NormalizeReportRetryPolicy(retryPolicy)

	cacheKey, err := graph.BuildReportRunCacheKey(reportID, req.Parameters)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	lineage := graph.BuildReportLineage(s.app.SecurityGraph, definition)
	storagePolicy := graph.BuildReportStoragePolicy(materializeResult, false)
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
		RetryPolicy:   retryPolicy,
		Lineage:       lineage,
		Storage:       storagePolicy,
	}
	run.StatusURL = "/api/v1/platform/intelligence/reports/" + reportID + "/runs/" + run.ID
	triggerSurface := "api.request"
	executionSurface := reportExecutionSurface(executionMode)
	run.Attempts = []graph.ReportRunAttempt{
		graph.NewReportRunAttempt(run.ID, 1, run.Status, triggerSurface, executionSurface, platformExecutionHost(), run.RequestedBy, "", now),
	}
	run.LatestAttemptID = run.Attempts[0].ID
	run.AttemptCount = len(run.Attempts)
	graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunQueued), run.Status, triggerSurface, run.RequestedBy, now, map[string]any{
		"report_id":           reportID,
		"execution_mode":      executionMode,
		"execution_surface":   executionSurface,
		"materialized_result": materializeResult,
	})
	run.EventCount = len(run.Events)

	if executionMode == graph.ReportExecutionModeAsync {
		job := s.newPlatformJob(r.Context(), "platform.report_run", map[string]any{
			"report_id":       reportID,
			"run_id":          run.ID,
			"cache_key":       cacheKey,
			"parameter_count": len(req.Parameters),
		}, run.RequestedBy)
		run.JobID = job.ID
		run.JobStatusURL = job.StatusURL
		run.Attempts[0].JobID = job.ID
		if err := s.storePlatformReportRun(run); err != nil {
			s.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunQueued, reportID, run.ID)

		// #nosec G118 -- async report runs intentionally detach from request lifetime and are canceled through the platform job.
		go s.runPlatformJob(job.ID, func(jobCtx context.Context) (any, error) {
			if err := s.executePlatformReportRun(jobCtx, run.ID, definition, req.Parameters, materializeResult); err != nil {
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

	if err := s.storePlatformReportRun(run); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunQueued, reportID, run.ID)
	if err := s.executePlatformReportRun(r.Context(), run.ID, definition, req.Parameters, materializeResult); err != nil {
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
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after execution")
		return
	}
	w.Header().Set("Location", stored.StatusURL)
	s.json(w, http.StatusCreated, stored)
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
	s.json(w, http.StatusOK, graph.ReportRunAttemptCollectionSnapshot(reportID, runID, run.Attempts))
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
	s.json(w, http.StatusOK, graph.ReportRunEventCollectionSnapshot(reportID, runID, run.Events))
}

func (s *Server) retryPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	definition, ok := graph.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	if run.Status != graph.ReportRunStatusFailed && run.Status != graph.ReportRunStatusCanceled {
		s.error(w, http.StatusConflict, "only failed or canceled report runs can be retried")
		return
	}

	var req platformReportRetryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	executionMode := strings.ToLower(strings.TrimSpace(req.ExecutionMode))
	if executionMode == "" {
		executionMode = run.ExecutionMode
	}
	if executionMode != graph.ReportExecutionModeSync && executionMode != graph.ReportExecutionModeAsync {
		s.error(w, http.StatusBadRequest, "execution_mode must be one of sync, async")
		return
	}
	materializeResult := run.Storage.MaterializedResultAvailable
	if req.MaterializeResult != nil {
		materializeResult = *req.MaterializeResult
	}
	parameters := graph.CloneReportParameterValues(run.Parameters)
	if len(req.Parameters) > 0 {
		parameters = graph.CloneReportParameterValues(req.Parameters)
	}
	if err := graph.ValidateReportParameterValues(definition, parameters); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	cacheKey, err := graph.BuildReportRunCacheKey(reportID, parameters)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	retryPolicy := run.RetryPolicy
	if req.RetryPolicy != nil {
		retryPolicy = *req.RetryPolicy
	}
	retryPolicy = graph.NormalizeReportRetryPolicy(retryPolicy)
	if run.AttemptCount >= retryPolicy.MaxAttempts {
		s.error(w, http.StatusConflict, "retry policy max_attempts exhausted")
		return
	}

	now := time.Now().UTC()
	retryReason := strings.TrimSpace(req.Reason)
	if retryReason == "" {
		retryReason = "manual_retry"
	}
	nextAttemptNumber := len(run.Attempts) + 1
	backoff := time.Duration(0)
	if executionMode == graph.ReportExecutionModeAsync {
		backoff = graph.ReportRetryBackoff(retryPolicy, nextAttemptNumber)
	}
	var previousAttemptID string
	if attempt := graph.LatestReportRunAttempt(run); attempt != nil {
		previousAttemptID = attempt.ID
	}
	retriedBy := strings.TrimSpace(GetUserID(r.Context()))
	if retriedBy == "" {
		retriedBy = run.RequestedBy
	}

	attempt := graph.NewReportRunAttempt(run.ID, nextAttemptNumber, graph.ReportRunStatusQueued, "api.retry", reportExecutionSurface(executionMode), platformExecutionHost(), retriedBy, "", now)
	attempt.RetryOfAttemptID = previousAttemptID
	attempt.RetryReason = retryReason
	attempt.RetryBackoffMS = backoff.Milliseconds()
	if backoff > 0 {
		scheduledFor := now.Add(backoff)
		attempt.ScheduledFor = &scheduledFor
	}

	if err := s.updatePlatformReportRun(runID, func(stored *graph.ReportRun) {
		stored.Status = graph.ReportRunStatusQueued
		stored.ExecutionMode = executionMode
		stored.RequestedBy = retriedBy
		stored.Parameters = parameters
		stored.TimeSlice = graph.ExtractReportTimeSlice(parameters)
		stored.CacheKey = cacheKey
		stored.JobID = ""
		stored.JobStatusURL = ""
		stored.StartedAt = nil
		stored.CompletedAt = nil
		stored.Error = ""
		stored.Sections = nil
		stored.Snapshot = nil
		stored.Result = nil
		stored.Storage = graph.BuildReportStoragePolicy(materializeResult, false)
		stored.RetryPolicy = retryPolicy
		stored.Attempts = append(stored.Attempts, attempt)
		stored.LatestAttemptID = attempt.ID
		graph.AppendReportRunEvent(stored, string(webhooks.EventPlatformReportRunQueued), stored.Status, "api.retry", retriedBy, now, map[string]any{
			"report_id":           stored.ReportID,
			"execution_mode":      executionMode,
			"execution_surface":   reportExecutionSurface(executionMode),
			"materialized_result": materializeResult,
			"retry_of_attempt_id": previousAttemptID,
			"retry_reason":        retryReason,
			"retry_backoff_ms":    backoff.Milliseconds(),
		})
		stored.AttemptCount = len(stored.Attempts)
		stored.EventCount = len(stored.Events)
	}); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	stored, _ := s.platformReportRunSnapshot(reportID, runID)
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after retry")
		return
	}

	s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunQueued, reportID, runID)
	if executionMode == graph.ReportExecutionModeAsync {
		job := s.newPlatformJob(r.Context(), "platform.report_run", map[string]any{
			"report_id":        reportID,
			"run_id":           runID,
			"cache_key":        cacheKey,
			"parameter_count":  len(parameters),
			"retry_attempt":    nextAttemptNumber,
			"retry_backoff_ms": backoff.Milliseconds(),
			"retry_of_attempt": previousAttemptID,
			"retry_reason":     retryReason,
		}, retriedBy)
		stored, cancelJob, cancelReason, err := s.attachPlatformReportRunJob(runID, job)
		if err != nil {
			s.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if cancelJob {
			s.cancelPlatformJob(job.ID, cancelReason)
		} else {
			// #nosec G118 -- async retry execution intentionally detaches from request lifetime and is canceled through the platform job.
			go s.runPlatformJob(job.ID, func(jobCtx context.Context) (any, error) {
				if backoff > 0 {
					timer := time.NewTimer(backoff)
					defer timer.Stop()
					select {
					case <-jobCtx.Done():
						return nil, jobCtx.Err()
					case <-timer.C:
					}
				}
				if err := s.executePlatformReportRun(jobCtx, runID, definition, parameters, materializeResult); err != nil {
					return nil, err
				}
				stored, ok := s.platformReportRunSnapshot(reportID, runID)
				if !ok {
					return nil, fmt.Errorf("report run %q disappeared during retry", runID)
				}
				return graph.SummarizeReportRun(*stored), nil
			})
		}
		if stored == nil {
			s.error(w, http.StatusInternalServerError, "report run disappeared after retry job attachment")
			return
		}
		w.Header().Set("Location", stored.StatusURL)
		s.json(w, http.StatusAccepted, stored)
		return
	}

	if err := s.executePlatformReportRun(r.Context(), runID, definition, parameters, materializeResult); err != nil && !errors.Is(err, context.Canceled) {
		stored, _ = s.platformReportRunSnapshot(reportID, runID)
		if stored != nil {
			w.Header().Set("Location", stored.StatusURL)
			s.json(w, http.StatusInternalServerError, stored)
			return
		}
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored, _ = s.platformReportRunSnapshot(reportID, runID)
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after retry execution")
		return
	}
	w.Header().Set("Location", stored.StatusURL)
	s.json(w, http.StatusOK, stored)
}

func (s *Server) cancelPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
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
	if run.Status != graph.ReportRunStatusQueued && run.Status != graph.ReportRunStatusRunning {
		s.error(w, http.StatusConflict, "only queued or running report runs can be canceled")
		return
	}

	var req platformReportCancelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cancelReason := strings.TrimSpace(req.Reason)
	if cancelReason == "" {
		cancelReason = "canceled by operator"
	}
	canceledAt := time.Now().UTC()
	actor := strings.TrimSpace(GetUserID(r.Context()))
	if actor == "" {
		actor = run.RequestedBy
	}

	stored, err := s.updatePlatformReportRunSnapshot(runID, func(stored *graph.ReportRun) {
		stored.Status = graph.ReportRunStatusCanceled
		stored.CompletedAt = &canceledAt
		stored.Error = cancelReason
		graph.CompleteLatestReportRunAttempt(stored, stored.Status, canceledAt, cancelReason, graph.ReportAttemptClassCancelled)
		graph.AppendReportRunEvent(stored, string(webhooks.EventPlatformReportRunCanceled), stored.Status, "api.cancel", actor, canceledAt, map[string]any{
			"report_id":     stored.ReportID,
			"cancel_reason": cancelReason,
		})
		stored.AttemptCount = len(stored.Attempts)
		stored.EventCount = len(stored.Events)
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after cancel")
		return
	}
	if stored.JobID != "" {
		s.cancelPlatformJob(stored.JobID, cancelReason)
	}
	s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunCanceled, reportID, runID)
	w.Header().Set("Location", stored.StatusURL)
	s.json(w, http.StatusOK, stored)
}

func (s *Server) executePlatformReportRun(ctx context.Context, runID string, definition graph.ReportDefinition, parameters []graph.ReportParameterValue, materializeResult bool) error {
	startedAt := time.Now().UTC()
	canceledBeforeStart := false
	if err := s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
		if run.Status == graph.ReportRunStatusCanceled {
			canceledBeforeStart = true
			return
		}
		run.Status = graph.ReportRunStatusRunning
		run.StartedAt = &startedAt
		run.Error = ""
		graph.StartLatestReportRunAttempt(run, startedAt)
		graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunStarted), run.Status, platformReportTriggerSurface(run), run.RequestedBy, startedAt, map[string]any{
			"report_id":         run.ReportID,
			"execution_mode":    run.ExecutionMode,
			"execution_surface": reportExecutionSurface(run.ExecutionMode),
		})
		run.AttemptCount = len(run.Attempts)
		run.EventCount = len(run.Events)
	}); err != nil {
		return err
	}
	if canceledBeforeStart {
		return context.Canceled
	}
	s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunStarted, definition.ID, runID)

	result, err := s.executePlatformReport(ctx, definition.ID, parameters)
	completedAt := time.Now().UTC()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			alreadyCanceled := false
			if updateErr := s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
				if run.Status == graph.ReportRunStatusCanceled {
					alreadyCanceled = true
					return
				}
				run.Status = graph.ReportRunStatusCanceled
				run.CompletedAt = &completedAt
				run.Error = err.Error()
				graph.CompleteLatestReportRunAttempt(run, run.Status, completedAt, err.Error(), graph.ReportAttemptClassCancelled)
				graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunCanceled), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
					"report_id":     run.ReportID,
					"cancel_reason": err.Error(),
				})
				run.AttemptCount = len(run.Attempts)
				run.EventCount = len(run.Events)
			}); updateErr != nil {
				return updateErr
			}
			if !alreadyCanceled {
				s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunCanceled, definition.ID, runID)
			}
			return err
		}
		classification := platformReportAttemptClassification(err)
		if updateErr := s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
			run.Status = graph.ReportRunStatusFailed
			run.CompletedAt = &completedAt
			run.Error = err.Error()
			graph.CompleteLatestReportRunAttempt(run, run.Status, completedAt, err.Error(), classification)
			graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunFailed), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
				"report_id":              run.ReportID,
				"error":                  err.Error(),
				"attempt_classification": classification,
			})
			run.AttemptCount = len(run.Attempts)
			run.EventCount = len(run.Events)
		}); updateErr != nil {
			return updateErr
		}
		s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunFailed, definition.ID, runID)
		return err
	}

	sections := graph.BuildReportSectionResults(definition, result)
	var snapshot *graph.ReportSnapshot
	if materializeResult {
		snapshot, err = graph.BuildReportSnapshot(runID, definition, result, true, completedAt)
		if err != nil {
			classification := platformReportAttemptClassification(err)
			if updateErr := s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
				run.Status = graph.ReportRunStatusFailed
				run.CompletedAt = &completedAt
				run.Error = err.Error()
				graph.CompleteLatestReportRunAttempt(run, run.Status, completedAt, err.Error(), classification)
				graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunFailed), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
					"report_id":              run.ReportID,
					"error":                  err.Error(),
					"attempt_classification": classification,
				})
				run.AttemptCount = len(run.Attempts)
				run.EventCount = len(run.Events)
			}); updateErr != nil {
				return updateErr
			}
			s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunFailed, definition.ID, runID)
			return err
		}
	}

	canceledBeforeCommit := false
	if err := s.updatePlatformReportRun(runID, func(run *graph.ReportRun) {
		if run.Status == graph.ReportRunStatusCanceled {
			canceledBeforeCommit = true
			return
		}
		run.Status = graph.ReportRunStatusSucceeded
		run.CompletedAt = &completedAt
		run.Sections = graph.CloneReportSectionResults(sections)
		run.Snapshot = snapshot
		run.Result = cloneJSONObject(result)
		run.Storage = graph.BuildReportStoragePolicy(snapshot != nil, false)
		graph.CompleteLatestReportRunAttempt(run, run.Status, completedAt, "", "")
		if snapshot != nil {
			snapshot.Lineage = graph.CloneReportLineage(run.Lineage)
			snapshot.Storage = graph.BuildReportStoragePolicy(true, false)
			graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportSnapshotMaterialized), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
				"report_id":   run.ReportID,
				"snapshot_id": snapshot.ID,
			})
		}
		graph.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunCompleted), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
			"report_id":           run.ReportID,
			"materialized_result": snapshot != nil,
		})
		run.AttemptCount = len(run.Attempts)
		run.EventCount = len(run.Events)
	}); err != nil {
		return err
	}
	if canceledBeforeCommit {
		return context.Canceled
	}
	if snapshot != nil {
		s.emitPlatformReportSnapshotLifecycleEvent(ctx, definition.ID, runID)
	}
	s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunCompleted, definition.ID, runID)
	return nil
}

func (s *Server) executePlatformReport(ctx context.Context, reportID string, parameters []graph.ReportParameterValue) (map[string]any, error) {
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
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, definition.Endpoint.Path, nil)
	if encoded := values.Encode(); encoded != "" {
		req.URL.RawQuery = encoded
	}
	resp := httptest.NewRecorder()
	handler(resp, req)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
		return nil, reportExecutionError{StatusCode: result.StatusCode, Message: message}
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode report payload: %w", err)
	}
	return payload, nil
}

func (s *Server) platformReportHandler(reportID string) (http.HandlerFunc, bool) {
	if handler, ok := s.platformReportHandlers[reportID]; ok {
		return handler, true
	}
	return nil, false
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

func platformReportRunIDParam(r *http.Request) string {
	runID := strings.TrimSpace(chi.URLParam(r, "run_id"))
	if runID != "" && !strings.HasPrefix(runID, "report_run:") {
		runID = "report_run:" + runID
	}
	return runID
}

type reportExecutionError struct {
	StatusCode int
	Message    string
}

func (e reportExecutionError) Error() string {
	return strings.TrimSpace(e.Message)
}

func platformReportAttemptClassification(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return graph.ReportAttemptClassCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return graph.ReportAttemptClassTransient
	}
	var executionErr reportExecutionError
	if errors.As(err, &executionErr) {
		switch executionErr.StatusCode {
		case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusConflict:
			return graph.ReportAttemptClassTransient
		}
		if executionErr.StatusCode >= 500 {
			return graph.ReportAttemptClassTransient
		}
		return graph.ReportAttemptClassDeterministic
	}
	return graph.ReportAttemptClassDeterministic
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

func (s *Server) newPlatformJob(parent context.Context, kind string, input map[string]any, requestedBy string) *platformJob {
	now := time.Now().UTC()
	parentCtx := context.Background()
	if parent != nil {
		parentCtx = context.WithoutCancel(parent)
	}
	// #nosec G118 -- the cancel func is stored on the job and invoked on terminal completion or explicit cancellation.
	jobCtx, cancel := context.WithCancel(parentCtx)
	job := &platformJob{
		ID:          "job:" + uuid.NewString(),
		Kind:        kind,
		Status:      "queued",
		SubmittedAt: now,
		RequestedBy: strings.TrimSpace(requestedBy),
		Input:       cloneJSONMap(input),
		cancel:      cancel,
		ctx:         jobCtx,
	}
	job.StatusURL = "/api/v1/platform/jobs/" + job.ID

	s.platformJobMu.Lock()
	s.platformJobs[job.ID] = job
	s.platformJobMu.Unlock()

	return clonePlatformJob(job)
}

func (s *Server) runPlatformJob(jobID string, runner func(context.Context) (any, error)) {
	now := time.Now().UTC()
	s.platformJobMu.Lock()
	job, ok := s.platformJobs[jobID]
	if ok {
		if job.Status == graph.ReportRunStatusCanceled || job.Status == "canceled" {
			if job.CompletedAt == nil {
				job.CompletedAt = &now
			}
			cancel := job.cancel
			job.cancel = nil
			job.ctx = nil
			s.platformJobMu.Unlock()
			if cancel != nil {
				cancel()
			}
			return
		}
		job.Status = "running"
		job.StartedAt = &now
	}
	jobCtx := context.Background()
	if ok && job.ctx != nil {
		jobCtx = job.ctx
	}
	s.platformJobMu.Unlock()
	if !ok {
		return
	}

	result, err := runner(jobCtx)
	completedAt := time.Now().UTC()

	s.platformJobMu.Lock()
	job, ok = s.platformJobs[jobID]
	if !ok {
		s.platformJobMu.Unlock()
		return
	}
	job.CompletedAt = &completedAt
	cancel := job.cancel
	job.cancel = nil
	job.ctx = nil
	if job.Status == "canceled" || errors.Is(err, context.Canceled) {
		job.Status = "canceled"
		if job.Error == "" && err != nil {
			job.Error = err.Error()
		}
		s.platformJobMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		s.platformJobMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	job.Status = "succeeded"
	job.Result = cloneJSONValue(result)
	s.platformJobMu.Unlock()
	if cancel != nil {
		cancel()
	}
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

func (s *Server) cancelPlatformJob(jobID, reason string) bool {
	now := time.Now().UTC()
	s.platformJobMu.Lock()
	job, ok := s.platformJobs[jobID]
	if !ok {
		s.platformJobMu.Unlock()
		return false
	}
	if job.Status == "succeeded" || job.Status == "failed" || job.Status == "canceled" {
		s.platformJobMu.Unlock()
		return false
	}
	job.Status = "canceled"
	job.CompletedAt = &now
	job.CancelRequestedAt = &now
	job.CancelReason = strings.TrimSpace(reason)
	cancel := job.cancel
	job.cancel = nil
	job.ctx = nil
	s.platformJobMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// attachPlatformReportRunJob links a platform job to the latest persisted run state.
// If a cancellation won the race before the job was attached, the caller should cancel
// the newly created job immediately so the run and job do not drift.
func (s *Server) attachPlatformReportRunJob(runID string, job *platformJob) (*graph.ReportRun, bool, string, error) {
	if job == nil {
		return nil, false, "", fmt.Errorf("platform job is required")
	}
	cancelJob := false
	cancelReason := ""
	stored, err := s.updatePlatformReportRunSnapshot(runID, func(updated *graph.ReportRun) {
		updated.JobID = job.ID
		updated.JobStatusURL = job.StatusURL
		for i := len(updated.Attempts) - 1; i >= 0; i-- {
			if updated.Attempts[i].ID == updated.LatestAttemptID {
				updated.Attempts[i].JobID = job.ID
				break
			}
		}
		if updated.Status == graph.ReportRunStatusCanceled {
			cancelJob = true
			cancelReason = strings.TrimSpace(updated.Error)
			if cancelReason == "" {
				cancelReason = "report run was canceled before job attachment"
			}
		}
	})
	if err != nil {
		return nil, false, "", err
	}
	return stored, cancelJob, cancelReason, nil
}

func clonePlatformJob(job *platformJob) *platformJob {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.cancel = nil
	cloned.ctx = nil
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

func (s *Server) storePlatformReportRun(run *graph.ReportRun) error {
	if run == nil {
		return nil
	}
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	s.platformReportRunMu.Lock()
	previous, hadPrevious := s.platformReportRuns[run.ID]
	s.platformReportRuns[run.ID] = graph.CloneReportRun(run)
	snapshot := s.clonePlatformReportRunsLocked()
	s.platformReportRunMu.Unlock()
	if err := s.persistPlatformReportRuns(snapshot); err != nil {
		s.platformReportRunMu.Lock()
		if hadPrevious {
			s.platformReportRuns[run.ID] = graph.CloneReportRun(previous)
		} else {
			delete(s.platformReportRuns, run.ID)
		}
		s.platformReportRunMu.Unlock()
		return fmt.Errorf("persist report run %q: %w", run.ID, err)
	}
	return nil
}

func (s *Server) updatePlatformReportRun(runID string, apply func(*graph.ReportRun)) error {
	_, err := s.updatePlatformReportRunSnapshot(runID, apply)
	return err
}

func (s *Server) updatePlatformReportRunSnapshot(runID string, apply func(*graph.ReportRun)) (*graph.ReportRun, error) {
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	s.platformReportRunMu.Lock()
	run, ok := s.platformReportRuns[runID]
	if !ok {
		s.platformReportRunMu.Unlock()
		return nil, fmt.Errorf("report run not found: %s", runID)
	}
	previous := graph.CloneReportRun(run)
	updated := graph.CloneReportRun(run)
	apply(updated)
	s.platformReportRuns[runID] = updated
	snapshot := s.clonePlatformReportRunsLocked()
	s.platformReportRunMu.Unlock()
	if err := s.persistPlatformReportRuns(snapshot); err != nil {
		s.platformReportRunMu.Lock()
		s.platformReportRuns[runID] = previous
		s.platformReportRunMu.Unlock()
		return nil, fmt.Errorf("persist report run %q: %w", runID, err)
	}
	return graph.CloneReportRun(updated), nil
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

func (s *Server) clonePlatformReportRunsLocked() map[string]*graph.ReportRun {
	cloned := make(map[string]*graph.ReportRun, len(s.platformReportRuns))
	for id, run := range s.platformReportRuns {
		cloned[id] = graph.CloneReportRun(run)
	}
	return cloned
}

func (s *Server) persistPlatformReportRuns(runs map[string]*graph.ReportRun) error {
	if s == nil || s.platformReportStore == nil {
		return nil
	}
	return s.platformReportStore.SaveAll(runs)
}

func (s *Server) emitPlatformReportRunLifecycleEvent(ctx context.Context, eventType webhooks.EventType, reportID, runID string) {
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok || run == nil {
		return
	}
	s.emitPlatformLifecycleEvent(ctx, eventType, platformReportRunEventPayload(run))
}

func (s *Server) emitPlatformReportSnapshotLifecycleEvent(ctx context.Context, reportID, runID string) {
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok || run == nil || run.Snapshot == nil {
		return
	}
	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformReportSnapshotMaterialized, platformReportSnapshotEventPayload(run))
}

func platformReportRunEventPayload(run *graph.ReportRun) map[string]any {
	if run == nil {
		return nil
	}
	payload := map[string]any{
		"run_id":                    run.ID,
		"report_id":                 run.ReportID,
		"status":                    run.Status,
		"execution_mode":            run.ExecutionMode,
		"submitted_at":              normalizeRFC3339(run.SubmittedAt),
		"status_url":                run.StatusURL,
		"parameter_count":           len(run.Parameters),
		"materialized_result":       run.Storage.MaterializedResultAvailable,
		"latest_attempt_id":         run.LatestAttemptID,
		"attempt_count":             len(run.Attempts),
		"event_count":               len(run.Events),
		"storage_class":             run.Storage.StorageClass,
		"retention_tier":            run.Storage.RetentionTier,
		"result_truncated":          run.Storage.ResultTruncated,
		"retry_max_attempts":        run.RetryPolicy.MaxAttempts,
		"retry_base_backoff_ms":     run.RetryPolicy.BaseBackoffMS,
		"retry_max_backoff_ms":      run.RetryPolicy.MaxBackoffMS,
		"report_definition_version": run.Lineage.ReportDefinitionVersion,
		"graph_schema_version":      run.Lineage.GraphSchemaVersion,
		"ontology_contract_version": run.Lineage.OntologyContractVersion,
	}
	if run.StartedAt != nil {
		payload["started_at"] = normalizeRFC3339(*run.StartedAt)
	}
	if run.CompletedAt != nil {
		payload["completed_at"] = normalizeRFC3339(*run.CompletedAt)
	}
	if run.RequestedBy != "" {
		payload["requested_by"] = run.RequestedBy
	}
	if run.CacheKey != "" {
		payload["cache_key"] = run.CacheKey
	}
	if run.JobID != "" {
		payload["job_id"] = run.JobID
	}
	if run.JobStatusURL != "" {
		payload["job_status_url"] = run.JobStatusURL
	}
	if run.Error != "" {
		payload["error"] = run.Error
		if run.Status == graph.ReportRunStatusCanceled {
			payload["cancel_reason"] = run.Error
		}
	}
	if run.Lineage.GraphSnapshotID != "" {
		payload["graph_snapshot_id"] = run.Lineage.GraphSnapshotID
	}
	if run.Lineage.GraphBuiltAt != nil {
		payload["graph_built_at"] = normalizeRFC3339(*run.Lineage.GraphBuiltAt)
	}
	if run.Snapshot != nil {
		payload["snapshot_id"] = run.Snapshot.ID
		payload["result_schema"] = run.Snapshot.ResultSchema
		payload["section_count"] = run.Snapshot.SectionCount
	}
	if attempt := graph.LatestReportRunAttempt(run); attempt != nil {
		if attempt.TriggerSurface != "" {
			payload["trigger_surface"] = attempt.TriggerSurface
		}
		if attempt.ExecutionSurface != "" {
			payload["execution_surface"] = attempt.ExecutionSurface
		}
		if attempt.ExecutionHost != "" {
			payload["execution_host"] = attempt.ExecutionHost
		}
		if attempt.Classification != "" {
			payload["attempt_classification"] = attempt.Classification
		}
		if attempt.RetryOfAttemptID != "" {
			payload["retry_of_attempt_id"] = attempt.RetryOfAttemptID
		}
		if attempt.RetryReason != "" {
			payload["retry_reason"] = attempt.RetryReason
		}
		if attempt.RetryBackoffMS > 0 {
			payload["retry_backoff_ms"] = attempt.RetryBackoffMS
		}
		if attempt.ScheduledFor != nil {
			payload["scheduled_for"] = normalizeRFC3339(*attempt.ScheduledFor)
		}
	}
	return payload
}

func platformReportSnapshotEventPayload(run *graph.ReportRun) map[string]any {
	if run == nil || run.Snapshot == nil {
		return nil
	}
	payload := map[string]any{
		"snapshot_id":               run.Snapshot.ID,
		"run_id":                    run.ID,
		"report_id":                 run.ReportID,
		"result_schema":             run.Snapshot.ResultSchema,
		"generated_at":              normalizeRFC3339(run.Snapshot.GeneratedAt),
		"recorded_at":               normalizeRFC3339(run.Snapshot.RecordedAt),
		"content_hash":              run.Snapshot.ContentHash,
		"byte_size":                 run.Snapshot.ByteSize,
		"section_count":             run.Snapshot.SectionCount,
		"retained":                  run.Snapshot.Retained,
		"status_url":                run.StatusURL,
		"storage_class":             run.Snapshot.Storage.StorageClass,
		"retention_tier":            run.Snapshot.Storage.RetentionTier,
		"materialized_result":       run.Snapshot.Storage.MaterializedResultAvailable,
		"result_truncated":          run.Snapshot.Storage.ResultTruncated,
		"report_definition_version": run.Snapshot.Lineage.ReportDefinitionVersion,
		"graph_schema_version":      run.Snapshot.Lineage.GraphSchemaVersion,
		"ontology_contract_version": run.Snapshot.Lineage.OntologyContractVersion,
	}
	if run.Snapshot.ExpiresAt != nil {
		payload["expires_at"] = normalizeRFC3339(*run.Snapshot.ExpiresAt)
	}
	if run.CacheKey != "" {
		payload["cache_key"] = run.CacheKey
	}
	if run.Snapshot.Lineage.GraphSnapshotID != "" {
		payload["graph_snapshot_id"] = run.Snapshot.Lineage.GraphSnapshotID
	}
	if run.Snapshot.Lineage.GraphBuiltAt != nil {
		payload["graph_built_at"] = normalizeRFC3339(*run.Snapshot.Lineage.GraphBuiltAt)
	}
	return payload
}

func platformExecutionHost() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(host)
}

func reportExecutionSurface(executionMode string) string {
	switch strings.TrimSpace(executionMode) {
	case graph.ReportExecutionModeAsync:
		return "platform.job"
	default:
		return "platform.inline"
	}
}

func platformReportTriggerSurface(run *graph.ReportRun) string {
	if run == nil {
		return ""
	}
	if attempt := graph.LatestReportRunAttempt(run); attempt != nil && strings.TrimSpace(attempt.TriggerSurface) != "" {
		return strings.TrimSpace(attempt.TriggerSurface)
	}
	return "api.request"
}
