package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/webhooks"
)

func (s *Server) retryPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	definition, ok := reports.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	if run.Status != reports.ReportRunStatusFailed && run.Status != reports.ReportRunStatusCanceled {
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
	if executionMode != reports.ReportExecutionModeSync && executionMode != reports.ReportExecutionModeAsync {
		s.error(w, http.StatusBadRequest, "execution_mode must be one of sync, async")
		return
	}
	materializeResult := run.Storage.MaterializedResultAvailable
	if req.MaterializeResult != nil {
		materializeResult = *req.MaterializeResult
	}
	parameters := reports.CloneReportParameterValues(run.Parameters)
	if len(req.Parameters) > 0 {
		parameters = reports.CloneReportParameterValues(req.Parameters)
	}
	if err := reports.ValidateReportParameterValues(definition, parameters); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	cacheKey, err := reports.BuildReportRunCacheKey(reportID, parameters)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	retryPolicy := run.RetryPolicy
	if req.RetryPolicy != nil {
		retryPolicy = *req.RetryPolicy
	}
	retryPolicy = reports.NormalizeReportRetryPolicy(retryPolicy)
	lineage := s.currentPlatformReportLineage(r.Context(), definition)
	cacheSource := s.reusablePlatformReportRun(reportID, cacheKey, lineage, runID)

	now := time.Now().UTC()
	retryReason := strings.TrimSpace(req.Reason)
	if retryReason == "" {
		retryReason = "manual_retry"
	}
	nextAttemptNumber := 0
	backoff := time.Duration(0)
	var previousAttemptID string
	retriedBy := strings.TrimSpace(GetUserID(r.Context()))
	if retriedBy == "" {
		retriedBy = run.RequestedBy
	}

	maxAttemptsExceeded := false
	if err := s.updatePlatformReportRun(runID, func(stored *reports.ReportRun) {
		if stored.AttemptCount >= retryPolicy.MaxAttempts {
			maxAttemptsExceeded = true
			return
		}
		nextAttemptNumber = len(stored.Attempts) + 1
		if executionMode == reports.ReportExecutionModeAsync {
			backoff = reports.ReportRetryBackoff(retryPolicy, nextAttemptNumber)
		}
		if attempt := reports.LatestReportRunAttempt(stored); attempt != nil {
			previousAttemptID = attempt.ID
		}
		attempt := reports.NewReportRunAttempt(stored.ID, nextAttemptNumber, reports.ReportRunStatusQueued, "api.retry", reportExecutionSurface(executionMode), platformExecutionHost(), retriedBy, "", now)
		attempt.RetryOfAttemptID = previousAttemptID
		attempt.RetryReason = retryReason
		attempt.RetryBackoffMS = backoff.Milliseconds()
		stored.Status = reports.ReportRunStatusQueued
		stored.ExecutionMode = executionMode
		stored.RequestedBy = retriedBy
		stored.Parameters = parameters
		stored.TimeSlice = reports.ExtractReportTimeSlice(parameters)
		stored.CacheKey = cacheKey
		stored.CacheStatus = reports.ReportCacheStatusMiss
		stored.CacheSourceRunID = ""
		if cacheSource != nil {
			stored.CacheStatus = reports.ReportCacheStatusHit
			stored.CacheSourceRunID = cacheSource.ID
		}
		stored.JobID = ""
		stored.JobStatusURL = ""
		stored.StartedAt = nil
		stored.CompletedAt = nil
		stored.Error = ""
		stored.CancelRequestedAt = nil
		stored.CancelRequestedBy = ""
		stored.CancelReason = ""
		stored.Sections = nil
		stored.Snapshot = nil
		stored.Result = nil
		stored.Storage = reports.BuildReportStoragePolicy(materializeResult, false)
		stored.RetryPolicy = retryPolicy
		stored.Lineage = lineage
		stored.Attempts = append(stored.Attempts, attempt)
		stored.LatestAttemptID = attempt.ID
		if backoff > 0 {
			reports.ScheduleLatestReportRunAttempt(stored, now.Add(backoff))
		}
		reports.AppendReportRunEvent(stored, string(webhooks.EventPlatformReportRunQueued), stored.Status, "api.retry", retriedBy, now, map[string]any{
			"report_id":           stored.ReportID,
			"execution_mode":      executionMode,
			"execution_surface":   reportExecutionSurface(executionMode),
			"cache_status":        stored.CacheStatus,
			"cache_source_run_id": stored.CacheSourceRunID,
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
	if maxAttemptsExceeded {
		s.error(w, http.StatusConflict, "retry policy max_attempts exhausted")
		return
	}

	stored, _ := s.platformReportRunSnapshot(reportID, runID)
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after retry")
		return
	}

	s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunQueued, reportID, runID)
	if executionMode == reports.ReportExecutionModeAsync {
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
			s.startPlatformJob(job.ID, func(jobCtx context.Context) (any, error) {
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
				return reports.SummarizeReportRun(*stored), nil
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
	if run.Status != reports.ReportRunStatusQueued && run.Status != reports.ReportRunStatusRunning {
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
	cancelAccepted := false
	cancelRejected := false

	stored, err := s.updatePlatformReportRunSnapshot(runID, func(stored *reports.ReportRun) {
		if stored.Status != reports.ReportRunStatusQueued && stored.Status != reports.ReportRunStatusRunning {
			cancelRejected = true
			return
		}
		cancelAccepted = stored.Status == reports.ReportRunStatusRunning
		stored.CancelRequestedAt = &canceledAt
		stored.CancelRequestedBy = actor
		stored.CancelReason = cancelReason
		stored.Status = reports.ReportRunStatusCanceled
		stored.CompletedAt = &canceledAt
		stored.Error = cancelReason
		reports.CompleteLatestReportRunAttempt(stored, stored.Status, canceledAt, cancelReason, reports.ReportAttemptClassCancelled)
		reports.AppendReportRunEvent(stored, string(webhooks.EventPlatformReportRunCanceled), stored.Status, "api.cancel", actor, canceledAt, map[string]any{
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
	if cancelRejected {
		s.error(w, http.StatusConflict, "only queued or running report runs can be canceled")
		return
	}
	if stored == nil {
		s.error(w, http.StatusInternalServerError, "report run disappeared after cancel")
		return
	}
	if stored.JobID != "" {
		s.cancelPlatformJob(stored.JobID, cancelReason)
	}
	if cancelAccepted {
		s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunCanceled, reportID, runID)
		s.json(w, http.StatusAccepted, stored)
		return
	}
	s.emitPlatformReportRunLifecycleEvent(r.Context(), webhooks.EventPlatformReportRunCanceled, reportID, runID)
	w.Header().Set("Location", stored.StatusURL)
	s.json(w, http.StatusOK, stored)
}
