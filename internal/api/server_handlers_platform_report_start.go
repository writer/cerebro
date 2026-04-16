package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/webhooks"
)

func (s *Server) currentPlatformSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	if s == nil || s.app == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return currentOrStoredGraphView(ctx, s.app.CurrentSecurityGraph(), s.app.CurrentSecurityGraphStore())
}

func (s *Server) currentPlatformReportLineage(ctx context.Context, definition reports.ReportDefinition) reports.ReportLineage {
	g, err := s.currentPlatformSecurityGraphView(ctx)
	if err != nil {
		return reports.BuildReportLineage(nil, definition)
	}
	return reports.BuildReportLineage(g, definition)
}

func (s *Server) startPlatformReportRun(ctx context.Context, reportID string, req platformReportRunRequest, requestedBy, triggerSurface string) (*reports.ReportRun, int, error) {
	definition, ok := reports.GetReportDefinition(reportID)
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("report definition not found")
	}
	if err := reports.ValidateReportParameterValues(definition, req.Parameters); err != nil {
		return nil, http.StatusBadRequest, err
	}

	executionMode := strings.ToLower(strings.TrimSpace(req.ExecutionMode))
	if executionMode == "" {
		executionMode = reports.ReportExecutionModeSync
	}
	if executionMode != reports.ReportExecutionModeSync && executionMode != reports.ReportExecutionModeAsync {
		return nil, http.StatusBadRequest, fmt.Errorf("execution_mode must be one of sync, async")
	}
	materializeResult := true
	if req.MaterializeResult != nil {
		materializeResult = *req.MaterializeResult
	}
	retryPolicy := reports.ReportRetryPolicy{}
	if req.RetryPolicy != nil {
		retryPolicy = *req.RetryPolicy
	}
	retryPolicy = reports.NormalizeReportRetryPolicy(retryPolicy)

	cacheKey, err := reports.BuildReportRunCacheKey(reportID, req.Parameters)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	now := time.Now().UTC()
	lineage := s.currentPlatformReportLineage(ctx, definition)
	storagePolicy := reports.BuildReportStoragePolicy(materializeResult, false)
	cacheSource := s.reusablePlatformReportRun(reportID, cacheKey, lineage, "")
	if strings.TrimSpace(requestedBy) == "" {
		requestedBy = strings.TrimSpace(GetUserID(ctx))
	}
	run := &reports.ReportRun{
		ID:            "report_run:" + uuid.NewString(),
		ReportID:      reportID,
		Status:        reports.ReportRunStatusQueued,
		ExecutionMode: executionMode,
		SubmittedAt:   now,
		RequestedBy:   strings.TrimSpace(requestedBy),
		Parameters:    reports.CloneReportParameterValues(req.Parameters),
		TimeSlice:     reports.ExtractReportTimeSlice(req.Parameters),
		CacheKey:      cacheKey,
		CacheStatus:   reports.ReportCacheStatusMiss,
		RetryPolicy:   retryPolicy,
		Lineage:       lineage,
		Storage:       storagePolicy,
	}
	if cacheSource != nil {
		run.CacheStatus = reports.ReportCacheStatusHit
		run.CacheSourceRunID = cacheSource.ID
	}
	run.StatusURL = "/api/v1/platform/intelligence/reports/" + reportID + "/runs/" + run.ID
	if triggerSurface == "" {
		triggerSurface = "api.request"
	}
	executionSurface := reportExecutionSurface(executionMode)
	run.Attempts = []reports.ReportRunAttempt{
		reports.NewReportRunAttempt(run.ID, 1, reports.ReportAttemptStatusQueued, triggerSurface, executionSurface, platformExecutionHost(), run.RequestedBy, "", now),
	}
	run.LatestAttemptID = run.Attempts[0].ID
	run.AttemptCount = len(run.Attempts)
	reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunQueued), run.Status, triggerSurface, run.RequestedBy, now, map[string]any{
		"report_id":           reportID,
		"execution_mode":      executionMode,
		"execution_surface":   executionSurface,
		"cache_status":        run.CacheStatus,
		"cache_source_run_id": run.CacheSourceRunID,
		"materialized_result": materializeResult,
		"api_credential_id":   strings.TrimSpace(GetAPICredentialID(ctx)),
		"api_client_id":       strings.TrimSpace(GetAPIClientID(ctx)),
		"traceparent":         strings.TrimSpace(GetTraceparent(ctx)),
	})
	run.EventCount = len(run.Events)
	s.bindAgentSDKReportProgress(run.ID, ctx)

	if executionMode == reports.ReportExecutionModeAsync {
		job := s.newPlatformJob(ctx, "platform.report_run", map[string]any{
			"report_id":       reportID,
			"run_id":          run.ID,
			"cache_key":       cacheKey,
			"parameter_count": len(req.Parameters),
		}, run.RequestedBy)
		run.JobID = job.ID
		run.JobStatusURL = job.StatusURL
		run.Attempts[0].JobID = job.ID
		if err := s.storePlatformReportRun(run); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunQueued, reportID, run.ID)

		// #nosec G118 -- async report runs intentionally detach from request lifetime and are canceled through the platform job.
		s.startPlatformJob(job.ID, func(jobCtx context.Context) (any, error) {
			if err := s.executePlatformReportRun(jobCtx, run.ID, definition, req.Parameters, materializeResult); err != nil {
				return nil, err
			}
			stored, ok := s.platformReportRunSnapshot(reportID, run.ID)
			if !ok {
				return nil, fmt.Errorf("report run %q disappeared during execution", run.ID)
			}
			return reports.SummarizeReportRun(*stored), nil
		})
		return run, http.StatusAccepted, nil
	}

	if err := s.storePlatformReportRun(run); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunQueued, reportID, run.ID)
	if err := s.executePlatformReportRun(ctx, run.ID, definition, req.Parameters, materializeResult); err != nil {
		stored, _ := s.platformReportRunSnapshot(reportID, run.ID)
		if stored != nil {
			return stored, http.StatusInternalServerError, err
		}
		return nil, http.StatusInternalServerError, err
	}
	stored, _ := s.platformReportRunSnapshot(reportID, run.ID)
	if stored == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("report run disappeared after execution")
	}
	return stored, http.StatusCreated, nil
}
