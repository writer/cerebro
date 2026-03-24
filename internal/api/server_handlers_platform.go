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

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
	risk "github.com/writer/cerebro/internal/graph/risk"
	"github.com/writer/cerebro/internal/webhooks"
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

func (s *Server) listPlatformGraphSnapshots(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, s.platformGraphSnapshotCollection(r.Context()))
}

func (s *Server) getCurrentPlatformGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	record, err := currentOrStoredGraphSnapshotRecord(r.Context(), s.currentTenantSecurityGraph(r.Context()), s.currentTenantSecurityGraphStore(r.Context()))
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			s.errorFromErr(w, err)
			return
		}
		s.errorFromErr(w, err)
		return
	}
	if record == nil {
		s.error(w, http.StatusNotFound, "graph snapshot not available")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	if snapshotID == "" {
		s.error(w, http.StatusBadRequest, "snapshot id required")
		return
	}
	snapshot, ok := s.platformGraphSnapshot(r.Context(), snapshotID)
	if !ok {
		s.error(w, http.StatusNotFound, "graph snapshot not found")
		return
	}
	s.json(w, http.StatusOK, snapshot)
}

func (s *Server) currentPlatformSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	if s == nil || s.app == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return currentOrStoredGraphView(ctx, s.app.CurrentSecurityGraph(), s.app.CurrentSecurityGraphStore())
}

func (s *Server) currentPlatformReportLineage(ctx context.Context, definition reports.ReportDefinition) reports.ReportLineage {
	if s == nil || s.app == nil {
		return reports.BuildReportLineageFromMetadata(reports.Metadata{}, definition)
	}
	meta, err := currentOrStoredGraphMetadata(ctx, s.app.CurrentSecurityGraph(), s.app.CurrentSecurityGraphStore())
	if err != nil {
		return reports.BuildReportLineageFromMetadata(reports.Metadata{}, definition)
	}
	return reports.BuildReportLineageFromMetadata(meta, definition)
}

func (s *Server) platformWriteClaim(w http.ResponseWriter, r *http.Request) {
	s.graphWriteClaim(w, r)
}

func (s *Server) platformWriteDecision(w http.ResponseWriter, r *http.Request) {
	s.graphWriteDecision(w, r)
}

func (s *Server) createSecurityAttackPathJob(w http.ResponseWriter, r *http.Request) {
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
	analysisGraph := s.currentTenantSecurityGraph(r.Context())
	analysisStore := s.currentTenantSecurityGraphStore(r.Context())
	if analysisGraph == nil && analysisStore == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	job := s.newPlatformJob(r.Context(), "security.attack_path_analysis", map[string]any{
		"max_depth": maxDepth,
		"threshold": req.Threshold,
		"limit":     limit,
	}, GetUserID(r.Context()))

	// #nosec G118 -- platform jobs intentionally outlive the originating request and use job-owned cancellation.
	s.startPlatformJob(job.ID, func(ctx context.Context) (any, error) {
		var result *risk.SimulationResult
		if analysisStore != nil {
			queryStore, ok := graph.AsAttackPathQueryStore(analysisStore)
			if !ok {
				var err error
				result, err = graph.SimulateAttackPathsFromStore(ctx, analysisStore, maxDepth)
				if err != nil {
					return nil, err
				}
			} else {
				var err error
				result, err = queryStore.AttackPaths(ctx, maxDepth)
				if err != nil {
					return nil, err
				}
			}
		} else {
			simulator := risk.NewAttackPathSimulator(analysisGraph)
			result = simulator.Simulate(maxDepth)
		}
		if req.Threshold > 0 {
			filtered := make([]*risk.ScoredAttackPath, 0, len(result.Paths))
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
	s.json(w, http.StatusOK, reports.ReportCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceReport(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	report, ok := reports.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) listPlatformIntelligenceMeasures(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportMeasureCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceChecks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportCheckCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceSectionEnvelopes(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportSectionEnvelopeCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceSectionEnvelope(w http.ResponseWriter, r *http.Request) {
	envelopeID := strings.TrimSpace(chi.URLParam(r, "envelope_id"))
	if envelopeID == "" {
		s.error(w, http.StatusBadRequest, "envelope id required")
		return
	}
	envelope, ok := reports.GetReportSectionEnvelopeDefinition(envelopeID)
	if !ok {
		s.error(w, http.StatusNotFound, "section envelope definition not found")
		return
	}
	s.json(w, http.StatusOK, envelope)
}

func (s *Server) listPlatformIntelligenceSectionFragments(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportSectionFragmentCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceSectionFragment(w http.ResponseWriter, r *http.Request) {
	fragmentID := strings.TrimSpace(chi.URLParam(r, "fragment_id"))
	if fragmentID == "" {
		s.error(w, http.StatusBadRequest, "fragment id required")
		return
	}
	fragment, ok := reports.GetReportSectionFragmentDefinition(fragmentID)
	if !ok {
		s.error(w, http.StatusNotFound, "section fragment definition not found")
		return
	}
	s.json(w, http.StatusOK, fragment)
}

func (s *Server) listPlatformIntelligenceBenchmarkPacks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.BenchmarkPackCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceBenchmarkPack(w http.ResponseWriter, r *http.Request) {
	packID := strings.TrimSpace(chi.URLParam(r, "pack_id"))
	if packID == "" {
		s.error(w, http.StatusBadRequest, "benchmark pack id required")
		return
	}
	pack, ok := reports.GetBenchmarkPack(packID)
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

func (s *Server) executePlatformReportRun(ctx context.Context, runID string, definition reports.ReportDefinition, parameters []reports.ReportParameterValue, materializeResult bool) error {
	startedAt := time.Now().UTC()
	canceledBeforeStart := false
	if err := s.updatePlatformReportRun(runID, func(run *reports.ReportRun) {
		if run.Status == reports.ReportRunStatusCanceled {
			canceledBeforeStart = true
			return
		}
		run.Status = reports.ReportRunStatusRunning
		run.StartedAt = &startedAt
		run.Error = ""
		reports.StartLatestReportRunAttempt(run, startedAt)
		reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunStarted), run.Status, platformReportTriggerSurface(run), run.RequestedBy, startedAt, map[string]any{
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
	executionRun, ok := s.platformReportRunSnapshot(definition.ID, runID)
	if !ok || executionRun == nil {
		return fmt.Errorf("report run disappeared before execution: %s", runID)
	}
	if platformReportCancellationRequested(executionRun) {
		return context.Canceled
	}
	cacheSource, err := s.refreshPlatformReportRunCacheBinding(runID, executionRun)
	if err != nil {
		return err
	}
	s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunStarted, definition.ID, runID)

	var result map[string]any
	if cacheSource != nil {
		result = cloneJSONObject(cacheSource.Result)
	} else {
		result, err = s.executePlatformReport(ctx, definition.ID, parameters)
	}
	completedAt := time.Now().UTC()
	latestRun, ok := s.platformReportRunSnapshot(definition.ID, runID)
	if ok && latestRun != nil && platformReportCancellationRequested(latestRun) {
		return context.Canceled
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			alreadyCanceled := false
			cancelReason := err.Error()
			if updateErr := s.updatePlatformReportRun(runID, func(run *reports.ReportRun) {
				if run.Status == reports.ReportRunStatusCanceled {
					alreadyCanceled = true
					return
				}
				if strings.TrimSpace(run.CancelReason) != "" {
					cancelReason = strings.TrimSpace(run.CancelReason)
				}
				run.Status = reports.ReportRunStatusCanceled
				run.CompletedAt = &completedAt
				run.Error = cancelReason
				reports.CompleteLatestReportRunAttempt(run, run.Status, completedAt, cancelReason, reports.ReportAttemptClassCancelled)
				reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunCanceled), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
					"report_id":     run.ReportID,
					"cancel_reason": cancelReason,
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
		if updateErr := s.updatePlatformReportRun(runID, func(run *reports.ReportRun) {
			run.Status = reports.ReportRunStatusFailed
			run.CompletedAt = &completedAt
			run.Error = err.Error()
			reports.CompleteLatestReportRunAttempt(run, run.Status, completedAt, err.Error(), classification)
			reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunFailed), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
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

	artifactRun, ok := s.platformReportRunSnapshot(definition.ID, runID)
	if !ok || artifactRun == nil {
		return fmt.Errorf("report run disappeared before artifact build: %s", runID)
	}
	sections, sectionEmissions, snapshot, err := s.buildPlatformReportArtifacts(ctx, artifactRun, runID, definition, result, materializeResult, completedAt)
	if err != nil {
		classification := platformReportAttemptClassification(err)
		if updateErr := s.updatePlatformReportRun(runID, func(run *reports.ReportRun) {
			run.Status = reports.ReportRunStatusFailed
			run.CompletedAt = &completedAt
			run.Error = err.Error()
			reports.CompleteLatestReportRunAttempt(run, run.Status, completedAt, err.Error(), classification)
			reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunFailed), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
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

	canceledBeforeCommit := false
	if err := s.updatePlatformReportRun(runID, func(run *reports.ReportRun) {
		if run.Status == reports.ReportRunStatusCanceled {
			canceledBeforeCommit = true
			return
		}
		run.Status = reports.ReportRunStatusSucceeded
		run.CompletedAt = &completedAt
		run.Sections = reports.CloneReportSectionResults(sections)
		run.Snapshot = snapshot
		run.Result = cloneJSONObject(result)
		run.Storage = reports.BuildReportStoragePolicy(snapshot != nil, false)
		reports.CompleteLatestReportRunAttempt(run, run.Status, completedAt, "", "")
		if snapshot != nil {
			snapshot.Lineage = reports.CloneReportLineage(run.Lineage)
			snapshot.Storage = reports.BuildReportStoragePolicy(true, false)
			reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportSnapshotMaterialized), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
				"report_id":   run.ReportID,
				"snapshot_id": snapshot.ID,
			})
		}
		for _, emission := range sectionEmissions {
			eventData := map[string]any{
				"report_id":        run.ReportID,
				"section_key":      emission.Section.Key,
				"sequence":         emission.Sequence,
				"emitted_at":       normalizeRFC3339(emission.EmittedAt),
				"progress_percent": emission.ProgressPercent,
				"envelope_kind":    emission.Section.EnvelopeKind,
				"content_type":     emission.Section.ContentType,
				"item_count":       emission.Section.ItemCount,
				"field_count":      emission.Section.FieldCount,
				"field_keys":       append([]string(nil), emission.Section.FieldKeys...),
				"measure_ids":      append([]string(nil), emission.Section.MeasureIDs...),
			}
			for key, value := range platformReportSectionMetadataPayload(emission.Section) {
				eventData[key] = value
			}
			if snapshot != nil {
				eventData["snapshot_id"] = snapshot.ID
			}
			reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportSectionEmitted), run.Status, platformReportTriggerSurface(run), run.RequestedBy, emission.EmittedAt, eventData)
		}
		reports.AppendReportRunEvent(run, string(webhooks.EventPlatformReportRunCompleted), run.Status, platformReportTriggerSurface(run), run.RequestedBy, completedAt, map[string]any{
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
	stored, ok := s.platformReportRunSnapshot(definition.ID, runID)
	if !ok || stored == nil {
		return fmt.Errorf("report run disappeared after commit: %s", runID)
	}
	if snapshot != nil {
		s.emitPlatformReportSnapshotLifecycleEvent(ctx, definition.ID, runID)
	}
	for _, emission := range sectionEmissions {
		s.emitPlatformReportSectionLifecycleEvent(ctx, stored, emission)
	}
	s.emitPlatformReportRunLifecycleEvent(ctx, webhooks.EventPlatformReportRunCompleted, definition.ID, runID)
	return nil
}

func (s *Server) executePlatformReport(ctx context.Context, reportID string, parameters []reports.ReportParameterValue) (map[string]any, error) {
	definition, ok := reports.GetReportDefinition(reportID)
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

func reportParameterValuesToQuery(values []reports.ReportParameterValue) (url.Values, error) {
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
		return reports.ReportAttemptClassCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return reports.ReportAttemptClassTransient
	}
	var executionErr reportExecutionError
	if errors.As(err, &executionErr) {
		switch executionErr.StatusCode {
		case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusConflict:
			return reports.ReportAttemptClassTransient
		}
		if executionErr.StatusCode >= 500 {
			return reports.ReportAttemptClassTransient
		}
		return reports.ReportAttemptClassDeterministic
	}
	return reports.ReportAttemptClassDeterministic
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
		if job.Status == reports.ReportRunStatusCanceled || job.Status == "canceled" {
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

func (s *Server) startPlatformJob(jobID string, runner func(context.Context) (any, error)) {
	s.platformJobWG.Add(1)
	go func() {
		defer s.platformJobWG.Done()
		s.runPlatformJob(jobID, runner)
	}()
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
	if job.Error == "" {
		job.Error = job.CancelReason
	}
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
func (s *Server) attachPlatformReportRunJob(runID string, job *platformJob) (*reports.ReportRun, bool, string, error) {
	if job == nil {
		return nil, false, "", fmt.Errorf("platform job is required")
	}
	cancelJob := false
	cancelReason := ""
	stored, err := s.updatePlatformReportRunSnapshot(runID, func(updated *reports.ReportRun) {
		updated.JobID = job.ID
		updated.JobStatusURL = job.StatusURL
		for i := len(updated.Attempts) - 1; i >= 0; i-- {
			if updated.Attempts[i].ID == updated.LatestAttemptID {
				updated.Attempts[i].JobID = job.ID
				break
			}
		}
		if updated.Status == reports.ReportRunStatusCanceled {
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

func (s *Server) storePlatformReportRun(run *reports.ReportRun) error {
	if run == nil {
		return nil
	}
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(run); err != nil {
			return fmt.Errorf("persist report run %q: %w", run.ID, err)
		}
	}
	s.syncPlatformJobWithReportRun(run)
	s.cachePlatformReportRun(run)
	return nil
}

func (s *Server) updatePlatformReportRun(runID string, apply func(*reports.ReportRun)) error {
	_, err := s.updatePlatformReportRunSnapshot(runID, apply)
	return err
}

func (s *Server) updatePlatformReportRunSnapshot(runID string, apply func(*reports.ReportRun)) (*reports.ReportRun, error) {
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	var (
		run *reports.ReportRun
		err error
	)
	if s.platformReportStore != nil {
		run, err = s.platformReportStore.LoadRun(runID)
		if err != nil {
			return nil, fmt.Errorf("load report run %q: %w", runID, err)
		}
	}
	if run == nil {
		s.platformReportRunMu.RLock()
		run = reports.CloneReportRun(s.platformReportRuns[runID])
		s.platformReportRunMu.RUnlock()
	}
	if run == nil {
		return nil, fmt.Errorf("report run not found: %s", runID)
	}
	updated := reports.CloneReportRun(run)
	apply(updated)
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(updated); err != nil {
			return nil, fmt.Errorf("persist report run %q: %w", runID, err)
		}
	}
	s.syncPlatformJobWithReportRun(updated)
	s.cachePlatformReportRun(updated)
	return reports.CloneReportRun(updated), nil
}

func (s *Server) platformReportRunSnapshot(reportID, runID string) (*reports.ReportRun, bool) {
	if s.platformReportStore != nil {
		run, err := s.platformReportStore.LoadRun(runID)
		if err == nil && run != nil && run.ReportID == reportID {
			s.cachePlatformReportRun(run)
			return reports.CloneReportRun(run), true
		}
	}
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	run, ok := s.platformReportRuns[runID]
	if !ok || run.ReportID != reportID {
		return nil, false
	}
	return reports.CloneReportRun(run), true
}

func (s *Server) syncPlatformJobWithReportRun(run *reports.ReportRun) {
	if run == nil {
		return
	}
	jobID := strings.TrimSpace(run.JobID)
	if jobID == "" {
		return
	}
	s.platformJobMu.Lock()
	defer s.platformJobMu.Unlock()
	job, ok := s.platformJobs[jobID]
	if !ok || job == nil {
		return
	}
	if run.CancelRequestedAt != nil {
		cancelRequestedAt := *run.CancelRequestedAt
		job.CancelRequestedAt = &cancelRequestedAt
	}
	if reason := strings.TrimSpace(run.CancelReason); reason != "" {
		job.CancelReason = reason
	}
	switch run.Status {
	case reports.ReportRunStatusRunning:
		job.Status = "running"
		if run.StartedAt != nil {
			startedAt := *run.StartedAt
			job.StartedAt = &startedAt
		}
	case reports.ReportRunStatusSucceeded:
		job.Status = "succeeded"
		if run.CompletedAt != nil {
			completedAt := *run.CompletedAt
			job.CompletedAt = &completedAt
		}
		job.Error = ""
		job.Result = cloneJSONValue(reports.SummarizeReportRun(*run))
	case reports.ReportRunStatusFailed:
		job.Status = "failed"
		if run.CompletedAt != nil {
			completedAt := *run.CompletedAt
			job.CompletedAt = &completedAt
		}
		job.Error = run.Error
	case reports.ReportRunStatusCanceled:
		// Preserve cancellation metadata immediately, but do not flip an active
		// job to terminal canceled until the job-owned cancel func has been
		// invoked. Otherwise handlers that are waiting on request context
		// cancellation can hang indefinitely.
		if job.cancel == nil {
			job.Status = "canceled"
			if run.CompletedAt != nil {
				completedAt := *run.CompletedAt
				job.CompletedAt = &completedAt
			}
		}
		if job.Error == "" {
			job.Error = strings.TrimSpace(run.CancelReason)
		}
	}
}

func (s *Server) platformReportRunSummaries(reportID string) []reports.ReportRunSummary {
	if s.platformReportStore != nil {
		runs, err := s.platformReportStore.ListRuns(reportID)
		if err == nil {
			s.cachePlatformReportRuns(runs)
			summaries := make([]reports.ReportRunSummary, 0, len(runs))
			for _, run := range runs {
				if run == nil {
					continue
				}
				summaries = append(summaries, reports.SummarizeReportRun(*run))
			}
			sort.Slice(summaries, func(i, j int) bool {
				if summaries[i].SubmittedAt.Equal(summaries[j].SubmittedAt) {
					return summaries[i].ID > summaries[j].ID
				}
				return summaries[i].SubmittedAt.After(summaries[j].SubmittedAt)
			})
			return summaries
		}
	}
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	runs := make([]reports.ReportRunSummary, 0)
	for _, run := range s.platformReportRuns {
		if run.ReportID != reportID {
			continue
		}
		runs = append(runs, reports.SummarizeReportRun(*run))
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].SubmittedAt.Equal(runs[j].SubmittedAt) {
			return runs[i].ID > runs[j].ID
		}
		return runs[i].SubmittedAt.After(runs[j].SubmittedAt)
	})
	return runs
}

func (s *Server) reusablePlatformReportRun(reportID, cacheKey string, lineage reports.ReportLineage, excludeRunID string) *reports.ReportRun {
	reportID = strings.TrimSpace(reportID)
	cacheKey = strings.TrimSpace(cacheKey)
	excludeRunID = strings.TrimSpace(excludeRunID)
	if reportID == "" || cacheKey == "" {
		return nil
	}
	candidates := make([]*reports.ReportRun, 0)
	if s.platformReportStore != nil {
		if storedRuns, err := s.platformReportStore.ListRuns(reportID); err == nil {
			s.cachePlatformReportRuns(storedRuns)
			candidates = append(candidates, storedRuns...)
		}
	}
	if len(candidates) == 0 {
		s.platformReportRunMu.RLock()
		for _, candidate := range s.platformReportRuns {
			candidates = append(candidates, reports.CloneReportRun(candidate))
		}
		s.platformReportRunMu.RUnlock()
	}
	var best *reports.ReportRun
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if strings.TrimSpace(candidate.ID) == excludeRunID {
			continue
		}
		if candidate.ReportID != reportID || candidate.Status != reports.ReportRunStatusSucceeded {
			continue
		}
		if strings.TrimSpace(candidate.CacheKey) != cacheKey {
			continue
		}
		if len(candidate.Result) == 0 {
			continue
		}
		if !platformReportLineageCompatible(candidate.Lineage, lineage) {
			continue
		}
		if best == nil || platformReportRunCompletedAt(candidate).After(platformReportRunCompletedAt(best)) {
			best = reports.CloneReportRun(candidate)
		}
	}
	return best
}

func (s *Server) refreshPlatformReportRunCacheBinding(runID string, run *reports.ReportRun) (*reports.ReportRun, error) {
	if run == nil {
		return nil, nil
	}
	cacheSource := s.selectPlatformReportCacheSource(run)
	cacheStatus := reports.ReportCacheStatusMiss
	cacheSourceRunID := ""
	if cacheSource != nil {
		cacheStatus = reports.ReportCacheStatusHit
		cacheSourceRunID = cacheSource.ID
	}
	if strings.TrimSpace(run.CacheStatus) == cacheStatus && strings.TrimSpace(run.CacheSourceRunID) == cacheSourceRunID {
		return cacheSource, nil
	}
	if err := s.updatePlatformReportRun(runID, func(updated *reports.ReportRun) {
		updated.CacheStatus = cacheStatus
		updated.CacheSourceRunID = cacheSourceRunID
	}); err != nil {
		return nil, err
	}
	return cacheSource, nil
}

func (s *Server) selectPlatformReportCacheSource(run *reports.ReportRun) *reports.ReportRun {
	if run == nil {
		return nil
	}
	if sourceRunID := strings.TrimSpace(run.CacheSourceRunID); sourceRunID != "" && sourceRunID != strings.TrimSpace(run.ID) {
		if source, ok := s.platformReportRunSnapshot(run.ReportID, sourceRunID); ok && source != nil && platformReportRunReusableFor(source, run) {
			return source
		}
	}
	return s.reusablePlatformReportRun(run.ReportID, run.CacheKey, run.Lineage, run.ID)
}

func (s *Server) buildPlatformReportArtifacts(ctx context.Context, run *reports.ReportRun, runID string, definition reports.ReportDefinition, result map[string]any, materializeResult bool, completedAt time.Time) ([]reports.ReportSectionResult, []reports.ReportSectionEmission, *reports.ReportSnapshot, error) {
	options := s.platformReportSectionBuildOptions(ctx, run)
	sections := reports.BuildReportSectionResultsWithOptions(definition, result, options)
	sectionEmissions := reports.BuildReportSectionEmissionsFromResults(sections, result, completedAt)
	var snapshot *reports.ReportSnapshot
	if materializeResult {
		var err error
		snapshot, err = reports.BuildReportSnapshot(runID, definition, result, true, completedAt)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return sections, sectionEmissions, snapshot, nil
}

func (s *Server) platformReportSectionBuildOptions(ctx context.Context, run *reports.ReportRun) *reports.ReportSectionBuildOptions {
	if run == nil {
		return nil
	}
	g, err := s.currentPlatformSecurityGraphView(ctx)
	if err != nil {
		g = nil
	}
	options := &reports.ReportSectionBuildOptions{
		Graph:            g,
		TimeSlice:        run.TimeSlice,
		CacheStatus:      run.CacheStatus,
		CacheSourceRunID: run.CacheSourceRunID,
	}
	if attempt := reports.LatestReportRunAttempt(run); attempt != nil {
		options.RetryBackoffMS = attempt.RetryBackoffMS
	}
	return options
}

func platformReportRunReusableFor(source, run *reports.ReportRun) bool {
	if source == nil || run == nil {
		return false
	}
	if source.ReportID != run.ReportID || source.Status != reports.ReportRunStatusSucceeded {
		return false
	}
	if strings.TrimSpace(source.CacheKey) == "" || strings.TrimSpace(source.CacheKey) != strings.TrimSpace(run.CacheKey) {
		return false
	}
	if len(source.Result) == 0 {
		return false
	}
	return platformReportLineageCompatible(source.Lineage, run.Lineage)
}

func platformReportLineageCompatible(left, right reports.ReportLineage) bool {
	if left.GraphSnapshotID != "" || right.GraphSnapshotID != "" {
		if strings.TrimSpace(left.GraphSnapshotID) != strings.TrimSpace(right.GraphSnapshotID) {
			return false
		}
	}
	return left.GraphSchemaVersion == right.GraphSchemaVersion &&
		strings.TrimSpace(left.OntologyContractVersion) == strings.TrimSpace(right.OntologyContractVersion) &&
		strings.TrimSpace(left.ReportDefinitionVersion) == strings.TrimSpace(right.ReportDefinitionVersion)
}

func platformReportRunCompletedAt(run *reports.ReportRun) time.Time {
	if run == nil {
		return time.Time{}
	}
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt.UTC()
	}
	return run.SubmittedAt.UTC()
}

func (s *Server) clonePlatformReportRunsLocked() map[string]*reports.ReportRun {
	cloned := make(map[string]*reports.ReportRun, len(s.platformReportRuns))
	for id, run := range s.platformReportRuns {
		cloned[id] = reports.CloneReportRun(run)
	}
	return cloned
}

func (s *Server) platformGraphSnapshotCollection(ctx context.Context) graph.GraphSnapshotCollection {
	return graph.GraphSnapshotCollectionFromRecords(s.platformGraphSnapshotRecords(ctx), time.Now().UTC())
}

func (s *Server) platformGraphSnapshot(ctx context.Context, snapshotID string) (*graph.GraphSnapshotRecord, bool) {
	record, ok := s.platformGraphSnapshotRecords(ctx)[strings.TrimSpace(snapshotID)]
	if !ok || record == nil {
		return nil, false
	}
	snapshot := *record
	return &snapshot, true
}

func (s *Server) emitPlatformReportRunLifecycleEvent(ctx context.Context, eventType webhooks.EventType, reportID, runID string) {
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok || run == nil {
		return
	}
	s.emitPlatformLifecycleEvent(ctx, eventType, platformReportRunEventPayload(run))
	s.emitPlatformReportRunLifecycleStream(run, eventType)
	s.emitAgentSDKReportProgress(run)
}

func (s *Server) emitPlatformReportSnapshotLifecycleEvent(ctx context.Context, reportID, runID string) {
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok || run == nil || run.Snapshot == nil {
		return
	}
	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformReportSnapshotMaterialized, platformReportSnapshotEventPayload(run))
}

func (s *Server) emitPlatformReportSectionLifecycleEvent(ctx context.Context, run *reports.ReportRun, section reports.ReportSectionEmission) {
	if run == nil {
		return
	}
	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformReportSectionEmitted, platformReportSectionEventPayload(run, section))
	s.emitPlatformReportSectionStream(run, section)
	s.emitAgentSDKReportSection(run, section)
}

func platformReportRunEventPayload(run *reports.ReportRun) map[string]any {
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
	if run.CacheStatus != "" {
		payload["cache_status"] = run.CacheStatus
	}
	if run.CacheSourceRunID != "" {
		payload["cache_source_run_id"] = run.CacheSourceRunID
	}
	if run.JobID != "" {
		payload["job_id"] = run.JobID
	}
	if run.JobStatusURL != "" {
		payload["job_status_url"] = run.JobStatusURL
	}
	if run.Error != "" {
		payload["error"] = run.Error
		if run.Status == reports.ReportRunStatusCanceled {
			payload["cancel_reason"] = run.Error
		}
	}
	if run.CancelRequestedAt != nil {
		payload["cancel_requested_at"] = normalizeRFC3339(*run.CancelRequestedAt)
	}
	if run.CancelRequestedBy != "" {
		payload["cancel_requested_by"] = run.CancelRequestedBy
	}
	if run.CancelReason != "" {
		payload["cancel_reason"] = run.CancelReason
	}
	if run.Lineage.GraphSnapshotID != "" {
		payload["graph_snapshot_id"] = run.Lineage.GraphSnapshotID
		payload["graph_snapshot_url"] = "/api/v1/platform/graph/snapshots/" + run.Lineage.GraphSnapshotID
	}
	if run.Lineage.GraphBuiltAt != nil {
		payload["graph_built_at"] = normalizeRFC3339(*run.Lineage.GraphBuiltAt)
	}
	if run.Snapshot != nil {
		payload["snapshot_id"] = run.Snapshot.ID
		payload["result_schema"] = run.Snapshot.ResultSchema
		payload["section_count"] = run.Snapshot.SectionCount
	}
	if attempt := reports.LatestReportRunAttempt(run); attempt != nil {
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
		if attempt.Status != "" {
			payload["latest_attempt_status"] = attempt.Status
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

func platformReportSnapshotEventPayload(run *reports.ReportRun) map[string]any {
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
		payload["graph_snapshot_url"] = "/api/v1/platform/graph/snapshots/" + run.Snapshot.Lineage.GraphSnapshotID
	}
	if run.Snapshot.Lineage.GraphBuiltAt != nil {
		payload["graph_built_at"] = normalizeRFC3339(*run.Snapshot.Lineage.GraphBuiltAt)
	}
	return payload
}

func platformReportSectionEventPayload(run *reports.ReportRun, section reports.ReportSectionEmission) map[string]any {
	if run == nil {
		return nil
	}
	emission := reports.CloneReportSectionEmissions([]reports.ReportSectionEmission{section})[0]
	payload := map[string]any{
		"run_id":           run.ID,
		"report_id":        run.ReportID,
		"status":           run.Status,
		"status_url":       run.StatusURL,
		"section_key":      emission.Section.Key,
		"sequence":         emission.Sequence,
		"emitted_at":       normalizeRFC3339(emission.EmittedAt),
		"progress_percent": emission.ProgressPercent,
		"envelope_kind":    emission.Section.EnvelopeKind,
		"envelope_schema":  emission.Section.EnvelopeSchema,
		"content_type":     emission.Section.ContentType,
		"item_count":       emission.Section.ItemCount,
		"field_count":      emission.Section.FieldCount,
	}
	if len(emission.Section.FieldKeys) > 0 {
		payload["field_keys"] = append([]string(nil), emission.Section.FieldKeys...)
	}
	if len(emission.Section.MeasureIDs) > 0 {
		payload["measure_ids"] = append([]string(nil), emission.Section.MeasureIDs...)
	}
	for key, value := range platformReportSectionMetadataPayload(emission.Section) {
		payload[key] = value
	}
	if run.Snapshot != nil {
		payload["snapshot_id"] = run.Snapshot.ID
	}
	return payload
}

func platformReportSectionMetadataPayload(section reports.ReportSectionResult) map[string]any {
	payload := make(map[string]any)
	if section.Lineage != nil {
		lineage := map[string]any{
			"referenced_node_count": section.Lineage.ReferencedNodeCount,
			"claim_count":           section.Lineage.ClaimCount,
			"evidence_count":        section.Lineage.EvidenceCount,
			"source_count":          section.Lineage.SourceCount,
			"supporting_edge_count": section.Lineage.SupportingEdgeCount,
			"ids_truncated":         section.Lineage.IDsTruncated,
		}
		if len(section.Lineage.ReferencedNodeIDs) > 0 {
			lineage["referenced_node_ids"] = append([]string(nil), section.Lineage.ReferencedNodeIDs...)
		}
		if len(section.Lineage.ClaimIDs) > 0 {
			lineage["claim_ids"] = append([]string(nil), section.Lineage.ClaimIDs...)
		}
		if len(section.Lineage.EvidenceIDs) > 0 {
			lineage["evidence_ids"] = append([]string(nil), section.Lineage.EvidenceIDs...)
		}
		if len(section.Lineage.SourceIDs) > 0 {
			lineage["source_ids"] = append([]string(nil), section.Lineage.SourceIDs...)
		}
		if len(section.Lineage.SupportingEdgeIDs) > 0 {
			lineage["supporting_edge_ids"] = append([]string(nil), section.Lineage.SupportingEdgeIDs...)
		}
		if section.Lineage.ValidAt != nil {
			lineage["valid_at"] = normalizeRFC3339(*section.Lineage.ValidAt)
		}
		if section.Lineage.RecordedAt != nil {
			lineage["recorded_at"] = normalizeRFC3339(*section.Lineage.RecordedAt)
		}
		payload["lineage"] = lineage
	}
	if section.PayloadSchema != "" {
		payload["payload_schema"] = section.PayloadSchema
	}
	if section.PayloadSchemaURL != "" {
		payload["payload_schema_url"] = section.PayloadSchemaURL
	}
	if section.PayloadStrict {
		payload["payload_strict"] = true
	}
	if section.Materialization != nil {
		materialization := map[string]any{
			"truncated": section.Materialization.Truncated,
		}
		if len(section.Materialization.TruncationSignals) > 0 {
			materialization["truncation_signals"] = append([]string(nil), section.Materialization.TruncationSignals...)
		}
		payload["materialization"] = materialization
	}
	if section.Telemetry != nil {
		telemetry := map[string]any{
			"materialization_duration_ms": section.Telemetry.MaterializationDurationMS,
		}
		if section.Telemetry.CacheStatus != "" {
			telemetry["cache_status"] = section.Telemetry.CacheStatus
		}
		if section.Telemetry.CacheSourceRunID != "" {
			telemetry["cache_source_run_id"] = section.Telemetry.CacheSourceRunID
		}
		if section.Telemetry.RetryBackoffMS > 0 {
			telemetry["retry_backoff_ms"] = section.Telemetry.RetryBackoffMS
		}
		payload["telemetry"] = telemetry
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

func platformReportCancellationRequested(run *reports.ReportRun) bool {
	if run == nil {
		return false
	}
	return run.CancelRequestedAt != nil || strings.TrimSpace(run.Status) == reports.ReportRunStatusCanceled
}

func reportExecutionSurface(executionMode string) string {
	switch strings.TrimSpace(executionMode) {
	case reports.ReportExecutionModeAsync:
		return "platform.job"
	default:
		return "platform.inline"
	}
}

func platformReportTriggerSurface(run *reports.ReportRun) string {
	if run == nil {
		return ""
	}
	if attempt := reports.LatestReportRunAttempt(run); attempt != nil && strings.TrimSpace(attempt.TriggerSurface) != "" {
		return strings.TrimSpace(attempt.TriggerSurface)
	}
	return "api.request"
}

func (s *Server) cachePlatformReportRun(run *reports.ReportRun) {
	if s == nil || run == nil || strings.TrimSpace(run.ID) == "" {
		return
	}
	s.platformReportRunMu.Lock()
	s.platformReportRuns[run.ID] = reports.CloneReportRun(run)
	s.platformReportRunMu.Unlock()
}

func (s *Server) cachePlatformReportRuns(runs []*reports.ReportRun) {
	if s == nil || len(runs) == 0 {
		return
	}
	s.platformReportRunMu.Lock()
	defer s.platformReportRunMu.Unlock()
	for _, run := range runs {
		if run == nil || strings.TrimSpace(run.ID) == "" {
			continue
		}
		s.platformReportRuns[run.ID] = reports.CloneReportRun(run)
	}
}
