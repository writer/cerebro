package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/webhooks"
)

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
