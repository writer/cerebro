package api

import (
	"context"
	"os"
	"strings"

	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/webhooks"
)

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
