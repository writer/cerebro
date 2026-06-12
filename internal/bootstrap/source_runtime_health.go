package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sourceRuntimeHealthResponse struct {
	GeneratedAt     string                       `json:"generated_at"`
	Runtimes        []sourceRuntimeHealthRecord  `json:"runtimes"`
	SourceSummaries []sourceRuntimeHealthSummary `json:"source_summaries"`
}

type runtimeFreshnessResponse struct {
	GeneratedAt string                    `json:"generated_at"`
	Status      string                    `json:"status"`
	Runtimes    []runtimeFreshnessRecord  `json:"runtimes"`
	Summaries   []runtimeFreshnessSummary `json:"summaries"`
}

type runtimeFreshnessSummary struct {
	SourceID              string `json:"source_id"`
	Total                 int    `json:"total"`
	Healthy               int    `json:"healthy"`
	NeedsAttention        int    `json:"needs_attention"`
	SourceFailed          int    `json:"source_failed"`
	SourceStale           int    `json:"source_stale"`
	GraphMissing          int    `json:"graph_missing"`
	GraphFailed           int    `json:"graph_failed"`
	GraphBehind           int    `json:"graph_behind"`
	BackfillEligible      int    `json:"backfill_eligible"`
	QuarantinedOrDisabled int    `json:"quarantined_or_disabled"`
}

type runtimeFreshnessRecord struct {
	RuntimeID                 string                                `json:"runtime_id"`
	SourceID                  string                                `json:"source_id"`
	TenantID                  string                                `json:"tenant_id,omitempty"`
	Family                    string                                `json:"family,omitempty"`
	LifecycleState            string                                `json:"lifecycle_state"`
	ScheduleState             string                                `json:"schedule_state"`
	FreshnessState            string                                `json:"freshness_state"`
	SourceSyncState           string                                `json:"source_sync_state"`
	GraphIngestState          string                                `json:"graph_ingest_state"`
	FindingEvaluationState    string                                `json:"finding_evaluation_state"`
	FailureClass              string                                `json:"failure_class,omitempty"`
	FailureReason             string                                `json:"failure_reason,omitempty"`
	LastSyncedAt              string                                `json:"last_synced_at,omitempty"`
	SyncLagSeconds            *int64                                `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark       string                                `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds       *int64                                `json:"watermark_lag_seconds,omitempty"`
	LatestGraphRun            *sourceRuntimeHealthGraphRun          `json:"latest_graph_run,omitempty"`
	GraphLagSeconds           *int64                                `json:"graph_lag_seconds,omitempty"`
	LatestFindingEvaluation   *sourceRuntimeHealthFindingEvaluation `json:"latest_finding_evaluation,omitempty"`
	ExpectedCadenceSeconds    *int64                                `json:"expected_cadence_seconds,omitempty"`
	StaleAfterSeconds         *int64                                `json:"stale_after_seconds,omitempty"`
	BackfillEligible          bool                                  `json:"backfill_eligible"`
	BackfillEligibilityReason string                                `json:"backfill_eligibility_reason,omitempty"`
	NextAction                string                                `json:"next_action"`
	RecommendedWorkflow       string                                `json:"recommended_workflow,omitempty"`
	CursorPending             bool                                  `json:"cursor_pending"`
	CheckpointCursorPresent   bool                                  `json:"checkpoint_cursor_present"`
	ScheduleContextConfigured bool                                  `json:"schedule_context_configured"`
	GeneratedAt               string                                `json:"generated_at"`
}

type sourceRuntimeHealthSummary struct {
	SourceID                   string `json:"source_id"`
	Total                      int    `json:"total"`
	Healthy                    int    `json:"healthy"`
	Stale                      int    `json:"stale"`
	Failing                    int    `json:"failing"`
	Unknown                    int    `json:"unknown"`
	CursorPending              int    `json:"cursor_pending"`
	GraphCurrent               int    `json:"graph_current"`
	GraphBehind                int    `json:"graph_behind"`
	GraphRunning               int    `json:"graph_running"`
	GraphFailed                int    `json:"graph_failed"`
	GraphNotObserved           int    `json:"graph_not_observed"`
	ContractProbePassing       int    `json:"contract_probe_passing"`
	ContractProbeFailure       int    `json:"contract_probe_failure"`
	ContractProbeUnknown       int    `json:"contract_probe_unknown"`
	ContractProbeNotConfigured int    `json:"contract_probe_not_configured"`
}

type sourceRuntimeHealthRecord struct {
	RuntimeID                 string                                `json:"runtime_id"`
	SourceID                  string                                `json:"source_id"`
	TenantID                  string                                `json:"tenant_id"`
	Family                    string                                `json:"family,omitempty"`
	EnabledState              string                                `json:"enabled_state"`
	Status                    string                                `json:"status"`
	LastSyncedAt              string                                `json:"last_synced_at,omitempty"`
	SyncLagSeconds            *int64                                `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark       string                                `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds       *int64                                `json:"watermark_lag_seconds,omitempty"`
	RecentSync                sourceRuntimeHealthSync               `json:"recent_sync"`
	LastFailureCategory       string                                `json:"last_failure_category,omitempty"`
	ContractProbeState        string                                `json:"contract_probe_state"`
	CursorPending             bool                                  `json:"cursor_pending"`
	CheckpointCursorPresent   bool                                  `json:"checkpoint_cursor_present"`
	LatestGraphRun            *sourceRuntimeHealthGraphRun          `json:"latest_graph_run,omitempty"`
	GraphLagSeconds           *int64                                `json:"graph_lag_seconds,omitempty"`
	LatestFindingEvaluation   *sourceRuntimeHealthFindingEvaluation `json:"latest_finding_evaluation,omitempty"`
	ExpectedCadenceSeconds    *int64                                `json:"expected_cadence_seconds,omitempty"`
	StaleAfterSeconds         *int64                                `json:"stale_after_seconds,omitempty"`
	ScheduleContextConfigured bool                                  `json:"schedule_context_configured"`
	GeneratedAt               string                                `json:"generated_at"`
}

type sourceRuntimeHealthSync struct {
	RecordsScanned    uint32 `json:"records_scanned"`
	RecordsAccepted   uint32 `json:"records_accepted"`
	RecordsRejected   uint32 `json:"records_rejected"`
	EntitiesProjected uint32 `json:"entities_projected"`
	LinksProjected    uint32 `json:"links_projected"`
}

type sourceRuntimeHealthGraphRun struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	StartedAt         string `json:"started_at,omitempty"`
	FinishedAt        string `json:"finished_at,omitempty"`
	Error             string `json:"error,omitempty"`
	PagesRead         int64  `json:"pages_read"`
	EventsRead        int64  `json:"events_read"`
	EntitiesProjected int64  `json:"entities_projected"`
	LinksProjected    int64  `json:"links_projected"`
	GraphNodesBefore  int64  `json:"graph_nodes_before"`
	GraphLinksBefore  int64  `json:"graph_links_before"`
	GraphNodesAfter   int64  `json:"graph_nodes_after"`
	GraphLinksAfter   int64  `json:"graph_links_after"`
	GraphNodeDelta    int64  `json:"graph_node_delta"`
	GraphLinkDelta    int64  `json:"graph_link_delta"`
	DurationSeconds   *int64 `json:"duration_seconds,omitempty"`
}

type sourceRuntimeHealthFindingEvaluation struct {
	ID               string `json:"id"`
	RuntimeID        string `json:"runtime_id"`
	RuleID           string `json:"rule_id,omitempty"`
	Status           string `json:"status"`
	StartedAt        string `json:"started_at,omitempty"`
	FinishedAt       string `json:"finished_at,omitempty"`
	Error            string `json:"error,omitempty"`
	EventsEvaluated  uint32 `json:"events_evaluated"`
	EventsProcessed  uint32 `json:"events_processed"`
	EventsMatched    uint32 `json:"events_matched"`
	FindingsUpserted uint32 `json:"findings_upserted"`
	FindingsEmitted  uint32 `json:"findings_emitted"`
	GraphRule        *bool  `json:"graph_rule,omitempty"`
	GraphRowsRead    uint32 `json:"graph_rows_read,omitempty"`
	DurationSeconds  *int64 `json:"duration_seconds,omitempty"`
}

const (
	runtimeStatusConfigKey                = "__cerebro_runtime_status"
	runtimeRecordsScannedConfigKey        = "__cerebro_runtime_records_scanned"
	runtimeRecordsAcceptedConfigKey       = "__cerebro_runtime_records_accepted"
	runtimeRecordsRejectedConfigKey       = "__cerebro_runtime_records_rejected"
	runtimeEntitiesProjectedConfigKey     = "__cerebro_runtime_entities_projected"
	runtimeLinksProjectedConfigKey        = "__cerebro_runtime_links_projected"
	runtimeLastFailureCategoryConfigKey   = "__cerebro_runtime_last_failure_category"
	runtimeContractProbeStateConfigKey    = "__cerebro_runtime_contract_probe_state"
	runtimeLastInvalidEventIDConfigKey    = "__cerebro_runtime_last_invalid_event_id"
	runtimeLastInvalidFieldConfigKey      = "__cerebro_runtime_last_invalid_field"
	runtimeLastInvalidStatusConfigKey     = "__cerebro_runtime_last_invalid_status"
	runtimeLastInvalidObservedAtConfigKey = "__cerebro_runtime_last_invalid_observed_at"
	runtimeLastInvalidOccurredAtConfigKey = "__cerebro_runtime_last_invalid_occurred_at"
	runtimeLastInvalidDiagnosticConfigKey = "__cerebro_runtime_last_invalid_diagnostic"
	runtimeLastInvalidRetryableConfigKey  = "__cerebro_runtime_last_invalid_retryable"
)

func (a *App) handleListSourceRuntimeHealth(w http.ResponseWriter, r *http.Request) {
	response, err := a.listSourceRuntimeHealth(r)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleListRuntimeFreshness(w http.ResponseWriter, r *http.Request) {
	health, err := a.listSourceRuntimeHealth(r)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runtimeFreshnessFromHealth(health))
}

func (a *App) listSourceRuntimeHealth(r *http.Request) (sourceRuntimeHealthResponse, error) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		return sourceRuntimeHealthResponse{}, err
	}
	filter := ports.SourceRuntimeFilter{
		RuntimeID:  strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		RuntimeIDs: csvQueryValues(r.URL.Query().Get("runtime_ids")),
		TenantID:   strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		SourceID:   strings.TrimSpace(r.URL.Query().Get("source_id")),
		Limit:      limit,
	}
	if filter.TenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok && strings.TrimSpace(auth.principal.TenantID) != "" {
			filter.TenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if filter.TenantID == "" {
		filter.TenantID = strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant"))
	}
	if filter.TenantID == "" && filter.RuntimeID != "" && requiresTenantFilter(r.Context()) {
		store := sourceRuntimeStore(a.deps.StateStore)
		if store == nil {
			return sourceRuntimeHealthResponse{}, sourceruntime.ErrRuntimeUnavailable
		}
		runtime, err := store.GetSourceRuntime(r.Context(), filter.RuntimeID)
		if errors.Is(err, ports.ErrSourceRuntimeNotFound) {
			return sourceRuntimeHealthResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
		}
		if err != nil {
			return sourceRuntimeHealthResponse{}, err
		}
		if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			return sourceRuntimeHealthResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
		}
		filter.TenantID = strings.TrimSpace(runtime.GetTenantId())
	}
	if filter.TenantID == "" && filter.RuntimeID == "" && len(filter.RuntimeIDs) == 0 && requiresTenantFilter(r.Context()) {
		return sourceRuntimeHealthResponse{}, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), filter.TenantID); err != nil {
		return sourceRuntimeHealthResponse{}, err
	}
	store := sourceRuntimeStore(a.deps.StateStore)
	if store == nil {
		return sourceRuntimeHealthResponse{}, sourceruntime.ErrRuntimeUnavailable
	}
	lister, ok := store.(ports.SourceRuntimeListStore)
	if !ok {
		return sourceRuntimeHealthResponse{}, sourceruntime.ErrRuntimeUnavailable
	}
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	runtimes, err := lister.ListSourceRuntimes(r.Context(), filter)
	if err != nil {
		return sourceRuntimeHealthResponse{}, err
	}
	generatedAt := time.Now().UTC()
	records := make([]sourceRuntimeHealthRecord, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if requiresTenantFilter(r.Context()) && !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			continue
		}
		record, err := a.sourceRuntimeHealthRecord(r.Context(), runtime, generatedAt)
		if err != nil {
			return sourceRuntimeHealthResponse{}, err
		}
		records = append(records, record)
	}
	return sourceRuntimeHealthResponse{
		GeneratedAt:     generatedAt.Format(time.RFC3339Nano),
		Runtimes:        records,
		SourceSummaries: sourceRuntimeHealthSummaries(records),
	}, nil
}

func runtimeFreshnessFromHealth(health sourceRuntimeHealthResponse) runtimeFreshnessResponse {
	records := make([]runtimeFreshnessRecord, 0, len(health.Runtimes))
	for _, record := range health.Runtimes {
		records = append(records, runtimeFreshnessRecordFromHealth(record))
	}
	status := "healthy"
	for _, record := range records {
		if record.FreshnessState != "healthy" {
			status = "degraded"
			break
		}
	}
	return runtimeFreshnessResponse{
		GeneratedAt: health.GeneratedAt,
		Status:      status,
		Runtimes:    records,
		Summaries:   runtimeFreshnessSummaries(records),
	}
}

func runtimeFreshnessRecordFromHealth(record sourceRuntimeHealthRecord) runtimeFreshnessRecord {
	lifecycleState := "active"
	if strings.ToLower(strings.TrimSpace(record.EnabledState)) == "disabled" {
		lifecycleState = "disabled"
	}
	sourceSyncState := runtimeFreshnessSourceSyncState(record)
	graphIngestState := sourceRuntimeGraphState(record)
	findingEvaluationState := runtimeFreshnessFindingEvaluationState(record)
	scheduleState := "unknown"
	if record.ScheduleContextConfigured {
		scheduleState = "configured"
	}
	freshnessState, failureClass, failureReason, nextAction := runtimeFreshnessState(record, lifecycleState, sourceSyncState, graphIngestState)
	backfillEligible, backfillReason := runtimeBackfillEligibility(lifecycleState, sourceSyncState, graphIngestState)
	workflow := ""
	if backfillEligible {
		workflow = "source-runtime-backfill"
	}
	return runtimeFreshnessRecord{
		RuntimeID:                 record.RuntimeID,
		SourceID:                  record.SourceID,
		TenantID:                  record.TenantID,
		Family:                    record.Family,
		LifecycleState:            lifecycleState,
		ScheduleState:             scheduleState,
		FreshnessState:            freshnessState,
		SourceSyncState:           sourceSyncState,
		GraphIngestState:          graphIngestState,
		FindingEvaluationState:    findingEvaluationState,
		FailureClass:              failureClass,
		FailureReason:             failureReason,
		LastSyncedAt:              record.LastSyncedAt,
		SyncLagSeconds:            record.SyncLagSeconds,
		CheckpointWatermark:       record.CheckpointWatermark,
		WatermarkLagSeconds:       record.WatermarkLagSeconds,
		LatestGraphRun:            record.LatestGraphRun,
		GraphLagSeconds:           record.GraphLagSeconds,
		LatestFindingEvaluation:   record.LatestFindingEvaluation,
		ExpectedCadenceSeconds:    record.ExpectedCadenceSeconds,
		StaleAfterSeconds:         record.StaleAfterSeconds,
		BackfillEligible:          backfillEligible,
		BackfillEligibilityReason: backfillReason,
		NextAction:                nextAction,
		RecommendedWorkflow:       workflow,
		CursorPending:             record.CursorPending,
		CheckpointCursorPresent:   record.CheckpointCursorPresent,
		ScheduleContextConfigured: record.ScheduleContextConfigured,
		GeneratedAt:               record.GeneratedAt,
	}
}

func runtimeFreshnessSourceSyncState(record sourceRuntimeHealthRecord) string {
	if strings.TrimSpace(record.LastFailureCategory) != "" {
		return "failed"
	}
	switch strings.ToLower(strings.TrimSpace(record.Status)) {
	case "failing":
		return "failed"
	case "stale":
		return "stale"
	case "healthy":
		return "current"
	default:
		return "unknown"
	}
}

func runtimeFreshnessFindingEvaluationState(record sourceRuntimeHealthRecord) string {
	if record.LatestFindingEvaluation == nil {
		return "not_observed"
	}
	status := strings.ToLower(strings.TrimSpace(record.LatestFindingEvaluation.Status))
	if strings.Contains(status, "fail") || strings.Contains(status, "error") || strings.Contains(status, "cancel") {
		return "failed"
	}
	if strings.Contains(status, "running") || strings.Contains(status, "pending") {
		return "running"
	}
	return "current"
}

func runtimeFreshnessState(record sourceRuntimeHealthRecord, lifecycleState string, sourceSyncState string, graphIngestState string) (string, string, string, string) {
	if lifecycleState != "active" {
		return "disabled", "disabled", "runtime is disabled", "review_runtime_enablement"
	}
	if sourceSyncState == "failed" {
		failureClass := strings.TrimSpace(record.LastFailureCategory)
		if failureClass == "" {
			failureClass = "source_sync_failed"
		}
		return "source_failed", failureClass, "source sync is failing", "fix_source_sync"
	}
	switch graphIngestState {
	case "failed":
		return "graph_failed", "graph_ingest_failed", "latest graph ingest failed", "inspect_graph_ingest"
	case "not_observed":
		return "graph_missing", "graph_ingest_missing", "no graph ingest run has been observed", "plan_backfill"
	case "behind":
		return "graph_behind", "graph_ingest_behind", "graph ingest is older than the configured freshness window", "plan_backfill"
	}
	if sourceSyncState == "stale" {
		return "source_stale", "source_sync_stale", "source runtime is older than the configured freshness window", "run_source_sync"
	}
	if sourceSyncState == "current" && graphIngestState == "current" {
		return "healthy", "", "", "monitor"
	}
	return "unknown", "insufficient_signal", "source or graph freshness signal is unavailable", "inspect_runtime"
}

func runtimeBackfillEligibility(lifecycleState string, sourceSyncState string, graphIngestState string) (bool, string) {
	if lifecycleState != "active" {
		return false, "runtime is disabled"
	}
	if sourceSyncState == "failed" {
		return false, "source sync must succeed before graph backfill"
	}
	switch graphIngestState {
	case "failed", "not_observed", "behind":
		return true, "graph ingest is missing, failed, or behind"
	default:
		return false, "graph ingest backfill is not indicated"
	}
}

func runtimeFreshnessSummaries(records []runtimeFreshnessRecord) []runtimeFreshnessSummary {
	bySource := map[string]*runtimeFreshnessSummary{}
	for _, record := range records {
		sourceID := record.SourceID
		if sourceID == "" {
			sourceID = "unknown"
		}
		summary := bySource[sourceID]
		if summary == nil {
			summary = &runtimeFreshnessSummary{SourceID: sourceID}
			bySource[sourceID] = summary
		}
		summary.Total++
		if record.FreshnessState == "healthy" {
			summary.Healthy++
		} else {
			summary.NeedsAttention++
		}
		switch record.FreshnessState {
		case "source_failed":
			summary.SourceFailed++
		case "source_stale":
			summary.SourceStale++
		case "graph_missing":
			summary.GraphMissing++
		case "graph_failed":
			summary.GraphFailed++
		case "graph_behind":
			summary.GraphBehind++
		case "disabled":
			summary.QuarantinedOrDisabled++
		}
		if record.BackfillEligible {
			summary.BackfillEligible++
		}
	}
	summaries := make([]runtimeFreshnessSummary, 0, len(bySource))
	for _, summary := range bySource {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].NeedsAttention != summaries[j].NeedsAttention {
			return summaries[i].NeedsAttention > summaries[j].NeedsAttention
		}
		if summaries[i].Total != summaries[j].Total {
			return summaries[i].Total > summaries[j].Total
		}
		return summaries[i].SourceID < summaries[j].SourceID
	})
	return summaries
}

func sourceRuntimeHealthSummaries(records []sourceRuntimeHealthRecord) []sourceRuntimeHealthSummary {
	bySource := map[string]*sourceRuntimeHealthSummary{}
	for _, record := range records {
		sourceID := strings.TrimSpace(record.SourceID)
		if sourceID == "" {
			sourceID = "unknown"
		}
		summary := bySource[sourceID]
		if summary == nil {
			summary = &sourceRuntimeHealthSummary{SourceID: sourceID}
			bySource[sourceID] = summary
		}
		summary.Total++
		switch strings.ToLower(strings.TrimSpace(record.Status)) {
		case "healthy":
			summary.Healthy++
		case "stale":
			summary.Stale++
		case "failing":
			summary.Failing++
		default:
			summary.Unknown++
		}
		if record.CursorPending {
			summary.CursorPending++
		}
		switch sourceRuntimeGraphState(record) {
		case "current":
			summary.GraphCurrent++
		case "behind":
			summary.GraphBehind++
		case "running":
			summary.GraphRunning++
		case "failed":
			summary.GraphFailed++
		default:
			summary.GraphNotObserved++
		}
		switch strings.ToLower(strings.TrimSpace(record.ContractProbeState)) {
		case "passing":
			summary.ContractProbePassing++
		case "failure":
			summary.ContractProbeFailure++
		case "unknown":
			summary.ContractProbeUnknown++
		default:
			summary.ContractProbeNotConfigured++
		}
	}
	summaries := make([]sourceRuntimeHealthSummary, 0, len(bySource))
	for _, summary := range bySource {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Total != summaries[j].Total {
			return summaries[i].Total > summaries[j].Total
		}
		return summaries[i].SourceID < summaries[j].SourceID
	})
	return summaries
}

func sourceRuntimeGraphState(record sourceRuntimeHealthRecord) string {
	if record.LatestGraphRun == nil {
		return "not_observed"
	}
	status := strings.ToLower(strings.TrimSpace(record.LatestGraphRun.Status))
	if strings.Contains(status, "fail") || strings.Contains(status, "error") || strings.Contains(status, "cancel") {
		return "failed"
	}
	if strings.Contains(status, "running") || strings.Contains(status, "pending") {
		return "running"
	}
	if record.GraphLagSeconds != nil && record.StaleAfterSeconds != nil && *record.GraphLagSeconds > *record.StaleAfterSeconds {
		return "behind"
	}
	return "current"
}

func (a *App) sourceRuntimeHealthRecord(ctx context.Context, runtime *cerebrov1.SourceRuntime, generatedAt time.Time) (sourceRuntimeHealthRecord, error) {
	record := sourceRuntimeHealthRecord{
		RuntimeID:    strings.TrimSpace(runtime.GetId()),
		SourceID:     strings.TrimSpace(runtime.GetSourceId()),
		TenantID:     strings.TrimSpace(runtime.GetTenantId()),
		Family:       strings.TrimSpace(runtime.GetConfig()["family"]),
		EnabledState: runtimeEnabledState(runtime),
		Status:       runtimeHealthStatus(runtime, generatedAt),
		RecentSync: sourceRuntimeHealthSync{
			RecordsScanned:    runtimeConfigUint32(runtime, runtimeRecordsScannedConfigKey),
			RecordsAccepted:   runtimeConfigUint32(runtime, runtimeRecordsAcceptedConfigKey),
			RecordsRejected:   runtimeConfigUint32(runtime, runtimeRecordsRejectedConfigKey),
			EntitiesProjected: runtimeConfigUint32(runtime, runtimeEntitiesProjectedConfigKey),
			LinksProjected:    runtimeConfigUint32(runtime, runtimeLinksProjectedConfigKey),
		},
		LastFailureCategory:     strings.TrimSpace(runtime.GetConfig()[runtimeLastFailureCategoryConfigKey]),
		ContractProbeState:      runtimeContractProbeState(runtime),
		CursorPending:           strings.TrimSpace(runtime.GetNextCursor().GetOpaque()) != "",
		CheckpointCursorPresent: strings.TrimSpace(runtime.GetCheckpoint().GetCursorOpaque()) != "",
		// Schedule cadence/SLA is currently deployment configuration, not runtime state.
		ScheduleContextConfigured: false,
		GeneratedAt:               generatedAt.Format(time.RFC3339Nano),
	}
	if lastSynced := timestampValue(runtime.GetLastSyncedAt()); !lastSynced.IsZero() {
		lastSynced = lastSynced.UTC()
		record.LastSyncedAt = lastSynced.Format(time.RFC3339Nano)
		record.SyncLagSeconds = secondsSince(generatedAt, lastSynced)
	}
	if watermark := timestampValue(runtime.GetCheckpoint().GetWatermark()); !watermark.IsZero() {
		watermark = watermark.UTC()
		record.CheckpointWatermark = watermark.Format(time.RFC3339Nano)
		record.WatermarkLagSeconds = secondsSince(generatedAt, watermark)
	}
	graphRun, err := a.latestGraphIngestRun(ctx, record.RuntimeID)
	if err != nil {
		return record, err
	}
	if graphRun != nil {
		record.LatestGraphRun = sourceRuntimeGraphRunHealth(*graphRun)
		record.GraphLagSeconds = graphRunLagSeconds(generatedAt, *graphRun)
	}
	findingRun, err := a.latestFindingEvaluationRun(ctx, record.RuntimeID)
	if err != nil {
		return record, err
	}
	if findingRun != nil {
		record.LatestFindingEvaluation = sourceRuntimeFindingEvaluationHealth(findingRun)
	}
	if expectedCadence := runtimeConfigInt64(runtime, "expected_cadence_seconds"); expectedCadence > 0 {
		record.ExpectedCadenceSeconds = &expectedCadence
		record.ScheduleContextConfigured = true
	}
	if staleAfter := runtimeConfigInt64(runtime, "stale_after_seconds"); staleAfter > 0 {
		record.StaleAfterSeconds = &staleAfter
		record.ScheduleContextConfigured = true
	}
	return record, nil
}

func runtimeConfigUint32(runtime *cerebrov1.SourceRuntime, key string) uint32 {
	if runtime == nil {
		return 0
	}
	value, err := strconv.ParseUint(strings.TrimSpace(runtime.GetConfig()[key]), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(value)
}

func runtimeConfigInt64(runtime *cerebrov1.SourceRuntime, key string) int64 {
	if runtime == nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(runtime.GetConfig()[key]), 10, 64)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func runtimeEnabledState(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return "unknown"
	}
	switch strings.ToLower(strings.TrimSpace(runtime.GetConfig()["enabled"])) {
	case "false", "0", "disabled":
		return "disabled"
	default:
		return "enabled"
	}
}

func runtimeHealthStatus(runtime *cerebrov1.SourceRuntime, now time.Time) string {
	if runtime == nil {
		return "unknown"
	}
	if strings.TrimSpace(runtime.GetConfig()[runtimeLastFailureCategoryConfigKey]) != "" {
		return "failing"
	}
	lastSynced := timestampValue(runtime.GetLastSyncedAt())
	if lastSynced.IsZero() {
		return "unknown"
	}
	if staleAfter := runtimeConfigInt64(runtime, "stale_after_seconds"); staleAfter > 0 && now.UTC().Sub(lastSynced.UTC()) > time.Duration(staleAfter)*time.Second {
		return "stale"
	}
	return "healthy"
}

func runtimeContractProbeState(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return "unknown"
	}
	if state := strings.TrimSpace(runtime.GetConfig()[runtimeContractProbeStateConfigKey]); state != "" {
		return state
	}
	if strings.TrimSpace(runtime.GetSourceId()) != "evidence_cas" {
		return "not_configured"
	}
	if runtime.GetLastSyncedAt() == nil {
		return "unknown"
	}
	return "passing"
}

func (a *App) latestGraphIngestRun(ctx context.Context, runtimeID string) (*graphstore.IngestRun, error) {
	runStore, ok := a.deps.GraphStore.(graphingest.RunStore)
	if !ok || isNilInterface(runStore) {
		return nil, nil
	}
	runs, err := runStore.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: runtimeID, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return &runs[0], nil
}

func (a *App) latestFindingEvaluationRun(ctx context.Context, runtimeID string) (*cerebrov1.FindingEvaluationRun, error) {
	runStore := findingEvaluationRunStore(a.deps.StateStore)
	if runStore == nil {
		return nil, nil
	}
	runs, err := runStore.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{RuntimeID: runtimeID, Limit: 1})
	if err != nil {
		if errors.Is(err, findings.ErrRuntimeUnavailable) {
			return nil, nil
		}
		return nil, err
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return runs[0], nil
}

func sourceRuntimeGraphRunHealth(run graphstore.IngestRun) *sourceRuntimeHealthGraphRun {
	return &sourceRuntimeHealthGraphRun{
		ID:                run.ID,
		Status:            run.Status,
		StartedAt:         run.StartedAt,
		FinishedAt:        run.FinishedAt,
		Error:             run.Error,
		PagesRead:         run.PagesRead,
		EventsRead:        run.EventsRead,
		EntitiesProjected: run.EntitiesProjected,
		LinksProjected:    run.LinksProjected,
		GraphNodesBefore:  run.GraphNodesBefore,
		GraphLinksBefore:  run.GraphLinksBefore,
		GraphNodesAfter:   run.GraphNodesAfter,
		GraphLinksAfter:   run.GraphLinksAfter,
		GraphNodeDelta:    run.GraphNodesAfter - run.GraphNodesBefore,
		GraphLinkDelta:    run.GraphLinksAfter - run.GraphLinksBefore,
		DurationSeconds:   durationSeconds(run.StartedAt, run.FinishedAt),
	}
}

func sourceRuntimeFindingEvaluationHealth(run *cerebrov1.FindingEvaluationRun) *sourceRuntimeHealthFindingEvaluation {
	if run == nil {
		return nil
	}
	var graphRowsRead uint32
	if run.GraphRowsRead != nil {
		graphRowsRead = run.GetGraphRowsRead()
	}
	return &sourceRuntimeHealthFindingEvaluation{
		ID:               run.GetId(),
		RuntimeID:        run.GetRuntimeId(),
		RuleID:           run.GetRuleId(),
		Status:           run.GetStatus(),
		StartedAt:        timestampString(run.GetStartedAt()),
		FinishedAt:       timestampString(run.GetFinishedAt()),
		Error:            run.GetError(),
		EventsEvaluated:  run.GetEventsEvaluated(),
		EventsProcessed:  run.GetEventsProcessed(),
		EventsMatched:    run.GetEventsMatched(),
		FindingsUpserted: run.GetFindingsUpserted(),
		FindingsEmitted:  run.GetFindingsEmitted(),
		GraphRule:        run.GraphRule,
		GraphRowsRead:    graphRowsRead,
		DurationSeconds:  timestampDurationSeconds(run.GetStartedAt(), run.GetFinishedAt()),
	}
}

func timestampString(value *timestamppb.Timestamp) string {
	if value == nil {
		return ""
	}
	timestamp := value.AsTime()
	if timestamp.IsZero() {
		return ""
	}
	return timestamp.UTC().Format(time.RFC3339Nano)
}

func secondsSince(now time.Time, then time.Time) *int64 {
	seconds := int64(now.UTC().Sub(then.UTC()).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}

func graphRunLagSeconds(now time.Time, run graphstore.IngestRun) *int64 {
	if finished, ok := parseRFC3339(run.FinishedAt); ok {
		return secondsSince(now, finished)
	}
	if started, ok := parseRFC3339(run.StartedAt); ok {
		return secondsSince(now, started)
	}
	return nil
}

func durationSeconds(startedAt string, finishedAt string) *int64 {
	started, ok := parseRFC3339(startedAt)
	if !ok {
		return nil
	}
	finished, ok := parseRFC3339(finishedAt)
	if !ok {
		return nil
	}
	seconds := int64(finished.Sub(started).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}

func timestampDurationSeconds(startedAt *timestamppb.Timestamp, finishedAt *timestamppb.Timestamp) *int64 {
	if startedAt == nil || finishedAt == nil {
		return nil
	}
	started := startedAt.AsTime()
	finished := finishedAt.AsTime()
	if started.IsZero() || finished.IsZero() {
		return nil
	}
	seconds := int64(finished.UTC().Sub(started.UTC()).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}

func parseRFC3339(value string) (time.Time, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
