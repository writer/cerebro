package bootstrap

import (
	"context"
	"errors"
	"net/http"
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
	GeneratedAt string                      `json:"generated_at"`
	Runtimes    []sourceRuntimeHealthRecord `json:"runtimes"`
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
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	filter := ports.SourceRuntimeFilter{
		RuntimeID: strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		TenantID:  strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		SourceID:  strings.TrimSpace(r.URL.Query().Get("source_id")),
		Limit:     limit,
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
			writeSourceRuntimeError(w, sourceruntime.ErrRuntimeUnavailable)
			return
		}
		runtime, err := store.GetSourceRuntime(r.Context(), filter.RuntimeID)
		if errors.Is(err, ports.ErrSourceRuntimeNotFound) {
			writeJSON(w, http.StatusOK, sourceRuntimeHealthResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			return
		}
		if err != nil {
			writeSourceRuntimeError(w, err)
			return
		}
		if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			writeJSON(w, http.StatusOK, sourceRuntimeHealthResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			return
		}
		filter.TenantID = strings.TrimSpace(runtime.GetTenantId())
	}
	if filter.TenantID == "" && filter.RuntimeID == "" && requiresTenantFilter(r.Context()) {
		writeSourceRuntimeError(w, errTenantForbidden)
		return
	}
	if err := authorizeTenantID(r.Context(), filter.TenantID); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	store := sourceRuntimeStore(a.deps.StateStore)
	if store == nil {
		writeSourceRuntimeError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	lister, ok := store.(ports.SourceRuntimeListStore)
	if !ok {
		writeSourceRuntimeError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	runtimes, err := lister.ListSourceRuntimes(r.Context(), filter)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
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
			writeSourceRuntimeError(w, err)
			return
		}
		records = append(records, record)
	}
	writeJSON(w, http.StatusOK, sourceRuntimeHealthResponse{
		GeneratedAt: generatedAt.Format(time.RFC3339Nano),
		Runtimes:    records,
	})
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
