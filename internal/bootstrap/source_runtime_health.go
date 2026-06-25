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
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/sourcehealthview"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sourceRuntimeHealthResponse struct {
	GeneratedAt     string                       `json:"generated_at"`
	Runtimes        []sourceRuntimeHealthRecord  `json:"runtimes"`
	SourceSummaries []sourceRuntimeHealthSummary `json:"source_summaries"`
	Coverage        []sourcecoverage.Record      `json:"coverage,omitempty"`
	CoverageSummary []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
}

type runtimeFreshnessResponse struct {
	GeneratedAt          string                    `json:"generated_at"`
	Status               string                    `json:"status"`
	Runtimes             []runtimeFreshnessRecord  `json:"runtimes"`
	Summaries            []runtimeFreshnessSummary `json:"summaries"`
	CoverageBlindSpots   []sourcecoverage.Record   `json:"coverage_blind_spots,omitempty"`
	CoverageBlindSummary []sourcecoverage.Summary  `json:"coverage_blind_summaries,omitempty"`
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
	runtimeFreshnessIdentity
	runtimeFreshnessStates
	runtimeFreshnessObservations
	runtimeFreshnessActions
}

type runtimeFreshnessIdentity struct {
	RuntimeID string `json:"runtime_id"`
	SourceID  string `json:"source_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	Family    string `json:"family,omitempty"`
}

type runtimeFreshnessStates struct {
	LifecycleState            string `json:"lifecycle_state"`
	ScheduleState             string `json:"schedule_state"`
	FreshnessState            string `json:"freshness_state"`
	SourceSyncState           string `json:"source_sync_state"`
	GraphIngestState          string `json:"graph_ingest_state"`
	FindingEvaluationState    string `json:"finding_evaluation_state"`
	FailureClass              string `json:"failure_class,omitempty"`
	FailureReason             string `json:"failure_reason,omitempty"`
	BackfillEligible          bool   `json:"backfill_eligible"`
	BackfillEligibilityReason string `json:"backfill_eligibility_reason,omitempty"`
}

type runtimeFreshnessObservations struct {
	LastSyncedAt            string                                `json:"last_synced_at,omitempty"`
	SyncLagSeconds          *int64                                `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark     string                                `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds     *int64                                `json:"watermark_lag_seconds,omitempty"`
	LatestGraphRun          *sourceRuntimeHealthGraphRun          `json:"latest_graph_run,omitempty"`
	GraphLagSeconds         *int64                                `json:"graph_lag_seconds,omitempty"`
	LatestFindingEvaluation *sourceRuntimeHealthFindingEvaluation `json:"latest_finding_evaluation,omitempty"`
	ExpectedCadenceSeconds  *int64                                `json:"expected_cadence_seconds,omitempty"`
	StaleAfterSeconds       *int64                                `json:"stale_after_seconds,omitempty"`
	GeneratedAt             string                                `json:"generated_at"`
}

type runtimeFreshnessActions struct {
	NextAction                string `json:"next_action"`
	RecommendedWorkflow       string `json:"recommended_workflow,omitempty"`
	CursorPending             bool   `json:"cursor_pending"`
	CheckpointCursorPresent   bool   `json:"checkpoint_cursor_present"`
	ScheduleContextConfigured bool   `json:"schedule_context_configured"`
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

type sourceRuntimeHealthRecord = sourcehealthview.Record
type sourceRuntimeHealthSync = sourcehealthview.Sync
type sourceRuntimeHealthGraphRun = sourcehealthview.GraphRun
type sourceRuntimeHealthFindingEvaluation = sourcehealthview.FindingEvaluation

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

	sourceRuntimeHealthRecordConcurrency = 8
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
func (a *App) handleGetConnectorCoverage(w http.ResponseWriter, r *http.Request) {
	health, err := a.listSourceRuntimeHealth(r)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	report := sourcecoverage.BuildScopedReport(health.Coverage, r.URL.Query().Get("tenant_id"), r.URL.Query().Get("source_id"), health.GeneratedAt)
	emitSourceCoverageGateTelemetry(r.Context(), report)
	writeJSON(w, http.StatusOK, report)
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
	visibleRuntimes := make([]*cerebrov1.SourceRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if requiresTenantFilter(r.Context()) && !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			continue
		}
		visibleRuntimes = append(visibleRuntimes, runtime)
	}
	records, err := a.sourceRuntimeHealthRecords(r.Context(), visibleRuntimes, generatedAt)
	if err != nil {
		return sourceRuntimeHealthResponse{}, err
	}
	coverage := a.sourceCoverageRecords(visibleRuntimes, filter, generatedAt)
	return sourceRuntimeHealthResponse{
		GeneratedAt:     generatedAt.Format(time.RFC3339Nano),
		Runtimes:        records,
		SourceSummaries: sourceRuntimeHealthSummaries(records),
		Coverage:        coverage,
		CoverageSummary: sourcecoverage.Summaries(coverage),
	}, nil
}

func emptySourceRuntimeHealthResponse() sourceRuntimeHealthResponse {
	return sourceRuntimeHealthResponse{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Runtimes:        []sourceRuntimeHealthRecord{},
		SourceSummaries: []sourceRuntimeHealthSummary{},
	}
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
	blindSpots := sourcecoverage.BlindSpots(health.Coverage)
	return runtimeFreshnessResponse{
		GeneratedAt:          health.GeneratedAt,
		Status:               status,
		Runtimes:             records,
		Summaries:            runtimeFreshnessSummaries(records),
		CoverageBlindSpots:   blindSpots,
		CoverageBlindSummary: sourcecoverage.Summaries(blindSpots),
	}
}

func (a *App) sourceCoverageRecords(runtimes []*cerebrov1.SourceRuntime, filter ports.SourceRuntimeFilter, generatedAt time.Time) []sourcecoverage.Record {
	if a == nil || a.sources == nil {
		return nil
	}
	contracts := sourcecoverage.ContractsFromRegistry(a.sources)
	if len(contracts) == 0 {
		return nil
	}
	observations := sourcecoverage.ObservationsFromRuntimes(runtimes, func(runtime *cerebrov1.SourceRuntime) string {
		return runtimeHealthStatus(runtime, generatedAt)
	})
	return sourcecoverage.Evaluate(contracts, observations, sourcecoverage.Options{
		TenantID: strings.TrimSpace(filter.TenantID),
		SourceID: strings.TrimSpace(filter.SourceID),
	})
}

func emitSourceCoverageGateTelemetry(ctx context.Context, report sourcecoverage.Report) {
	gate := report.Gate
	if strings.TrimSpace(gate.Status) == "" {
		gate = sourcecoverage.GateForTotals(report.Totals)
		report.Gate = gate
	}
	attrs := sourceCoverageGateTelemetryAttributes(report)
	telemetry.Event(ctx, "source_coverage.release_gate", attrs)
	telemetry.IncrementMain(ctx, "source_coverage.release_gate.count", 1)
	telemetry.IncrementMain(ctx, "source_coverage.release_gate."+gate.Status+".count", 1)
	telemetry.AnnotateMain(ctx, attrs)
}

func sourceCoverageGateTelemetryAttributes(report sourcecoverage.Report) telemetry.Attributes {
	gate := report.Gate
	if strings.TrimSpace(gate.Status) == "" {
		gate = sourcecoverage.GateForTotals(report.Totals)
	}
	return telemetry.Attrs(
		telemetry.Field{Key: "source_coverage.gate.status", Value: gate.Status},
		telemetry.Field{Key: "source_coverage.gate.blocking_reason", Value: gate.BlockingReason},
		telemetry.Field{Key: "source_coverage.dimensions.total", Value: report.Totals.Dimensions},
		telemetry.Field{Key: "source_coverage.high_value_dimensions.total", Value: report.Totals.HighValueDimensions},
		telemetry.Field{Key: "source_coverage.healthy_count", Value: report.Totals.Healthy},
		telemetry.Field{Key: "source_coverage.partial_count", Value: report.Totals.Partial},
		telemetry.Field{Key: "source_coverage.unsupported_count", Value: report.Totals.Unsupported},
		telemetry.Field{Key: "source_coverage.unconfigured_count", Value: report.Totals.Unconfigured},
		telemetry.Field{Key: "source_coverage.stale_count", Value: report.Totals.Stale},
		telemetry.Field{Key: "source_coverage.failed_count", Value: report.Totals.Failed},
		telemetry.Field{Key: "source_coverage.unknown_count", Value: report.Totals.Unknown},
		telemetry.Field{Key: "source_coverage.blind_spot_count", Value: report.Totals.BlindSpots},
	)
}

func runtimeFreshnessRecordFromHealth(record sourceRuntimeHealthRecord) runtimeFreshnessRecord {
	state := sourcehealth.Evaluate(sourceHealthRecord(record))
	return runtimeFreshnessRecord{
		runtimeFreshnessIdentity: runtimeFreshnessIdentity{
			RuntimeID: record.RuntimeID,
			SourceID:  record.SourceID,
			TenantID:  record.TenantID,
			Family:    record.Family,
		},
		runtimeFreshnessStates: runtimeFreshnessStates{
			LifecycleState:            state.LifecycleState,
			ScheduleState:             state.ScheduleState,
			FreshnessState:            state.FreshnessState,
			SourceSyncState:           state.SourceSyncState,
			GraphIngestState:          state.GraphIngestState,
			FindingEvaluationState:    state.FindingEvaluationState,
			FailureClass:              state.FailureClass,
			FailureReason:             state.FailureReason,
			BackfillEligible:          state.BackfillEligible,
			BackfillEligibilityReason: state.BackfillEligibilityReason,
		},
		runtimeFreshnessObservations: runtimeFreshnessObservations{
			LastSyncedAt:            record.LastSyncedAt,
			SyncLagSeconds:          record.SyncLagSeconds,
			CheckpointWatermark:     record.CheckpointWatermark,
			WatermarkLagSeconds:     record.WatermarkLagSeconds,
			LatestGraphRun:          record.LatestGraphRun,
			GraphLagSeconds:         record.GraphLagSeconds,
			LatestFindingEvaluation: record.LatestFindingEvaluation,
			ExpectedCadenceSeconds:  record.ExpectedCadenceSeconds,
			StaleAfterSeconds:       record.StaleAfterSeconds,
			GeneratedAt:             record.GeneratedAt,
		},
		runtimeFreshnessActions: runtimeFreshnessActions{
			NextAction:                state.NextAction,
			RecommendedWorkflow:       state.RecommendedWorkflow,
			CursorPending:             record.CursorPending,
			CheckpointCursorPresent:   record.CheckpointCursorPresent,
			ScheduleContextConfigured: record.ScheduleContextConfigured,
		},
	}
}

func sourceHealthRecord(record sourceRuntimeHealthRecord) sourcehealth.Record {
	var graphRun *sourcehealth.GraphRun
	if record.LatestGraphRun != nil {
		graphRun = &sourcehealth.GraphRun{Status: record.LatestGraphRun.Status}
	}
	var findingEvaluation *sourcehealth.FindingEvaluation
	if record.LatestFindingEvaluation != nil {
		findingEvaluation = &sourcehealth.FindingEvaluation{Status: record.LatestFindingEvaluation.Status}
	}
	return sourcehealth.Record{
		RuntimeID:                 record.RuntimeID,
		SourceID:                  record.SourceID,
		TenantID:                  record.TenantID,
		Family:                    record.Family,
		EnabledState:              record.EnabledState,
		Status:                    record.Status,
		LastFailureCategory:       record.LastFailureCategory,
		ContractProbeState:        record.ContractProbeState,
		CursorPending:             record.CursorPending,
		CheckpointCursorPresent:   record.CheckpointCursorPresent,
		ScheduleContextConfigured: record.ScheduleContextConfigured,
		SyncLagSeconds:            record.SyncLagSeconds,
		WatermarkLagSeconds:       record.WatermarkLagSeconds,
		GraphLagSeconds:           record.GraphLagSeconds,
		ExpectedCadenceSeconds:    record.ExpectedCadenceSeconds,
		StaleAfterSeconds:         record.StaleAfterSeconds,
		LatestGraphRun:            graphRun,
		LatestFindingEvaluation:   findingEvaluation,
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
	return sourcehealth.GraphIngestState(sourceHealthRecord(record))
}

func (a *App) sourceRuntimeHealthRecords(ctx context.Context, runtimes []*cerebrov1.SourceRuntime, generatedAt time.Time) ([]sourceRuntimeHealthRecord, error) {
	visibleRuntimes := make([]*cerebrov1.SourceRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			visibleRuntimes = append(visibleRuntimes, runtime)
		}
	}
	records := make([]sourceRuntimeHealthRecord, len(visibleRuntimes))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(sourceRuntimeHealthRecordConcurrency)
	for index, runtime := range visibleRuntimes {
		index, runtime := index, runtime
		group.Go(func() error {
			record, err := a.sourceRuntimeHealthRecord(groupCtx, runtime, generatedAt)
			if err != nil {
				return err
			}
			records[index] = record
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return records, nil
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
	if policy, err := resourcescope.FromConfig(runtime.GetConfig()); err == nil && !policy.Empty() {
		record.ScopePolicy = &policy
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
	var graphRun *graphstore.IngestRun
	var findingRun *cerebrov1.FindingEvaluationRun
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var err error
		graphRun, err = a.latestGraphIngestRun(groupCtx, record.RuntimeID)
		return err
	})
	group.Go(func() error {
		var err error
		findingRun, err = a.latestFindingEvaluationRun(groupCtx, record.RuntimeID)
		return err
	})
	if err := group.Wait(); err != nil {
		return record, err
	}
	if graphRun != nil {
		record.LatestGraphRun = sourceRuntimeGraphRunHealth(*graphRun)
		record.GraphLagSeconds = graphRunLagSeconds(generatedAt, *graphRun)
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
	if timestampValue(runtime.GetLastSyncedAt()).IsZero() {
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
