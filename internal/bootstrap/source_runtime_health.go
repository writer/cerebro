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
	"github.com/writer/cerebro/internal/nhicoverage"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/sourcehealthview"
	"github.com/writer/cerebro/internal/sourcehttp/coverageview"
	"github.com/writer/cerebro/internal/sourcehttp/responseview"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
	"golang.org/x/sync/errgroup"
)

type sourceRuntimeHealthResponse struct {
	GeneratedAt     string                       `json:"generated_at"`
	Runtimes        []sourceRuntimeHealthRecord  `json:"runtimes"`
	SourceSummaries []sourceRuntimeHealthSummary `json:"source_summaries"`
	Coverage        []sourcecoverage.Record      `json:"coverage,omitempty"`
	CoverageSummary []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
	view            responseview.View
	coverageRecords []sourcecoverage.Record
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
	coverage := health.coverageRecords
	if coverage == nil {
		coverage = health.Coverage
	}
	report := sourcecoverage.BuildScopedReport(coverage, r.URL.Query().Get("tenant_id"), r.URL.Query().Get("source_id"), health.GeneratedAt)
	emitSourceCoverageGateTelemetry(r.Context(), report)
	response := nhicoverage.WithSourceCoverage(report)
	view, err := coverageview.FromRequest(r)
	if err != nil {
		writeSourceRuntimeError(w, errors.Join(sourceruntime.ErrInvalidRequest, err))
		return
	}
	switch view {
	case coverageview.Expanded:
		writeJSON(w, http.StatusOK, response)
	case coverageview.Summary:
		writeJSON(w, http.StatusOK, coverageview.Compact(response))
	case coverageview.Page:
		page, err := coverageview.Paginate(r, response, report.Records)
		if err != nil {
			writeSourceRuntimeError(w, errors.Join(sourceruntime.ErrInvalidRequest, err))
			return
		}
		writeJSON(w, http.StatusOK, page)
	}
}
func (a *App) listSourceRuntimeHealth(r *http.Request) (sourceRuntimeHealthResponse, error) {
	view, err := responseview.FromRequest(r)
	if err != nil {
		return sourceRuntimeHealthResponse{}, errors.Join(sourceruntime.ErrInvalidRequest, err)
	}
	coverageScope, err := responseview.CoverageScopeFromRequest(r, view)
	if err != nil {
		return sourceRuntimeHealthResponse{}, errors.Join(sourceruntime.ErrInvalidRequest, err)
	}
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
	coverage := a.sourceCoverageRecordsScoped(visibleRuntimes, filter, generatedAt, coverageScope)
	serializedCoverage := coverage
	if view == responseview.Summary {
		serializedCoverage = nil
	}
	return sourceRuntimeHealthResponse{
		GeneratedAt:     generatedAt.Format(time.RFC3339Nano),
		Runtimes:        records,
		SourceSummaries: sourceRuntimeHealthSummaries(records),
		Coverage:        serializedCoverage,
		CoverageSummary: sourcecoverage.Summaries(coverage),
		view:            view,
		coverageRecords: coverage,
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
	coverage := health.coverageRecords
	if coverage == nil {
		coverage = health.Coverage
	}
	blindSpots := sourcecoverage.BlindSpots(coverage)
	serializedBlindSpots := blindSpots
	if health.view == responseview.Summary {
		serializedBlindSpots = nil
	}
	return runtimeFreshnessResponse{
		GeneratedAt:          health.GeneratedAt,
		Status:               status,
		Runtimes:             records,
		Summaries:            runtimeFreshnessSummaries(records),
		CoverageBlindSpots:   serializedBlindSpots,
		CoverageBlindSummary: sourcecoverage.Summaries(blindSpots),
	}
}

func (a *App) sourceCoverageRecords(runtimes []*cerebrov1.SourceRuntime, filter ports.SourceRuntimeFilter, generatedAt time.Time) []sourcecoverage.Record {
	return a.sourceCoverageRecordsScoped(runtimes, filter, generatedAt, responseview.CoverageCatalog)
}

func (a *App) sourceCoverageRecordsScoped(runtimes []*cerebrov1.SourceRuntime, filter ports.SourceRuntimeFilter, generatedAt time.Time, scope responseview.CoverageScope) []sourcecoverage.Record {
	if a == nil || a.sources == nil {
		return nil
	}
	contracts := sourcecoverage.ContractsFromRegistry(a.sources)
	if scope == responseview.CoverageConfigured {
		configuredSources := make(map[string]struct{}, len(runtimes))
		for _, runtime := range runtimes {
			if runtime == nil {
				continue
			}
			if sourceID := strings.TrimSpace(runtime.GetSourceId()); sourceID != "" {
				configuredSources[sourceID] = struct{}{}
			}
		}
		configuredContracts := contracts[:0]
		for _, contract := range contracts {
			if _, ok := configuredSources[strings.TrimSpace(contract.SourceID)]; ok {
				configuredContracts = append(configuredContracts, contract)
			}
		}
		contracts = configuredContracts
	}
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
		graphRun = &sourcehealth.GraphRun{
			Status:             record.LatestGraphRun.Status,
			CheckpointCursor:   record.LatestGraphRun.CheckpointCursor,
			CheckpointComplete: record.LatestGraphRun.CheckpointComplete,
		}
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
	runtimeIDs := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			visibleRuntimes = append(visibleRuntimes, runtime)
			runtimeIDs = append(runtimeIDs, strings.TrimSpace(runtime.GetId()))
		}
	}
	var graphRuns map[string]*graphstore.IngestRun
	var findingRuns map[string]*cerebrov1.FindingEvaluationRun
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		runStore, ok := a.deps.GraphStore.(graphingest.RunStore)
		if !ok || isNilInterface(runStore) {
			graphRuns = map[string]*graphstore.IngestRun{}
			return nil
		}
		var loadErr error
		graphRuns, loadErr = sourcehealth.LatestGraphIngestRuns(groupCtx, runStore, runtimeIDs)
		return loadErr
	})
	group.Go(func() error {
		runStore := findingEvaluationRunStore(a.deps.StateStore)
		if runStore == nil {
			findingRuns = map[string]*cerebrov1.FindingEvaluationRun{}
			return nil
		}
		var loadErr error
		findingRuns, loadErr = sourcehealth.LatestFindingEvaluationRuns(groupCtx, runStore, runtimeIDs)
		if errors.Is(loadErr, findings.ErrRuntimeUnavailable) {
			findingRuns = map[string]*cerebrov1.FindingEvaluationRun{}
			return nil
		}
		return loadErr
	})
	if err := group.Wait(); err != nil {
		return nil, err
	}
	records := make([]sourceRuntimeHealthRecord, len(visibleRuntimes))
	for index, runtime := range visibleRuntimes {
		runtimeID := strings.TrimSpace(runtime.GetId())
		records[index] = sourcehealthview.FromRuntime(runtime, generatedAt, graphRuns[runtimeID], findingRuns[runtimeID])
	}
	return records, nil
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
