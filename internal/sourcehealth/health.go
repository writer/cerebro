package sourcehealth

import (
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	RuntimeLastFailureCategoryConfigKey = "__cerebro_runtime_last_failure_category"
	RuntimeContractProbeStateConfigKey  = "__cerebro_runtime_contract_probe_state"
	ExpectedCadenceSecondsConfigKey     = "expected_cadence_seconds"
	StaleAfterSecondsConfigKey          = "stale_after_seconds"
)

type GraphRun struct {
	Status             string
	CheckpointCursor   string
	CheckpointComplete *bool
}

type FindingEvaluation struct {
	Status string
}

type Record struct {
	RuntimeID                 string
	SourceID                  string
	TenantID                  string
	Family                    string
	EnabledState              string
	Status                    string
	LastFailureCategory       string
	ContractProbeState        string
	CursorPending             bool
	CheckpointCursorPresent   bool
	ScheduleContextConfigured bool
	SyncLagSeconds            *int64
	WatermarkLagSeconds       *int64
	GraphLagSeconds           *int64
	ExpectedCadenceSeconds    *int64
	StaleAfterSeconds         *int64
	LatestGraphRun            *GraphRun
	LatestFindingEvaluation   *FindingEvaluation
}

type State struct {
	LifecycleState            string
	ScheduleState             string
	FreshnessState            string
	SourceSyncState           string
	GraphIngestState          string
	FindingEvaluationState    string
	FailureClass              string
	FailureReason             string
	BackfillEligible          bool
	BackfillEligibilityReason string
	NextAction                string
	RecommendedWorkflow       string
}

func RecordFromRuntime(runtime *cerebrov1.SourceRuntime, now time.Time) Record {
	if runtime == nil {
		return Record{EnabledState: "unknown", Status: "unknown", ContractProbeState: "unknown"}
	}
	record := Record{
		RuntimeID:                 strings.TrimSpace(runtime.GetId()),
		SourceID:                  strings.TrimSpace(runtime.GetSourceId()),
		TenantID:                  strings.TrimSpace(runtime.GetTenantId()),
		Family:                    strings.TrimSpace(runtime.GetConfig()["family"]),
		EnabledState:              RuntimeEnabledState(runtime),
		Status:                    RuntimeStatus(runtime, now),
		LastFailureCategory:       strings.TrimSpace(runtime.GetConfig()[RuntimeLastFailureCategoryConfigKey]),
		ContractProbeState:        RuntimeContractProbeState(runtime),
		CursorPending:             strings.TrimSpace(runtime.GetNextCursor().GetOpaque()) != "",
		CheckpointCursorPresent:   strings.TrimSpace(runtime.GetCheckpoint().GetCursorOpaque()) != "",
		ScheduleContextConfigured: false,
	}
	if lastSynced := timestampValue(runtime.GetLastSyncedAt()); !lastSynced.IsZero() {
		record.SyncLagSeconds = secondsSince(now, lastSynced.UTC())
	}
	if watermark := timestampValue(runtime.GetCheckpoint().GetWatermark()); !watermark.IsZero() {
		record.WatermarkLagSeconds = secondsSince(now, watermark.UTC())
	}
	if expectedCadence := RuntimeConfigInt64(runtime, ExpectedCadenceSecondsConfigKey); expectedCadence > 0 {
		record.ExpectedCadenceSeconds = &expectedCadence
		record.ScheduleContextConfigured = true
	}
	if staleAfter := RuntimeConfigInt64(runtime, StaleAfterSecondsConfigKey); staleAfter > 0 {
		record.StaleAfterSeconds = &staleAfter
		record.ScheduleContextConfigured = true
	}
	return record
}

func RuntimeConfigInt64(runtime *cerebrov1.SourceRuntime, key string) int64 {
	if runtime == nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(runtime.GetConfig()[key]), 10, 64)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func RuntimeEnabledState(runtime *cerebrov1.SourceRuntime) string {
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

func RuntimeStatus(runtime *cerebrov1.SourceRuntime, now time.Time) string {
	if runtime == nil {
		return "unknown"
	}
	if strings.TrimSpace(runtime.GetConfig()[RuntimeLastFailureCategoryConfigKey]) != "" {
		return "failing"
	}
	lastSynced := timestampValue(runtime.GetLastSyncedAt())
	if lastSynced.IsZero() {
		return "unknown"
	}
	if staleAfter := RuntimeConfigInt64(runtime, StaleAfterSecondsConfigKey); staleAfter > 0 && now.UTC().Sub(lastSynced.UTC()) > time.Duration(staleAfter)*time.Second {
		return "stale"
	}
	return "healthy"
}

func RuntimeContractProbeState(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return "unknown"
	}
	if state := strings.TrimSpace(runtime.GetConfig()[RuntimeContractProbeStateConfigKey]); state != "" {
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

func Evaluate(record Record) State {
	lifecycleState := "active"
	if strings.ToLower(strings.TrimSpace(record.EnabledState)) == "disabled" {
		lifecycleState = "disabled"
	}
	scheduleState := "unknown"
	if record.ScheduleContextConfigured {
		scheduleState = "configured"
	}
	sourceSyncState := SourceSyncState(record)
	graphIngestState := GraphIngestState(record)
	findingEvaluationState := FindingEvaluationState(record)
	freshnessState, failureClass, failureReason, nextAction := FreshnessState(record, lifecycleState, sourceSyncState, graphIngestState)
	backfillEligible, backfillReason := BackfillEligibility(lifecycleState, sourceSyncState, graphIngestState)
	workflow := ""
	if backfillEligible {
		workflow = "source-runtime-backfill"
	}
	return State{
		LifecycleState:            lifecycleState,
		ScheduleState:             scheduleState,
		FreshnessState:            freshnessState,
		SourceSyncState:           sourceSyncState,
		GraphIngestState:          graphIngestState,
		FindingEvaluationState:    findingEvaluationState,
		FailureClass:              failureClass,
		FailureReason:             failureReason,
		BackfillEligible:          backfillEligible,
		BackfillEligibilityReason: backfillReason,
		NextAction:                nextAction,
		RecommendedWorkflow:       workflow,
	}
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	if value.GetSeconds() == 0 && value.GetNanos() == 0 {
		return time.Time{}
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}
	}
	timestamp := value.AsTime()
	if timestamp.IsZero() {
		return time.Time{}
	}
	return timestamp.UTC()
}

func secondsSince(now time.Time, then time.Time) *int64 {
	seconds := int64(now.UTC().Sub(then.UTC()).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}

func SourceSyncState(record Record) string {
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

func FindingEvaluationState(record Record) string {
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

func FreshnessState(record Record, lifecycleState string, sourceSyncState string, graphIngestState string) (string, string, string, string) {
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
	if sourceSyncState == "current" && (graphIngestState == "current" || graphIngestState == "running") {
		return "healthy", "", "", "monitor"
	}
	return "unknown", "insufficient_signal", "source or graph freshness signal is unavailable", "inspect_runtime"
}

func BackfillEligibility(lifecycleState string, sourceSyncState string, graphIngestState string) (bool, string) {
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

func GraphIngestState(record Record) string {
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
	if strings.TrimSpace(record.LatestGraphRun.CheckpointCursor) != "" || (record.LatestGraphRun.CheckpointComplete != nil && !*record.LatestGraphRun.CheckpointComplete) {
		return "behind"
	}
	if record.GraphLagSeconds != nil && record.StaleAfterSeconds != nil && *record.GraphLagSeconds > *record.StaleAfterSeconds {
		return "behind"
	}
	return "current"
}

func ContractProbeStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "passing", "success":
		return "success"
	case "failure", "failed", "failing":
		return "failure"
	case "stale":
		return "stale"
	default:
		return "unknown"
	}
}

func LinkStatusRollup(resourceLinkStatus string, caseLinkStatus string) string {
	resourceMissing := strings.EqualFold(strings.TrimSpace(resourceLinkStatus), "missing")
	caseMissing := strings.EqualFold(strings.TrimSpace(caseLinkStatus), "missing")
	switch {
	case resourceMissing && caseMissing:
		return "orphan"
	case resourceMissing:
		return "missing_resource"
	case caseMissing:
		return "missing_case"
	default:
		return "linked"
	}
}

func ValidationFieldClass(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "missing_required_attribute":
		return "attribute"
	case "missing_required_payload_field":
		return "payload_field"
	case "missing_canonical_field":
		return "canonical_field"
	default:
		return "unknown"
	}
}
