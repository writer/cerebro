package sourcehealthview

import (
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcehealth"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func FromRuntime(runtime *cerebrov1.SourceRuntime, generatedAt time.Time, graphRun *graphstore.IngestRun, findingRun *cerebrov1.FindingEvaluationRun) Record {
	health := sourcehealth.RecordFromRuntime(runtime, generatedAt)
	record := Record{
		RuntimeID: health.RuntimeID, SourceID: health.SourceID, TenantID: health.TenantID, Family: health.Family,
		EnabledState: health.EnabledState, Status: health.Status, RecentSync: syncFromRuntime(runtime),
		LastFailureCategory: health.LastFailureCategory, ContractProbeState: health.ContractProbeState,
		CursorPending: health.CursorPending, CheckpointCursorPresent: health.CheckpointCursorPresent,
		ExpectedCadenceSeconds: health.ExpectedCadenceSeconds, StaleAfterSeconds: health.StaleAfterSeconds,
		ScheduleContextConfigured: health.ScheduleContextConfigured, GeneratedAt: generatedAt.UTC().Format(time.RFC3339Nano),
	}
	if policy, err := resourcescope.FromConfig(runtime.GetConfig()); err == nil && !policy.Empty() {
		record.ScopePolicy = &policy
	}
	if lastSynced := timestampValue(runtime.GetLastSyncedAt()); !lastSynced.IsZero() {
		record.LastSyncedAt, record.SyncLagSeconds = lastSynced.Format(time.RFC3339Nano), health.SyncLagSeconds
	}
	if watermark := timestampValue(runtime.GetCheckpoint().GetWatermark()); !watermark.IsZero() {
		record.CheckpointWatermark, record.WatermarkLagSeconds = watermark.Format(time.RFC3339Nano), health.WatermarkLagSeconds
	}
	if graphRun != nil {
		record.LatestGraphRun, record.GraphLagSeconds = GraphRunFromStore(*graphRun), graphRunLagSeconds(generatedAt, *graphRun)
	}
	record.LatestFindingEvaluation = FindingEvaluationFromRun(findingRun)
	return record
}

func GraphRunFromStore(run graphstore.IngestRun) *GraphRun {
	return &GraphRun{
		ID: run.ID, Status: run.Status, CheckpointCursor: run.CheckpointCursor, CheckpointComplete: run.CheckpointCompleteValue(),
		StartedAt: run.StartedAt, FinishedAt: run.FinishedAt, Error: run.Error,
		PagesRead: run.PagesRead, EventsRead: run.EventsRead, EntitiesProjected: run.EntitiesProjected, LinksProjected: run.LinksProjected,
		GraphNodesBefore: run.GraphNodesBefore, GraphLinksBefore: run.GraphLinksBefore, GraphNodesAfter: run.GraphNodesAfter, GraphLinksAfter: run.GraphLinksAfter,
		GraphNodeDelta: run.GraphNodesAfter - run.GraphNodesBefore, GraphLinkDelta: run.GraphLinksAfter - run.GraphLinksBefore,
		DurationSeconds: durationSeconds(run.StartedAt, run.FinishedAt),
	}
}

func FindingEvaluationFromRun(run *cerebrov1.FindingEvaluationRun) *FindingEvaluation {
	if run == nil {
		return nil
	}
	var graphRowsRead uint32
	if run.GraphRowsRead != nil {
		graphRowsRead = run.GetGraphRowsRead()
	}
	return &FindingEvaluation{
		ID: run.GetId(), RuntimeID: run.GetRuntimeId(), RuleID: run.GetRuleId(), Status: run.GetStatus(),
		StartedAt: timestampString(run.GetStartedAt()), FinishedAt: timestampString(run.GetFinishedAt()), Error: run.GetError(),
		EventsEvaluated: run.GetEventsEvaluated(), EventsProcessed: run.GetEventsProcessed(), EventsMatched: run.GetEventsMatched(),
		FindingsUpserted: run.GetFindingsUpserted(), FindingsEmitted: run.GetFindingsEmitted(), GraphRule: run.GraphRule,
		GraphRowsRead: graphRowsRead, DurationSeconds: timestampDurationSeconds(run.GetStartedAt(), run.GetFinishedAt()),
	}
}

func syncFromRuntime(runtime *cerebrov1.SourceRuntime) Sync {
	return Sync{
		RecordsScanned: configUint32(runtime, "__cerebro_runtime_records_scanned"), RecordsAccepted: configUint32(runtime, "__cerebro_runtime_records_accepted"),
		RecordsRejected: configUint32(runtime, "__cerebro_runtime_records_rejected"), EntitiesProjected: configUint32(runtime, "__cerebro_runtime_entities_projected"),
		LinksProjected: configUint32(runtime, "__cerebro_runtime_links_projected"),
	}
}

func configUint32(runtime *cerebrov1.SourceRuntime, key string) uint32 {
	if runtime == nil {
		return 0
	}
	value, err := strconv.ParseUint(strings.TrimSpace(runtime.GetConfig()[key]), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(value)
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil || (value.GetSeconds() == 0 && value.GetNanos() == 0) || value.CheckValid() != nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func timestampString(value *timestamppb.Timestamp) string {
	if timestamp := timestampValue(value); !timestamp.IsZero() {
		return timestamp.Format(time.RFC3339Nano)
	}
	return ""
}

func graphRunLagSeconds(now time.Time, run graphstore.IngestRun) *int64 {
	if finished, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(run.FinishedAt)); err == nil {
		return secondsSince(now, finished)
	}
	if started, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(run.StartedAt)); err == nil {
		return secondsSince(now, started)
	}
	return nil
}

func durationSeconds(startedAt, finishedAt string) *int64 {
	started, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(startedAt))
	if err != nil {
		return nil
	}
	finished, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(finishedAt))
	if err != nil {
		return nil
	}
	return nonnegativeSeconds(finished.Sub(started))
}

func timestampDurationSeconds(startedAt, finishedAt *timestamppb.Timestamp) *int64 {
	started, finished := timestampValue(startedAt), timestampValue(finishedAt)
	if started.IsZero() || finished.IsZero() {
		return nil
	}
	return nonnegativeSeconds(finished.Sub(started))
}

func secondsSince(now, then time.Time) *int64 { return nonnegativeSeconds(now.UTC().Sub(then.UTC())) }

func nonnegativeSeconds(duration time.Duration) *int64 {
	seconds := int64(duration.Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}
