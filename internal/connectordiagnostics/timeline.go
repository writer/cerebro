package connectordiagnostics

import (
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcehealthview"
)

type Entry struct {
	ID                string `json:"id"`
	RuntimeID         string `json:"runtime_id,omitempty"`
	SourceID          string `json:"source_id"`
	TenantID          string `json:"tenant_id,omitempty"`
	Family            string `json:"family,omitempty"`
	Stage             string `json:"stage"`
	StageOrder        int    `json:"stage_order"`
	Status            string `json:"status"`
	Title             string `json:"title"`
	Description       string `json:"description,omitempty"`
	OccurredAt        string `json:"occurred_at,omitempty"`
	DurationSeconds   *int64 `json:"duration_seconds,omitempty"`
	RecordsAccepted   uint32 `json:"records_accepted,omitempty"`
	RecordsRejected   uint32 `json:"records_rejected,omitempty"`
	EntitiesProjected int64  `json:"entities_projected,omitempty"`
	LinksProjected    int64  `json:"links_projected,omitempty"`
	FindingsEvaluated uint32 `json:"findings_evaluated,omitempty"`
	FindingsOpened    uint32 `json:"findings_opened,omitempty"`
	FailureClass      string `json:"failure_class,omitempty"`
	CorrelationID     string `json:"correlation_id,omitempty"`
	NextAction        string `json:"next_action,omitempty"`
}

type Preflight struct {
	GeneratedAt string
	SourceID    string
	RuntimeID   string
	TenantID    string
	Status      string
	Summary     string
	NextAction  string
	Checks      []PreflightCheck
}

type PreflightCheck struct {
	ID         string
	Label      string
	Status     string
	Detail     string
	NextAction string
}

func FromPreflight(response Preflight) []Entry {
	timeline := make([]Entry, 0, len(response.Checks)+1)
	timeline = append(timeline, Entry{
		ID:            timelineID(response.RuntimeID, "preflight", response.GeneratedAt),
		RuntimeID:     response.RuntimeID,
		SourceID:      response.SourceID,
		TenantID:      response.TenantID,
		Stage:         "preflight",
		StageOrder:    20,
		Status:        preflightTimelineStatus(response.Status),
		Title:         "Setup preflight",
		Description:   response.Summary,
		OccurredAt:    response.GeneratedAt,
		FailureClass:  preflightFailureClass(response.Status),
		CorrelationID: response.RuntimeID,
		NextAction:    response.NextAction,
	})
	for index, check := range response.Checks {
		timeline = append(timeline, Entry{
			ID:            timelineID(response.RuntimeID, "preflight_"+check.ID, response.GeneratedAt),
			RuntimeID:     response.RuntimeID,
			SourceID:      response.SourceID,
			TenantID:      response.TenantID,
			Stage:         "preflight_check",
			StageOrder:    21 + index,
			Status:        preflightTimelineStatus(check.Status),
			Title:         check.Label,
			Description:   check.Detail,
			OccurredAt:    response.GeneratedAt,
			FailureClass:  preflightFailureClass(check.Status),
			CorrelationID: response.RuntimeID,
			NextAction:    check.NextAction,
		})
	}
	return timeline
}

func FromHealth(records []sourcehealthview.Record) []Entry {
	timeline := make([]Entry, 0, len(records)*5)
	for _, record := range records {
		readiness := connectionReadiness(record)
		timeline = append(timeline, Entry{
			ID:          timelineID(record.RuntimeID, "setup", ""),
			RuntimeID:   record.RuntimeID,
			SourceID:    record.SourceID,
			TenantID:    record.TenantID,
			Family:      record.Family,
			Stage:       "setup",
			StageOrder:  10,
			Status:      "success",
			Title:       "Connection configured",
			Description: "Runtime configuration exists for this connector.",
			NextAction:  connectionNextAction(readiness, record),
		})
		syncStatus := syncActivityStatus(record)
		timeline = append(timeline, Entry{
			ID:              timelineID(record.RuntimeID, "source_sync", recordLastActivity(record)),
			RuntimeID:       record.RuntimeID,
			SourceID:        record.SourceID,
			TenantID:        record.TenantID,
			Family:          record.Family,
			Stage:           "source_sync",
			StageOrder:      30,
			Status:          syncStatus,
			Title:           syncActivityTitle(syncStatus),
			Description:     syncActivityDescription(record),
			OccurredAt:      recordLastActivity(record),
			RecordsAccepted: record.RecentSync.RecordsAccepted,
			RecordsRejected: record.RecentSync.RecordsRejected,
			FailureClass:    failureClass(record),
			CorrelationID:   record.RuntimeID,
			NextAction:      connectionNextAction(readiness, record),
		})
		appendContractProbe(&timeline, record)
		appendGraphProjection(&timeline, record)
		appendFindingEvaluation(&timeline, record)
	}
	sort.SliceStable(timeline, func(i, j int) bool {
		if timeline[i].RuntimeID != timeline[j].RuntimeID {
			return timeline[i].RuntimeID < timeline[j].RuntimeID
		}
		if timeline[i].StageOrder != timeline[j].StageOrder {
			return timeline[i].StageOrder < timeline[j].StageOrder
		}
		return timeline[i].ID < timeline[j].ID
	})
	return timeline
}

func Limit(timeline []Entry, limit int) []Entry {
	if limit <= 0 || len(timeline) <= limit {
		return timeline
	}
	return timeline[:limit]
}

func appendContractProbe(timeline *[]Entry, record sourcehealthview.Record) {
	if strings.TrimSpace(record.ContractProbeState) == "" {
		return
	}
	probeStatus := contractProbeTimelineStatus(record.ContractProbeState)
	*timeline = append(*timeline, Entry{
		ID:            timelineID(record.RuntimeID, "contract_probe", record.LastSyncedAt),
		RuntimeID:     record.RuntimeID,
		SourceID:      record.SourceID,
		TenantID:      record.TenantID,
		Family:        record.Family,
		Stage:         "contract_probe",
		StageOrder:    35,
		Status:        probeStatus,
		Title:         contractProbeTimelineTitle(probeStatus),
		Description:   "Runtime event contract probe signal for this connection.",
		OccurredAt:    record.LastSyncedAt,
		FailureClass:  contractProbeFailureClass(probeStatus),
		CorrelationID: record.RuntimeID,
	})
}

func appendGraphProjection(timeline *[]Entry, record sourcehealthview.Record) {
	if record.LatestGraphRun == nil {
		return
	}
	graphStatus := graphActivityStatus(record.LatestGraphRun.Status)
	*timeline = append(*timeline, Entry{
		ID:                timelineID(record.RuntimeID, "graph_projection", graphActivityTime(record.LatestGraphRun)),
		RuntimeID:         record.RuntimeID,
		SourceID:          record.SourceID,
		TenantID:          record.TenantID,
		Family:            record.Family,
		Stage:             "graph_projection",
		StageOrder:        40,
		Status:            graphStatus,
		Title:             graphActivityTitle(graphStatus),
		Description:       "Graph projection activity for this connection.",
		OccurredAt:        graphActivityTime(record.LatestGraphRun),
		DurationSeconds:   record.LatestGraphRun.DurationSeconds,
		EntitiesProjected: record.LatestGraphRun.EntitiesProjected,
		LinksProjected:    record.LatestGraphRun.LinksProjected,
		FailureClass:      graphFailureClass(record.LatestGraphRun.Status),
		CorrelationID:     record.LatestGraphRun.ID,
		NextAction:        graphTimelineNextAction(graphStatus),
	})
}

func appendFindingEvaluation(timeline *[]Entry, record sourcehealthview.Record) {
	if record.LatestFindingEvaluation == nil {
		return
	}
	evaluation := record.LatestFindingEvaluation
	evaluationStatus := findingEvaluationTimelineStatus(evaluation.Status)
	*timeline = append(*timeline, Entry{
		ID:                timelineID(record.RuntimeID, "finding_evaluation", findingEvaluationTimelineTime(evaluation)),
		RuntimeID:         record.RuntimeID,
		SourceID:          record.SourceID,
		TenantID:          record.TenantID,
		Family:            record.Family,
		Stage:             "finding_evaluation",
		StageOrder:        50,
		Status:            evaluationStatus,
		Title:             findingEvaluationTimelineTitle(evaluationStatus),
		Description:       "Finding evaluation activity for this connection.",
		OccurredAt:        findingEvaluationTimelineTime(evaluation),
		DurationSeconds:   evaluation.DurationSeconds,
		FindingsEvaluated: evaluation.EventsEvaluated + evaluation.GraphRowsRead,
		FindingsOpened:    evaluation.FindingsUpserted,
		FailureClass:      findingEvaluationFailureClass(evaluationStatus),
		CorrelationID:     evaluation.ID,
		NextAction:        findingEvaluationNextAction(evaluationStatus),
	})
}

func connectionReadiness(record sourcehealthview.Record) string {
	if strings.EqualFold(record.Status, "failing") || sourceRuntimeGraphState(record) == "failed" || strings.EqualFold(record.ContractProbeState, "failure") {
		return "bad"
	}
	if strings.EqualFold(record.Status, "stale") || record.CursorPending || sourceRuntimeGraphState(record) == "behind" || sourceRuntimeGraphState(record) == "not_observed" {
		return "needs_refresh"
	}
	if strings.EqualFold(record.Status, "healthy") && sourceRuntimeGraphState(record) == "current" {
		return "healthy"
	}
	return "poor"
}

func connectionNextAction(status string, record sourcehealthview.Record) string {
	switch status {
	case "bad":
		return "fix_connection"
	case "needs_refresh":
		if sourceRuntimeGraphState(record) == "not_observed" || sourceRuntimeGraphState(record) == "behind" {
			return "run_graph_ingest"
		}
		return "run_sync"
	case "healthy":
		return "monitor"
	default:
		return "inspect_connection"
	}
}

func recordLastActivity(record sourcehealthview.Record) string {
	if observedAt, ok := recordLastActivityTime(record); ok {
		return observedAt.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

func recordLastActivityTime(record sourcehealthview.Record) (time.Time, bool) {
	var latest time.Time
	for _, value := range []string{record.LastSyncedAt, record.CheckpointWatermark, graphActivityTime(record.LatestGraphRun)} {
		parsed, ok := parseRFC3339(value)
		if !ok {
			continue
		}
		if parsed.After(latest) {
			latest = parsed
		}
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

func syncActivityStatus(record sourcehealthview.Record) string {
	switch connectionReadiness(record) {
	case "healthy":
		return "success"
	case "bad":
		return "failed"
	case "needs_refresh":
		return "needs_refresh"
	default:
		return "incomplete"
	}
}

func syncActivityTitle(status string) string {
	switch status {
	case "success":
		return "Successful sync"
	case "failed":
		return "Sync needs attention"
	case "needs_refresh":
		return "Sync refresh needed"
	default:
		return "Sync signal incomplete"
	}
}

func syncActivityDescription(record sourcehealthview.Record) string {
	switch syncActivityStatus(record) {
	case "success":
		return "Runtime sync completed with current source telemetry."
	case "failed":
		return "Runtime sync or validation is failing."
	case "needs_refresh":
		return "Runtime sync, cursor, or graph projection is behind."
	default:
		return "Runtime telemetry has not produced enough signal yet."
	}
}

func graphActivityStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if strings.Contains(normalized, "fail") || strings.Contains(normalized, "error") || strings.Contains(normalized, "cancel") {
		return "failed"
	}
	if strings.Contains(normalized, "running") || strings.Contains(normalized, "pending") {
		return "running"
	}
	if normalized == "" {
		return "not_observed"
	}
	return "success"
}

func graphActivityTitle(status string) string {
	switch status {
	case "success":
		return "Graph projection complete"
	case "failed":
		return "Graph projection failed"
	case "running":
		return "Graph projection running"
	default:
		return "Graph projection not observed"
	}
}

func graphActivityTime(run *sourcehealthview.GraphRun) string {
	if run == nil {
		return ""
	}
	if strings.TrimSpace(run.FinishedAt) != "" {
		return strings.TrimSpace(run.FinishedAt)
	}
	return strings.TrimSpace(run.StartedAt)
}

func failureClass(record sourcehealthview.Record) string {
	if value := strings.TrimSpace(record.LastFailureCategory); value != "" {
		return value
	}
	if strings.EqualFold(record.ContractProbeState, "failure") {
		return "contract_probe_failure"
	}
	if connectionReadiness(record) == "needs_refresh" {
		return "freshness"
	}
	return ""
}

func graphFailureClass(status string) string {
	if graphActivityStatus(status) == "failed" {
		return "graph_ingest_failed"
	}
	return ""
}

func sourceRuntimeGraphState(record sourcehealthview.Record) string {
	if record.LatestGraphRun == nil {
		if record.RecentSync.EntitiesProjected > 0 || record.RecentSync.LinksProjected > 0 {
			return "current"
		}
		return "not_observed"
	}
	status := graphActivityStatus(record.LatestGraphRun.Status)
	if status == "failed" || status == "running" {
		return status
	}
	if record.GraphLagSeconds != nil && *record.GraphLagSeconds > 0 {
		return "behind"
	}
	return "current"
}

func preflightTimelineStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ready", "passed", "success":
		return "success"
	case "warning":
		return "warning"
	case "blocked", "failed", "error":
		return "failed"
	default:
		return "incomplete"
	}
}

func preflightFailureClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "blocked", "failed", "error":
		return "preflight_blocked"
	default:
		return ""
	}
}

func contractProbeTimelineStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "passing", "passed", "success":
		return "success"
	case "failure", "failed":
		return "failed"
	case "not_configured":
		return "not_configured"
	default:
		return "incomplete"
	}
}

func contractProbeTimelineTitle(status string) string {
	switch status {
	case "success":
		return "Contract probe passed"
	case "failed":
		return "Contract probe failed"
	case "not_configured":
		return "Contract probe not configured"
	default:
		return "Contract probe incomplete"
	}
}

func contractProbeFailureClass(status string) string {
	if status == "failed" {
		return "contract_probe_failure"
	}
	return ""
}

func graphTimelineNextAction(status string) string {
	switch status {
	case "failed":
		return "inspect_graph_ingest"
	case "running":
		return "wait_for_graph_ingest"
	case "success":
		return "monitor"
	default:
		return "run_graph_ingest"
	}
}

func findingEvaluationTimelineStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if strings.Contains(normalized, "fail") || strings.Contains(normalized, "error") || strings.Contains(normalized, "cancel") {
		return "failed"
	}
	if strings.Contains(normalized, "running") || strings.Contains(normalized, "pending") {
		return "running"
	}
	if normalized == "" {
		return "not_observed"
	}
	return "success"
}

func findingEvaluationTimelineTitle(status string) string {
	switch status {
	case "success":
		return "Finding evaluation complete"
	case "failed":
		return "Finding evaluation failed"
	case "running":
		return "Finding evaluation running"
	default:
		return "Finding evaluation not observed"
	}
}

func findingEvaluationTimelineTime(evaluation *sourcehealthview.FindingEvaluation) string {
	if evaluation == nil {
		return ""
	}
	if strings.TrimSpace(evaluation.FinishedAt) != "" {
		return strings.TrimSpace(evaluation.FinishedAt)
	}
	return strings.TrimSpace(evaluation.StartedAt)
}

func findingEvaluationFailureClass(status string) string {
	if status == "failed" {
		return "finding_evaluation_failed"
	}
	return ""
}

func findingEvaluationNextAction(status string) string {
	switch status {
	case "failed":
		return "inspect_finding_evaluation"
	case "running":
		return "wait_for_finding_evaluation"
	case "success":
		return "monitor"
	default:
		return "run_finding_evaluation"
	}
}

func timelineID(runtimeID string, stage string, occurredAt string) string {
	parts := []string{strings.TrimSpace(runtimeID), strings.TrimSpace(stage), strings.TrimSpace(occurredAt)}
	return strings.Trim(strings.Join(parts, ":"), ":")
}

func parseRFC3339(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
