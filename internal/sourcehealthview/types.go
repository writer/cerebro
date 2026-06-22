package sourcehealthview

import "github.com/writer/cerebro/internal/resourcescope"

type Record struct {
	RuntimeID                 string                `json:"runtime_id"`
	SourceID                  string                `json:"source_id"`
	TenantID                  string                `json:"tenant_id"`
	Family                    string                `json:"family,omitempty"`
	ScopePolicy               *resourcescope.Policy `json:"scope_policy,omitempty"`
	EnabledState              string                `json:"enabled_state"`
	Status                    string                `json:"status"`
	LastSyncedAt              string                `json:"last_synced_at,omitempty"`
	SyncLagSeconds            *int64                `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark       string                `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds       *int64                `json:"watermark_lag_seconds,omitempty"`
	RecentSync                Sync                  `json:"recent_sync"`
	LastFailureCategory       string                `json:"last_failure_category,omitempty"`
	ContractProbeState        string                `json:"contract_probe_state"`
	CursorPending             bool                  `json:"cursor_pending"`
	CheckpointCursorPresent   bool                  `json:"checkpoint_cursor_present"`
	LatestGraphRun            *GraphRun             `json:"latest_graph_run,omitempty"`
	GraphLagSeconds           *int64                `json:"graph_lag_seconds,omitempty"`
	LatestFindingEvaluation   *FindingEvaluation    `json:"latest_finding_evaluation,omitempty"`
	ExpectedCadenceSeconds    *int64                `json:"expected_cadence_seconds,omitempty"`
	StaleAfterSeconds         *int64                `json:"stale_after_seconds,omitempty"`
	ScheduleContextConfigured bool                  `json:"schedule_context_configured"`
	GeneratedAt               string                `json:"generated_at"`
}

type Sync struct {
	RecordsScanned    uint32 `json:"records_scanned"`
	RecordsAccepted   uint32 `json:"records_accepted"`
	RecordsRejected   uint32 `json:"records_rejected"`
	EntitiesProjected uint32 `json:"entities_projected"`
	LinksProjected    uint32 `json:"links_projected"`
}

type GraphRun struct {
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

type FindingEvaluation struct {
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
