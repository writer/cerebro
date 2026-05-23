package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// FindingControlRef maps one finding to one compliance framework control.
type FindingControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

// FindingNote captures one analyst note attached to one finding.
type FindingNote struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// FindingTicket captures one external ticket reference attached to one finding.
type FindingTicket struct {
	URL        string    `json:"url"`
	Name       string    `json:"name"`
	ExternalID string    `json:"external_id"`
	LinkedAt   time.Time `json:"linked_at"`
}

// FindingWorkflow captures mutable analyst-managed finding workflow metadata.
type FindingWorkflow struct {
	Notes           []FindingNote
	Tickets         []FindingTicket
	Assignee        string
	DueAt           time.Time
	StatusReason    string
	StatusUpdatedAt time.Time
}

// FindingRisk carries normalized likelihood × impact scoring metadata.
type FindingRisk struct {
	RiskScore        int
	LikelihoodScore  int
	ImpactScore      int
	ConfidenceScore  int
	LikelihoodLevel  string
	ImpactLevel      string
	RiskReasons      []string
	RiskModelVersion string
}

// FindingTombstone captures the durable tombstone state for one finding row.
type FindingTombstone struct {
	Tombstoned          bool
	TombstonedAt        time.Time
	TombstonedBy        string
	TombstonedReason    string
	TombstonedRunID     string
	PriorStatus         string
	TombstoneGeneration int
}

// FindingRecord is the normalized persisted finding shape.
type FindingRecord struct {
	ID                string
	Fingerprint       string
	TenantID          string
	RuntimeID         string
	RuleID            string
	Title             string
	Severity          string
	Status            string
	Summary           string
	ResourceURNs      []string
	EventIDs          []string
	ObservedPolicyIDs []string
	PolicyID          string
	PolicyName        string
	CheckID           string
	CheckName         string
	ControlRefs       []FindingControlRef
	GraphEvidenceRows []*cerebrov1.GraphEvidenceRow
	FindingRisk
	FindingWorkflow
	FindingTombstone
	Attributes      map[string]string
	FirstObservedAt time.Time
	LastObservedAt  time.Time
}

// ListFindingsRequest scopes one finding query.
type ListFindingsRequest struct {
	TenantID      string
	RuntimeID     string
	RuntimeIDs    []string
	FindingID     string
	RuleID        string
	Severity      string
	Status        string
	ResourceURN   string
	EventID       string
	PolicyID      string
	Limit         uint32
	PriorityOrder bool
	Order         FindingOrder
}

// FindingOrder controls persisted finding list sort order.
type FindingOrder string

const (
	FindingOrderLastObserved FindingOrder = "last_observed"
	FindingOrderPriority     FindingOrder = "priority"
	FindingOrderRiskScore    FindingOrder = "risk_score"
)

// FindingSummary captures aggregate counts for one finding query without applying
// pagination limits intended for UI rows.
type FindingSummary struct {
	OpenFindings       int
	CriticalFindings   int
	HighFindings       int
	OverdueFindings    int
	Unassigned         int
	ControlsFailing    int
	FailingControlKeys []string
}

// ErrFindingEvaluationRunNotFound indicates that a persisted finding evaluation run does not exist.
var ErrFindingEvaluationRunNotFound = errors.New("finding evaluation run not found")

// ErrFindingNotFound indicates that a persisted finding does not exist.
var ErrFindingNotFound = errors.New("finding not found")

// ErrFindingEvidenceNotFound indicates that persisted finding evidence does not exist.
var ErrFindingEvidenceNotFound = errors.New("finding evidence not found")

// ErrCloseoutRunInFlight indicates that another closeout run is currently running.
var ErrCloseoutRunInFlight = errors.New("another closeout run is in flight")

// ErrCloseoutRunAlreadyExists indicates that a closeout_run row with the same run_id exists.
var ErrCloseoutRunAlreadyExists = errors.New("closeout run already exists")

// CloseoutRunInsert scopes one closeout_run insertion (start of a run).
type CloseoutRunInsert struct {
	RunID        string
	Actor        string
	ChangeTicket string
	SelectorJSON []byte
	DryRun       bool
	StartedAt    time.Time
}

// CloseoutRunFinish scopes one closeout_run completion update.
type CloseoutRunFinish struct {
	RunID         string
	Status        string
	ErrorMessage  string
	ProposedCount int
	AppliedCount  int
	FinishedAt    time.Time
	S3SummaryKey  string
}

// CloseoutRunRecord reflects one persisted closeout_run row.
type CloseoutRunRecord struct {
	RunID         string
	Actor         string
	ChangeTicket  string
	SelectorJSON  []byte
	Status        string
	StartedAt     time.Time
	FinishedAt    time.Time
	DryRun        bool
	ProposedCount int
	AppliedCount  int
	ErrorMessage  string
	S3SummaryKey  string
}

// FindingTombstoneEvent captures one finding_tombstone_events audit row.
type FindingTombstoneEvent struct {
	FindingID    string
	TenantID     string
	RuleID       string
	AnchorURI    string
	PriorStatus  string
	Reason       string
	Actor        string
	RunID        string
	TombstonedAt time.Time
}

// CloseoutRunStore persists closeout_run lifecycle rows. The singleton-running
// partial unique index in Postgres enforces fail-fast behavior on concurrent runs;
// implementations MUST translate that database conflict into ErrCloseoutRunInFlight.
type CloseoutRunStore interface {
	InsertCloseoutRun(ctx context.Context, run CloseoutRunInsert) error
	FinishCloseoutRun(ctx context.Context, finish CloseoutRunFinish) error
	GetCloseoutRun(ctx context.Context, runID string) (*CloseoutRunRecord, error)
}

// FindingTombstoneEventStore persists finding_tombstone_events audit rows.
type FindingTombstoneEventStore interface {
	InsertFindingTombstoneEvent(ctx context.Context, event FindingTombstoneEvent) error
	CountFindingTombstoneEventsByRun(ctx context.Context, runID string) (int, error)
}

// FindingTombstoneApply carries the tombstone-column writes performed alongside a
// finding status update. When present, the underlying status update path writes the
// findings.tombstoned columns atomically with the status flip so the tombstone is
// recorded through the same per-row write path that preserves manual state.
type FindingTombstoneApply struct {
	By           string
	Reason       string
	RunID        string
	PriorStatus  string
	TombstonedAt time.Time
}

// FindingStatusUpdate scopes one persisted finding lifecycle mutation.
type FindingStatusUpdate struct {
	FindingID string
	Status    string
	Reason    string
	UpdatedAt time.Time
	Tombstone *FindingTombstoneApply
}

// FindingAssigneeUpdate scopes one persisted finding assignee mutation.
type FindingAssigneeUpdate struct {
	FindingID string
	Assignee  string
}

// FindingDueDateUpdate scopes one persisted finding due date mutation.
type FindingDueDateUpdate struct {
	FindingID string
	DueAt     time.Time
}

// FindingRiskUpdate scopes a risk-only finding metadata mutation.
type FindingRiskUpdate struct {
	FindingID string
	FindingRisk
	Attributes map[string]string
}

// FindingNoteCreate scopes one appended finding note.
type FindingNoteCreate struct {
	FindingID string
	Note      FindingNote
}

// FindingTicketLink scopes one linked finding ticket reference.
type FindingTicketLink struct {
	FindingID string
	Ticket    FindingTicket
}

// ListFindingEvaluationRunsRequest scopes one finding evaluation run query.
type ListFindingEvaluationRunsRequest struct {
	RuntimeID string
	RuleID    string
	Status    string
	Limit     uint32
}

// ListFindingEvidenceRequest scopes one finding evidence query.
type ListFindingEvidenceRequest struct {
	RuntimeID    string
	RuntimeIDs   []string
	FindingID    string
	FindingIDs   []string
	RunID        string
	RuleID       string
	ClaimID      string
	EventID      string
	GraphRootURN string
	GraphPathURN string
	Limit        uint32
	CreatedOrder bool
}

// FindingStore persists normalized findings in the state store.
type FindingStore interface {
	StateStore
	UpsertFinding(context.Context, *FindingRecord) (*FindingRecord, error)
	GetFinding(context.Context, string) (*FindingRecord, error)
	ListFindings(context.Context, ListFindingsRequest) ([]*FindingRecord, error)
	UpdateFindingStatus(context.Context, FindingStatusUpdate) (*FindingRecord, error)
	UpdateFindingAssignee(context.Context, FindingAssigneeUpdate) (*FindingRecord, error)
	UpdateFindingDueDate(context.Context, FindingDueDateUpdate) (*FindingRecord, error)
	AddFindingNote(context.Context, FindingNoteCreate) (*FindingRecord, error)
	LinkFindingTicket(context.Context, FindingTicketLink) (*FindingRecord, error)
}

// FindingEvaluationRunStore persists durable finding evaluation runs in the state store.
type FindingEvaluationRunStore interface {
	StateStore
	PutFindingEvaluationRun(context.Context, *cerebrov1.FindingEvaluationRun) error
	GetFindingEvaluationRun(context.Context, string) (*cerebrov1.FindingEvaluationRun, error)
	ListFindingEvaluationRuns(context.Context, ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error)
}

// FindingEvidenceStore persists durable links between findings, runs, and their supporting evidence references.
type FindingEvidenceStore interface {
	StateStore
	PutFindingEvidence(context.Context, *cerebrov1.FindingEvidence) error
	GetFindingEvidence(context.Context, string) (*cerebrov1.FindingEvidence, error)
	ListFindingEvidence(context.Context, ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error)
}
