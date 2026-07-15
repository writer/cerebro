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

// FindingExternalRef captures one source-native alert/case lifecycle reference
// attached to a normalized finding.
type FindingExternalRef struct {
	System               string    `json:"system"`
	Kind                 string    `json:"kind"`
	ExternalID           string    `json:"external_id"`
	URL                  string    `json:"url"`
	ExternalStatus       string    `json:"external_status"`
	ExternalStatusReason string    `json:"external_status_reason"`
	LifecycleOwner       string    `json:"lifecycle_owner"`
	ObservedAt           time.Time `json:"observed_at"`
}

// FindingWorkflow captures mutable analyst-managed finding workflow metadata.
type FindingWorkflow struct {
	Notes           []FindingNote
	Tickets         []FindingTicket
	ExternalRefs    []FindingExternalRef
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
	RiskFactors      []FindingRiskFactor
	RiskModelVersion string
}

// FindingRiskFactor links one scoring factor to evidence used to derive it.
type FindingRiskFactor struct {
	FactorID             string    `json:"factor_id"`
	Category             string    `json:"category"`
	Weight               int       `json:"weight"`
	SeverityContribution string    `json:"severity_contribution"`
	EvidenceRefs         []string  `json:"evidence_refs"`
	ObservedAt           time.Time `json:"observed_at,omitempty"`
	SuppressionScope     string    `json:"suppression_scope,omitempty"`
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
	TenantID            string
	RuntimeID           string
	RuntimeIDs          []string
	FindingID           string
	RuleID              string
	Severity            string
	Status              string
	ResourceURN         string
	ResourceURNs        []string
	EventID             string
	PolicyID            string
	Framework           string
	FirstObservedFrom   time.Time
	FirstObservedBefore time.Time
	StatusUpdatedFrom   time.Time
	StatusUpdatedBefore time.Time
	LastObservedBefore  time.Time
	MinAgeDays          uint32
	MaxAgeDays          uint32
	SLAStatus           string
	Limit               uint32
	PriorityOrder       bool
	Order               FindingOrder
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
	TotalFindings      int
	OpenFindings       int
	CriticalFindings   int
	HighFindings       int
	OverdueFindings    int
	Unassigned         int
	MaxRiskScore       int
	RiskScoreTotal     int
	BySeverity         map[string]int
	ByStatus           map[string]int
	RiskReasonCounts   map[string]int
	ControlsFailing    int
	FailingControlKeys []string
}

// ErrFindingEvaluationRunNotFound indicates that a persisted finding evaluation run does not exist.
var ErrFindingEvaluationRunNotFound = errors.New("finding evaluation run not found")

// ErrFindingNotFound indicates that a persisted finding does not exist.
var ErrFindingNotFound = errors.New("finding not found")

// ErrFindingStatusPreconditionFailed indicates that a conditional lifecycle
// status mutation did not match the live row state.
var ErrFindingStatusPreconditionFailed = errors.New("finding status precondition failed")

// ErrFindingEvidenceNotFound indicates that persisted finding evidence does not exist.
var ErrFindingEvidenceNotFound = errors.New("finding evidence not found")

// ErrFindingCandidateNotFound indicates that a persisted finding candidate does not exist.
var ErrFindingCandidateNotFound = errors.New("finding candidate not found")

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
	HeartbeatAt  time.Time
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
	HeartbeatAt   time.Time
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
	// RetryFailedCloseoutRun atomically flips a failed closeout_run back to
	// running so retries re-acquire the singleton-running lock. Implementations
	// MUST translate the singleton lock conflict into ErrCloseoutRunInFlight.
	RetryFailedCloseoutRun(ctx context.Context, runID string, heartbeatAt time.Time) error
	FinishCloseoutRun(ctx context.Context, finish CloseoutRunFinish) error
	GetCloseoutRun(ctx context.Context, runID string) (*CloseoutRunRecord, error)
	// RefreshCloseoutRunHeartbeat updates heartbeat_at for a currently running
	// closeout_run. Long apply runs call this periodically so stale-lock recovery
	// keys off recent activity rather than the original started_at timestamp.
	RefreshCloseoutRunHeartbeat(ctx context.Context, runID string, heartbeatAt time.Time) error
	// BreakStaleRunningCloseoutRuns flips any closeout_run rows with status='running'
	// and heartbeat_at < cutoff (falling back to started_at for legacy rows) to
	// status='failed' with finished_at=now and the supplied error message. The
	// bulk primitive uses this to recover from operator crashes without manual
	// intervention (I-8: stale-lock break). Implementations MUST be idempotent
	// and return the count of rows that were updated.
	BreakStaleRunningCloseoutRuns(ctx context.Context, cutoff time.Time, errMessage string) (int, error)
	// UpdateCloseoutRunSummary persists the per-run S3 audit summary key on a
	// closeout_run row that has already been finished. When summaryErr is non-nil
	// the row is flipped to status='failed' with error_message=summaryErr.Error()
	// so the operator can correlate the run record with the missing S3 object;
	// the previously committed tombstones remain durable. Implementations MUST
	// return an error if the row does not exist.
	UpdateCloseoutRunSummary(ctx context.Context, runID, summaryKey string, summaryErr error) error
}

// FindingTombstoneEventStore persists finding_tombstone_events audit rows.
type FindingTombstoneEventStore interface {
	InsertFindingTombstoneEvent(ctx context.Context, event FindingTombstoneEvent) error
	CountFindingTombstoneEventsByRun(ctx context.Context, runID string) (int, error)
}

// FindingTombstoneWorkflowEmitter emits the workflow tombstone event for an
// already-updated and durably committed finding row. Transactional stores invoke
// this after commit so append-log consumers never observe a tombstone event for
// a SQL transaction that later rolls back.
type FindingTombstoneWorkflowEmitter func(ctx context.Context, finding *FindingRecord, priorStatus string, tombstonedAt time.Time) error

// FindingTombstoneAtomicRequest carries the full per-candidate closeout mutation
// that must commit or roll back as one unit.
type FindingTombstoneAtomicRequest struct {
	FindingID         string
	ExpectedStatus    string
	Status            string
	Reason            string
	Actor             string
	RunID             string
	AnchorURI         string
	EventIDs          []string
	UpdatedAt         time.Time
	EmitWorkflowEvent FindingTombstoneWorkflowEmitter
}

// FindingTombstoneAtomicResult describes whether a transaction actually
// tombstoned the candidate. Applied is false when the live row was already
// tombstoned or its status changed after candidate listing.
type FindingTombstoneAtomicResult struct {
	Finding       *FindingRecord
	Applied       bool
	StatusChanged bool
	PriorStatus   string
	TombstonedAt  time.Time
}

// FindingTombstoneAtomicStore performs a per-candidate closeout mutation in one
// transaction: current row re-read/lock, tombstone status update, and audit
// insert. The external workflow event is emitted only after that transaction
// commits.
type FindingTombstoneAtomicStore interface {
	TombstoneFindingAtomic(ctx context.Context, request FindingTombstoneAtomicRequest) (*FindingTombstoneAtomicResult, error)
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
	FindingID          string
	Status             string
	Reason             string
	UpdatedAt          time.Time
	EventIDs           []string
	ExpectedStatus     string
	LastObservedBefore time.Time
	Tombstone          *FindingTombstoneApply
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

// FindingExternalRefLink scopes one linked external lifecycle reference.
type FindingExternalRefLink struct {
	FindingID   string
	ExternalRef FindingExternalRef
}

// ListFindingEvaluationRunsRequest scopes one finding evaluation run query.
type ListFindingEvaluationRunsRequest struct {
	RuntimeID          string
	RuleID             string
	Status             string
	FinishedAtOrBefore time.Time
	Limit              uint32
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

// FindingCandidateRun records one candidate-rule evaluation pass. Candidate runs
// are intentionally separate from production finding evaluation runs because they
// do not upsert current-state findings.
type FindingCandidateRun struct {
	ID              string
	TenantID        string
	RuntimeID       string
	RuleID          string
	Status          string
	EventLimit      uint32
	EventsEvaluated uint32
	EventsMatched   uint32
	Candidates      uint32
	StartedAt       time.Time
	FinishedAt      time.Time
	Error           string
}

// FindingCandidateRecord stores a reviewed-but-not-yet-production finding snapshot.
type FindingCandidateRecord struct {
	ID                 string
	TenantID           string
	RuntimeID          string
	RuleID             string
	Fingerprint        string
	Status             string
	Finding            *FindingRecord
	Evidence           []*cerebrov1.FindingEvidence
	LastRunID          string
	ObservationCount   uint32
	FirstObservedAt    time.Time
	LastObservedAt     time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	PromotedFindingID  string
	DecisionID         string
	PromotedBy         string
	PromotionRationale string
	ChangeTicket       string
	PromotedAt         time.Time
	RejectedBy         string
	RejectionRationale string
	RejectedAt         time.Time
}

// ListFindingCandidatesRequest scopes one candidate-finding query.
type ListFindingCandidatesRequest struct {
	TenantID    string
	RuntimeID   string
	CandidateID string
	RuleID      string
	Status      string
	Fingerprint string
	Limit       uint32
}

// FindingCandidatePromotion marks one candidate as promoted after the production
// finding and audit decision are durable.
type FindingCandidatePromotion struct {
	CandidateID       string
	PromotedFindingID string
	DecisionID        string
	PromotedBy        string
	Rationale         string
	ChangeTicket      string
	PromotedAt        time.Time
}

// FindingCandidateRejection marks one candidate as reviewed and rejected without
// writing production finding state.
type FindingCandidateRejection struct {
	CandidateID string
	DecisionID  string
	RejectedBy  string
	Rationale   string
	RejectedAt  time.Time
}

// FindingCandidateExpiration marks stale candidate rows that were not reproduced
// by a later successful evaluation covering the same source events.
type FindingCandidateExpiration struct {
	TenantID          string
	RuntimeID         string
	RuleID            string
	RunID             string
	EvaluatedEventIDs []string
	RunStartedAt      time.Time
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
	LinkFindingExternalRef(context.Context, FindingExternalRefLink) (*FindingRecord, error)
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

// FindingCandidateStore persists non-production candidate finding outputs.
type FindingCandidateStore interface {
	StateStore
	PutFindingCandidateRun(context.Context, *FindingCandidateRun) error
	GetFindingCandidateRun(context.Context, string) (*FindingCandidateRun, error)
	ListFindingCandidateRuns(context.Context, ListFindingCandidatesRequest) ([]*FindingCandidateRun, error)
	UpsertFindingCandidate(context.Context, *FindingCandidateRecord) (*FindingCandidateRecord, error)
	GetFindingCandidate(context.Context, string) (*FindingCandidateRecord, error)
	ListFindingCandidates(context.Context, ListFindingCandidatesRequest) ([]*FindingCandidateRecord, error)
	ExpireStaleFindingCandidates(context.Context, FindingCandidateExpiration) (int, error)
	MarkFindingCandidatePromoted(context.Context, FindingCandidatePromotion) (*FindingCandidateRecord, error)
	MarkFindingCandidateRejected(context.Context, FindingCandidateRejection) (*FindingCandidateRecord, error)
}
