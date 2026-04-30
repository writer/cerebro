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
	FindingWorkflow
	Attributes      map[string]string
	FirstObservedAt time.Time
	LastObservedAt  time.Time
}

// ListFindingsRequest scopes one finding query.
type ListFindingsRequest struct {
	TenantID    string
	RuntimeID   string
	FindingID   string
	RuleID      string
	Severity    string
	Status      string
	ResourceURN string
	EventID     string
	PolicyID    string
	Limit       uint32
}

// ErrFindingEvaluationRunNotFound indicates that a persisted finding evaluation run does not exist.
var ErrFindingEvaluationRunNotFound = errors.New("finding evaluation run not found")

// ErrFindingNotFound indicates that a persisted finding does not exist.
var ErrFindingNotFound = errors.New("finding not found")

// ErrFindingEvidenceNotFound indicates that persisted finding evidence does not exist.
var ErrFindingEvidenceNotFound = errors.New("finding evidence not found")

// FindingStatusUpdate scopes one persisted finding lifecycle mutation.
type FindingStatusUpdate struct {
	FindingID string
	Status    string
	Reason    string
	UpdatedAt time.Time
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
	FindingID    string
	RunID        string
	RuleID       string
	ClaimID      string
	EventID      string
	GraphRootURN string
	Limit        uint32
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
