package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// FindingRecord is the normalized persisted finding shape.
type FindingRecord struct {
	ID              string
	Fingerprint     string
	TenantID        string
	RuntimeID       string
	RuleID          string
	Title           string
	Severity        string
	Status          string
	Summary         string
	ResourceURNs    []string
	EventIDs        []string
	Attributes      map[string]string
	FirstObservedAt time.Time
	LastObservedAt  time.Time
}

// ListFindingsRequest scopes one finding query.
type ListFindingsRequest struct {
	RuntimeID   string
	FindingID   string
	RuleID      string
	Severity    string
	Status      string
	ResourceURN string
	EventID     string
	Limit       uint32
}

// ErrFindingEvaluationRunNotFound indicates that a persisted finding evaluation run does not exist.
var ErrFindingEvaluationRunNotFound = errors.New("finding evaluation run not found")

// ListFindingEvaluationRunsRequest scopes one finding evaluation run query.
type ListFindingEvaluationRunsRequest struct {
	RuntimeID string
	RuleID    string
	Status    string
	Limit     uint32
}

// FindingStore persists normalized findings in the state store.
type FindingStore interface {
	StateStore
	UpsertFinding(context.Context, *FindingRecord) (*FindingRecord, error)
	ListFindings(context.Context, ListFindingsRequest) ([]*FindingRecord, error)
}

// FindingEvaluationRunStore persists durable finding evaluation runs in the state store.
type FindingEvaluationRunStore interface {
	StateStore
	PutFindingEvaluationRun(context.Context, *cerebrov1.FindingEvaluationRun) error
	GetFindingEvaluationRun(context.Context, string) (*cerebrov1.FindingEvaluationRun, error)
	ListFindingEvaluationRuns(context.Context, ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error)
}
