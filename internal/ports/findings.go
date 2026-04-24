package ports

import (
	"context"
	"time"
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

// FindingStore persists normalized findings in the state store.
type FindingStore interface {
	StateStore
	UpsertFinding(context.Context, *FindingRecord) (*FindingRecord, error)
	ListFindings(context.Context, ListFindingsRequest) ([]*FindingRecord, error)
}
