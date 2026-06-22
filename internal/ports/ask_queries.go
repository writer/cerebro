package ports

import (
	"context"
	"errors"
	"time"
)

// ErrAskQueryNotFound indicates that a persisted saved ask query does not exist.
var ErrAskQueryNotFound = errors.New("ask query not found")

// AskQuery is a saved natural-language graph question a user can re-run from the
// ask console. Queries are scoped to a single tenant.
type AskQuery struct {
	ID        string
	TenantID  string
	Name      string
	Question  string
	ScopeURN  string
	Model     string
	Pinned    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AskQueryFilter scopes a saved-ask-query listing.
type AskQueryFilter struct {
	TenantID string
	Limit    uint32
}

// AskQueryStore persists saved ask queries. State stores implement it as an
// optional capability discovered via type assertion.
type AskQueryStore interface {
	PutAskQuery(context.Context, *AskQuery) error
	GetAskQuery(context.Context, string) (*AskQuery, error)
	ListAskQueries(context.Context, AskQueryFilter) ([]*AskQuery, error)
	DeleteAskQuery(context.Context, string) error
}
