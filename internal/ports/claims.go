package ports

import (
	"context"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ClaimRecord is the normalized persisted claim shape.
type ClaimRecord struct {
	ID            string
	RuntimeID     string
	TenantID      string
	SubjectURN    string
	SubjectRef    *cerebrov1.EntityRef
	Predicate     string
	ObjectURN     string
	ObjectRef     *cerebrov1.EntityRef
	ObjectValue   string
	ClaimType     string
	Status        string
	SourceEventID string
	ObservedAt    time.Time
	ValidFrom     time.Time
	ValidTo       time.Time
	Attributes    map[string]string
}

// ListClaimsRequest scopes one claim query.
type ListClaimsRequest struct {
	RuntimeID     string
	TenantID      string
	ClaimID       string
	SubjectURN    string
	Predicate     string
	ObjectURN     string
	ObjectValue   string
	ClaimType     string
	Status        string
	SourceEventID string
	Limit         uint32
}

// ClaimStore persists normalized claims in the state store.
type ClaimStore interface {
	StateStore
	UpsertClaim(context.Context, *ClaimRecord) (*ClaimRecord, error)
	ListClaims(context.Context, ListClaimsRequest) ([]*ClaimRecord, error)
}
