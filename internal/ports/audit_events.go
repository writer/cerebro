package ports

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrAuditEventConflict indicates that an event identity was reused with
	// different normalized content.
	ErrAuditEventConflict = errors.New("audit event conflict")
	// ErrAuditEventInvalid indicates that an event or query is malformed.
	ErrAuditEventInvalid = errors.New("invalid audit event")
)

const (
	AuditEventOutcomeSuccess = "success"
	AuditEventOutcomeFailure = "failure"
	AuditEventOutcomeDenied  = "denied"
	AuditEventOutcomeUnknown = "unknown"
)

// AuditEventActorV1 is the bounded actor identity exposed by the portable
// audit-event contract. Label is approved display text supplied by the source
// adapter. The record intentionally has no attributes or raw payload.
type AuditEventActorV1 struct {
	ID    string
	Kind  string
	Label string
}

// AuditEventResourceV1 is the bounded resource identity exposed by the
// portable audit-event contract. Label is approved display text supplied by
// the source adapter. The record has no attributes or raw payload.
type AuditEventResourceV1 struct {
	ID    string
	Type  string
	Label string
}

// AuditEventV1 is one normalized, tenant-owned audit event. TenantID is a
// storage and authorization key and is never serialized by the HTTP handler.
// Summary is approved display text supplied by the source adapter. The fixed
// fields are the complete persistence allowlist.
type AuditEventV1 struct {
	ID         string
	TenantID   string
	Action     string
	Actor      *AuditEventActorV1
	Category   string
	DurationMS *int64
	OccurredAt time.Time
	Outcome    string
	RequestID  string
	Resource   *AuditEventResourceV1
	Service    string
	Summary    string
	TraceID    string
}

// AuditEventQueryV1 is the normalized store query. Before/After define every
// page to one immutable time window. PageBeforeOccurredAt and PageBeforeID
// form the stable descending keyset boundary.
type AuditEventQueryV1 struct {
	TenantID             string
	Action               string
	Actor                string
	After                time.Time
	Before               time.Time
	Limit                uint32
	Outcome              string
	PageBeforeOccurredAt time.Time
	PageBeforeID         string
	Query                string
	ResourceType         string
	Service              string
	TraceID              string
}

// AuditEventPageV1 is a keyset page returned by an AuditEventReader. Partial
// is reserved for readers that can prove that only a subset of their durable
// inputs was available. The Postgres reader returns complete pages or an error.
type AuditEventPageV1 struct {
	Events  []*AuditEventV1
	HasMore bool
	Partial bool
}

// AuditEventReader is the read-only portable audit-event capability.
type AuditEventReader interface {
	ListAuditEvents(context.Context, AuditEventQueryV1) (AuditEventPageV1, error)
}

// AuditEventProjectionV1 binds one normalized read-model record to the durable
// append-log sequence from which it was derived. Projectors must not invent a
// sequence or write a record before the source event is durably appended.
type AuditEventProjectionV1 struct {
	SourceSequence uint64
	Event          *AuditEventV1
}

// AuditEventProjectionWriter populates the rebuildable audit-event read model.
// It is intentionally separate from AuditEventReader: no public HTTP write
// route or second log-of-record is part of this contract.
type AuditEventProjectionWriter interface {
	ProjectAuditEvent(context.Context, AuditEventProjectionV1) error
}
