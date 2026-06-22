package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ErrSourceRuntimeNotFound indicates that a stored source runtime does not exist.
var ErrSourceRuntimeNotFound = errors.New("source runtime not found")

// SourceRuntimeStore persists source runtime configuration and checkpoints.
type SourceRuntimeStore interface {
	StateStore
	PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error
	GetSourceRuntime(context.Context, string) (*cerebrov1.SourceRuntime, error)
}

// SourceRuntimeBatchStore persists multiple source runtimes atomically.
type SourceRuntimeBatchStore interface {
	SourceRuntimeStore
	PutSourceRuntimes(context.Context, []*cerebrov1.SourceRuntime) error
}

// SourceRuntimePageAttempt records one source-runtime page commit attempt.
type SourceRuntimePageAttempt struct {
	AttemptID      string
	RuntimeID      string
	SourceID       string
	TenantID       string
	PageNumber     uint32
	RecordsScanned uint32
	Events         []*cerebrov1.EventEnvelope
}

// SourceRuntimePageProjection records projection counts for one page attempt.
type SourceRuntimePageProjection struct {
	EntitiesProjected uint32
	LinksProjected    uint32
}

// SourceRuntimePageLedgerStore durably records page commit state and outbox
// events. CommitSourceRuntimePage must atomically persist runtime progress and
// mark the page committed.
type SourceRuntimePageLedgerStore interface {
	BeginSourceRuntimePage(context.Context, SourceRuntimePageAttempt) error
	MarkSourceRuntimePageAppended(context.Context, string) error
	MarkSourceRuntimePageProjected(context.Context, string, SourceRuntimePageProjection) error
	CommitSourceRuntimePage(context.Context, string, *cerebrov1.SourceRuntime) error
}

// SourceRuntimeFilter scopes persisted source runtime listing.
type SourceRuntimeFilter struct {
	RuntimeID  string
	RuntimeIDs []string
	TenantID   string
	SourceID   string
	Limit      uint32
}

// SourceRuntimeListStore lists persisted source runtime definitions.
type SourceRuntimeListStore interface {
	SourceRuntimeStore
	ListSourceRuntimes(context.Context, SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error)
}

// SourceRuntimeLeaseStore leases source runtimes before orchestration work.
type SourceRuntimeLeaseStore interface {
	AcquireSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error)
	RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error)
	ReleaseSourceRuntimeLease(context.Context, string, string) error
}
