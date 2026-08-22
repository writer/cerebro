package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var (
	// ErrSourceRuntimeNotFound indicates that a stored source runtime does not exist.
	ErrSourceRuntimeNotFound = errors.New("source runtime not found")
	// ErrSourceRuntimeLeaseLost indicates that an operation no longer owns the
	// durable generation under which it collected a source page.
	ErrSourceRuntimeLeaseLost = errors.New("source runtime lease lost")
)

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
	Admission      SourceRuntimePageAdmission
	Authority      SourceRuntimeAuthorityEvidenceRef
}

// SourceRuntimeAuthorityEvidenceRef binds a page or deposit receipt to the
// append-only source-family authority evidence that allowed the work.
type SourceRuntimeAuthorityEvidenceRef struct {
	DecisionID string
	Epoch      uint64
}

// SourceRuntimePageAdmission records the exact kernel decision made before append.
type SourceRuntimePageAdmission struct {
	Kernel          string
	ABIVersion      uint32
	Scanned         uint32
	Accepted        uint32
	Quarantined     uint32
	Duplicates      uint32
	ContractsSHA256 string
	ScannedSHA256   string
	AcceptedSHA256  string
	ResultSHA256    string
}

// SourceRuntimePageProjection records projection counts for one page attempt.
type SourceRuntimePageProjection struct {
	EntitiesProjected uint32
	LinksProjected    uint32
}

// SourceCollectionManifest records one bounded sync run without treating a
// completed incremental run as an authoritative full snapshot.
type SourceCollectionManifest struct {
	CollectionID          string
	TenantID              string
	SourceID              string
	RuntimeID             string
	StartedAtUnixMS       int64
	CompletedAtUnixMS     int64
	Status                string
	IncompletenessReasons []string
	ExpectedFamilyIDs     []string
	ObservedFamilyIDs     []string
	PagesRead             uint32
	RecordsScanned        uint32
	RecordsAccepted       uint32
	RecordsRejected       uint32
	EntitiesProjected     uint32
	LinksProjected        uint32
}

// SourceCollectionRecorder retains collection-level coverage and completeness
// at the Rust migration boundary.
type SourceCollectionRecorder interface {
	RecordSourceCollection(context.Context, SourceCollectionManifest) error
}

// SourceCollectionReader loads the exact durable final manifest used to prove
// collection completeness. Missing receipts are not inferred from graph state.
type SourceCollectionReader interface {
	GetSourceCollection(ctx context.Context, tenantID, runtimeID, collectionID string) (SourceCollectionManifest, error)
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

// SourceRuntimeFencedPageCommitter commits progress only while the exact
// owner and generation that admitted the page still hold the durable lease.
type SourceRuntimeFencedPageCommitter interface {
	CommitSourceRuntimePageFenced(context.Context, string, *cerebrov1.SourceRuntime, SourceRuntimeLeaseFence) error
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

// SourceRuntimeLeaseFence is the durable owner/generation snapshot bound to
// one source-runtime execution.
type SourceRuntimeLeaseFence struct {
	Owner      string
	Generation uint64
	ExpiresAt  time.Time
}

// SourceRuntimeLeaseFenceReader returns the current durable lease fence only
// when the requested owner still holds it.
type SourceRuntimeLeaseFenceReader interface {
	ReadSourceRuntimeLeaseFence(context.Context, string, string) (SourceRuntimeLeaseFence, error)
}
