package ports

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const EventAttributeSourceRuntimeID = "source_runtime_id"
const EventAttributeJobID = "job_id"

var ErrAppendLogDeadLetterNotFound = errors.New("append log dead letter not found")

const (
	AppendLogDeadLetterStatusPending   = "pending"
	AppendLogDeadLetterStatusReplayed  = "replayed"
	AppendLogDeadLetterStatusDiscarded = "discarded"
)

// AppendLog is the future append-only event log boundary.
type AppendLog interface {
	Ping(context.Context) error
	Append(context.Context, *cerebrov1.EventEnvelope) error
}

// AppendLogBatcher is an optional append-log capability for paths that can
// publish a validated page or upload batch through one boundary.
type AppendLogBatcher interface {
	AppendBatch(context.Context, []*cerebrov1.EventEnvelope) error
}

// AppendLogPublishExhaustedError marks a publish that exhausted the configured
// retry budget. It lets recovery wrappers distinguish durable publish failures
// from validation, authorization, and caller-cancellation errors.
type AppendLogPublishExhaustedError struct {
	Operation     string
	Subject       string
	ErrorCategory string
	RetryCount    int
	MaxAttempts   int
	Err           error
}

func (e *AppendLogPublishExhaustedError) Error() string {
	subject := strings.TrimSpace(e.Subject)
	if subject == "" {
		subject = "unknown"
	}
	if e.Err == nil {
		return fmt.Sprintf("append log publish exhausted for subject %s", subject)
	}
	return fmt.Sprintf("append log publish exhausted for subject %s: %v", subject, e.Err)
}

func (e *AppendLogPublishExhaustedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// AppendLogDeadLetter records one append-log event that could not be published
// after all configured attempts.
type AppendLogDeadLetter struct {
	ID            string
	Status        string
	Subject       string
	Operation     string
	EventID       string
	EventKind     string
	TenantID      string
	SourceID      string
	RuntimeID     string
	JobID         string
	ErrorCategory string
	ErrorMessage  string
	RetryCount    int
	MaxAttempts   int
	PayloadHash   string
	PayloadBytes  int
	Event         *cerebrov1.EventEnvelope
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ReplayedAt    time.Time
	DiscardedAt   time.Time
	DiscardReason string
}

// AppendLogDeadLetterFilter scopes operator reads over persisted publish
// recovery records.
type AppendLogDeadLetterFilter struct {
	Status    string
	Subject   string
	RuntimeID string
	SourceID  string
	Limit     uint32
}

// AppendLogDeadLetterStore persists and manages exhausted publish recovery
// records outside JetStream so broker degradation does not recursively depend
// on the same append path.
type AppendLogDeadLetterStore interface {
	RecordAppendLogDeadLetter(context.Context, AppendLogDeadLetter) error
	ListAppendLogDeadLetters(context.Context, AppendLogDeadLetterFilter) ([]AppendLogDeadLetter, error)
	GetAppendLogDeadLetter(context.Context, string) (AppendLogDeadLetter, error)
	MarkAppendLogDeadLetterReplayed(context.Context, string) error
	DiscardAppendLogDeadLetter(context.Context, string, string) error
}

// ReplayRequest scopes a bounded event replay from the append log.
type ReplayRequest struct {
	RuntimeID           string
	KindPrefix          string
	KindPrefixes        []string
	ExactKindFilters    bool
	RequireRuntimeIndex bool
	TenantID            string
	AttributeEquals     map[string]string
	Limit               uint32
}

// EventReplayer replays stored event envelopes from the append log.
type EventReplayer interface {
	Replay(context.Context, ReplayRequest) ([]*cerebrov1.EventEnvelope, error)
}

// RuntimeIndexEntry is one append-log message indexed by source runtime and stream sequence.
type RuntimeIndexEntry struct {
	RuntimeID  string
	Seq        uint64
	TenantID   string
	Kind       string
	OccurredAt time.Time
}

// RuntimeIndexScan is one bounded forward scan of the append log for index population.
type RuntimeIndexScan struct {
	Entries   []RuntimeIndexEntry
	Watermark uint64 // highest stream sequence examined; everything at or below it is processed.
	CaughtUp  bool   // true when the scan reached the current stream tail.
}

// RuntimeIndexSource scans the append log forward to populate the per-runtime replay index.
type RuntimeIndexSource interface {
	ScanRuntimeIndex(ctx context.Context, fromSeq uint64, batch uint32) (RuntimeIndexScan, error)
}

// RuntimeIndexQuery scopes a per-runtime replay index lookup.
type RuntimeIndexQuery struct {
	RuntimeID string
	Kinds     []string // exact event kinds; empty matches all kinds for the runtime.
	Limit     uint32
}

// RuntimeIndexResult carries newest-observed-first stream sequences for one runtime replay lookup.
type RuntimeIndexResult struct {
	Sequences []uint64
	Watermark uint64
	Available bool // true once the index has been populated (watermark > 0).
}

// RuntimeReplayIndex is the read side of the per-runtime append-log replay index.
type RuntimeReplayIndex interface {
	LookupRuntimeReplay(ctx context.Context, query RuntimeIndexQuery) (RuntimeIndexResult, error)
}

// RuntimeIndexWriter persists per-runtime replay index entries and advances the watermark.
type RuntimeIndexWriter interface {
	PutRuntimeIndexEntries(ctx context.Context, entries []RuntimeIndexEntry, watermark uint64) error
	RuntimeIndexWatermark(ctx context.Context) (uint64, error)
}
