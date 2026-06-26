package ports

import (
	"context"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const EventAttributeSourceRuntimeID = "source_runtime_id"

// AppendLog is the future append-only event log boundary.
type AppendLog interface {
	Ping(context.Context) error
	Append(context.Context, *cerebrov1.EventEnvelope) error
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

// RuntimeIndexResult carries newest-first stream sequences for one runtime replay lookup.
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
