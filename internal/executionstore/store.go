package executionstore

import (
	"context"
	"time"
)

// Store is the durable execution-state substrate interface. SQLite is the
// current implementation, but higher-scale backends should satisfy the same
// contract instead of forcing callers to depend on SQLite directly.
type Store interface {
	Close() error
	UpsertRun(context.Context, RunEnvelope) error
	CompareAndSwapRun(context.Context, RunEnvelope, RunEnvelope) (bool, error)
	ReplaceRunWithEvents(context.Context, RunEnvelope, []EventEnvelope) error
	LoadRun(context.Context, string, string) (*RunEnvelope, error)
	ListRuns(context.Context, string, RunListOptions) ([]RunEnvelope, error)
	ListAllRuns(context.Context, RunListOptions) ([]RunEnvelope, error)
	DeleteRun(context.Context, string, string) error
	DeleteEvents(context.Context, string, string) error
	SaveEvent(context.Context, EventEnvelope) (EventEnvelope, error)
	LoadEvents(context.Context, string, string) ([]EventEnvelope, error)
	LookupProcessedEvent(context.Context, string, string, time.Time) (*ProcessedEventRecord, error)
	TouchProcessedEvent(context.Context, string, string, time.Time, time.Duration) error
	RememberProcessedEvent(context.Context, ProcessedEventRecord, int) error
	DeleteProcessedEvent(context.Context, string, string) error
}
