package collector

import (
	"context"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

// SnapshotCollector is implemented by collectors that produce point-in-time
// host telemetry snapshots.  Collectors should be deterministic and quick so
// the manager can fan out requests without starving other work.
type SnapshotCollector interface {
	// Name returns the registry identifier for the collector.  It doubles as
	// the task name when artifact packs reference the collector.
	Name() string
	// Collect gathers the current host telemetry.  The params map allows
	// artifact packs to override defaults (for example, process limits).
	Collect(context.Context, config.Config, map[string]any) (*types.HostTelemetry, error)
}

// EventCollector streams high-frequency events (process deltas, file watches,
// etc.) which the runtime batches and forwards on a cadence.
type EventCollector interface {
	// Name returns the registry identifier for the collector.
	Name() string
	// Collect gathers the next batch of events to enqueue.
	Collect(context.Context, config.Config) ([]types.HostEvent, error)
}
