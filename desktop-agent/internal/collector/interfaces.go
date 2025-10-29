package collector

import (
	"context"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type SnapshotCollector interface {
	Name() string
	Collect(context.Context, config.Config, map[string]any) (*types.HostTelemetry, error)
}

type EventCollector interface {
	Name() string
	Collect(context.Context, config.Config) ([]types.HostEvent, error)
}
