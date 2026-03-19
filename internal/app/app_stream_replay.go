package app

import (
	"context"
	"log/slog"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

// NewTapReplayApp builds the minimal app surface required to replay TAP
// CloudEvents into a graph without booting the full application container.
func NewTapReplayApp(cfg *Config, logger *slog.Logger) *App {
	if cfg == nil {
		cfg = LoadConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}
	securityGraph := graph.New()
	app := &App{
		Config:        cfg,
		Logger:        logger,
		SecurityGraph: securityGraph,
	}
	app.configureGraphRuntimeBehavior(securityGraph)
	return app
}

// ReplayTapCloudEvent applies one TAP CloudEvent on the replay app graph.
func (a *App) ReplayTapCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	return a.handleTapCloudEvent(ctx, evt)
}
