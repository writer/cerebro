package app

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) initEntitySearchBackend(ctx context.Context) error {
	if a == nil || a.Config == nil {
		return nil
	}

	a.configuredEntitySearchBackend = nil
	a.configuredEntitySearchClose = nil

	backend := a.Config.graphSearchBackend()
	if backend == graph.EntitySearchBackendGraph {
		return nil
	}

	provider, err := a.resolveEntitySearchBackendProvider(backend)
	if err != nil {
		return err
	}
	handle, err := provider.Open(ctx, a)
	if err != nil {
		return err
	}

	a.configuredEntitySearchBackend = handle.Backend
	a.configuredEntitySearchClose = handle.Close

	if a.Logger != nil {
		args := []any{"backend", provider.Backend()}
		args = append(args, provider.LogFields(a)...)
		a.Logger.Info("configured entity search backend", args...)
	}

	return nil
}

func (a *App) CurrentEntitySearchBackend() graph.EntitySearchBackend {
	if a == nil {
		return nil
	}
	return a.configuredEntitySearchBackend
}
