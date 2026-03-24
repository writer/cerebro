package app

import (
	"context"
	"fmt"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) initConfiguredSecurityGraphStore(ctx context.Context) error {
	if a == nil || a.Config == nil {
		return nil
	}
	switch a.Config.graphStoreBackend() {
	case graph.StoreBackendMemory:
		a.configuredSecurityGraphStore = nil
		a.configuredSecurityGraphClose = nil
		a.configuredSecurityGraphReady = false
		a.graphStoreDualWriteReplayQueue = nil
		return nil
	default:
		provider, err := a.resolveGraphStoreBackendProvider(a.Config.graphStoreBackend())
		if err != nil {
			return err
		}
		handle, err := provider.Open(ctx, a)
		if err != nil {
			return err
		}
		handle, dualWriteLogFields, err := a.wrapConfiguredSecurityGraphStoreWithDualWrite(ctx, handle)
		if err != nil {
			return closeHandle(handle, err)
		}
		ready, err := a.probeConfiguredSecurityGraphStore(ctx, handle.Store)
		if err != nil {
			return closeHandle(handle, err)
		}
		a.configuredSecurityGraphStore = handle.Store
		a.configuredSecurityGraphClose = handle.Close
		a.configuredSecurityGraphReady = ready
		if a.Logger != nil {
			args := []any{"backend", provider.Backend(), "ready", ready}
			args = append(args, provider.LogFields(a)...)
			args = append(args, dualWriteLogFields...)
			a.Logger.Info("configured graph store backend", args...)
		}
		return nil
	}
}

func (a *App) probeConfiguredSecurityGraphStore(ctx context.Context, store graph.GraphStore) (bool, error) {
	if store == nil {
		return false, nil
	}
	if err := store.EnsureIndexes(ctx); err != nil {
		return false, fmt.Errorf("ensure configured graph store backend: %w", err)
	}
	nodes, err := store.CountNodes(ctx)
	if err != nil {
		return false, fmt.Errorf("probe configured graph store nodes: %w", err)
	}
	edges, err := store.CountEdges(ctx)
	if err != nil {
		return false, fmt.Errorf("probe configured graph store edges: %w", err)
	}
	return nodes > 0 || edges > 0, nil
}
