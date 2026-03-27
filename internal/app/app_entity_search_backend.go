package app

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

type entitySearchBackendChecker interface {
	Check(context.Context) error
}

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
	if checker, ok := handle.Backend.(entitySearchBackendChecker); ok {
		if err := checker.Check(ctx); err != nil {
			if !graph.IsEntitySearchBootstrapPending(err) {
				return closeEntitySearchHandle(handle, err)
			}
			if a.Logger != nil {
				a.Logger.Warn("entity search backend bootstrap pending; falling back to graph reads until the search index is ready", "backend", provider.Backend(), "error", err)
			}
		}
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

func closeEntitySearchHandle(handle entitySearchBackendHandle, base error) error {
	if handle.Close == nil {
		return base
	}
	if err := handle.Close(); err != nil {
		return errors.Join(base, err)
	}
	return base
}

func (a *App) resolveCurrentEntitySearchGraph(ctx context.Context, tenantID string) (*graph.Graph, error) {
	tenantID = strings.TrimSpace(tenantID)
	if a == nil {
		return nil, graph.ErrStoreUnavailable
	}

	if current := a.currentLiveSecurityGraph(); current != nil {
		if tenantID == "" {
			return current, nil
		}
		view := a.CurrentSecurityGraphForTenant(tenantID)
		if view == nil {
			return nil, graph.ErrStoreUnavailable
		}
		return view, nil
	}

	if tenantID != "" {
		if store, err := a.currentWarmTenantGraphStore(ctx, tenantID); err == nil && store != nil {
			return entitySearchGraphFromWarmStore(ctx, store)
		} else if err != nil && !errors.Is(err, graph.ErrStoreUnavailable) {
			return nil, err
		}
	}

	if view, err := a.currentConfiguredSecurityGraphView(ctx); err != nil {
		return nil, err
	} else if view != nil {
		return scopeEntitySearchGraphView(view, tenantID), nil
	}

	view, err := a.storedSecurityGraphViewWithSnapshotLoader(func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error) {
		snapshot, _, _, err := store.PeekLatestSnapshot()
		return snapshot, err
	})
	if err != nil {
		return nil, err
	}
	if view != nil {
		return scopeEntitySearchGraphView(view, tenantID), nil
	}
	return nil, graph.ErrStoreUnavailable
}

func scopeEntitySearchGraphView(view *graph.Graph, tenantID string) *graph.Graph {
	tenantID = strings.TrimSpace(tenantID)
	if view == nil {
		return nil
	}
	if tenantID == "" {
		return view
	}
	return view.SubgraphForTenant(tenantID)
}

func entitySearchGraphFromWarmStore(ctx context.Context, store graph.GraphStore) (*graph.Graph, error) {
	switch typed := store.(type) {
	case *graph.Graph:
		return typed, nil
	case *graph.SnapshotGraphStore:
		snapshot, err := typed.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		if snapshot == nil {
			return nil, graph.ErrStoreUnavailable
		}
		return graph.GraphViewFromSnapshot(snapshot), nil
	default:
		return nil, graph.ErrStoreUnavailable
	}
}
