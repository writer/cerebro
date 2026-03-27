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
			return closeEntitySearchHandle(handle, err)
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

func (a *App) hydrateCurrentEntitySearchRecord(ctx context.Context, tenantID, id string) (graph.EntityRecord, bool, error) {
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	if id == "" {
		return graph.EntityRecord{}, false, nil
	}
	if a == nil {
		return graph.EntityRecord{}, false, graph.ErrStoreUnavailable
	}

	if current := a.currentLiveSecurityGraph(); current != nil {
		return hydrateCurrentEntitySearchRecordFromStore(ctx, current, tenantID, id)
	}

	if tenantID != "" {
		if store, err := a.currentWarmTenantGraphStore(ctx, tenantID); err == nil && store != nil {
			return hydrateCurrentEntitySearchRecordFromStore(ctx, store, "", id)
		} else if err != nil && !errors.Is(err, graph.ErrStoreUnavailable) {
			return graph.EntityRecord{}, false, err
		}
	}

	if store, err := a.currentConfiguredSecurityGraphStore(ctx); err == nil && store != nil {
		return hydrateCurrentEntitySearchRecordFromStore(ctx, store, tenantID, id)
	} else if err != nil && !errors.Is(err, graph.ErrStoreUnavailable) {
		return graph.EntityRecord{}, false, err
	}

	if store, err := a.currentPassiveSnapshotStore(ctx); err == nil && store != nil {
		return hydrateCurrentEntitySearchRecordFromStore(ctx, store, tenantID, id)
	} else if err != nil && !errors.Is(err, graph.ErrStoreUnavailable) {
		return graph.EntityRecord{}, false, err
	}

	return graph.EntityRecord{}, false, graph.ErrStoreUnavailable
}

func hydrateCurrentEntitySearchRecordFromStore(ctx context.Context, store graph.GraphStore, tenantID, id string) (graph.EntityRecord, bool, error) {
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	if id == "" {
		return graph.EntityRecord{}, false, nil
	}
	if store == nil {
		return graph.EntityRecord{}, false, graph.ErrStoreUnavailable
	}
	if tenantID == "" {
		return graph.GetCurrentEntityRecordFromStore(ctx, store, id)
	}

	switch typed := store.(type) {
	case *graph.Graph:
		return graph.GetCurrentEntityRecordFromStore(ctx, typed.SubgraphForTenant(tenantID), id)
	case *graph.SnapshotGraphStore:
		snapshot, err := typed.Snapshot(ctx)
		if err != nil {
			return graph.EntityRecord{}, false, err
		}
		if snapshot == nil {
			return graph.EntityRecord{}, false, graph.ErrStoreUnavailable
		}
		return graph.GetCurrentEntityRecordFromStore(ctx, graph.GraphViewFromSnapshot(snapshot).SubgraphForTenant(tenantID), id)
	default:
		return graph.GetCurrentEntityRecordFromStore(graph.WithTenantScope(ctx, tenantID), store, id)
	}
}
