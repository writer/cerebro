package api

import (
	"context"

	"github.com/evalops/cerebro/internal/graph"
)

func currentOrStoredGraphView(ctx context.Context, current *graph.Graph, store graph.GraphStore) (*graph.Graph, error) {
	if current != nil {
		return current, nil
	}
	return snapshotGraphView(ctx, store)
}

func snapshotBackedGraphView(ctx context.Context, current *graph.Graph, store graph.GraphStore) (*graph.Graph, error) {
	if store != nil {
		return snapshotGraphView(ctx, store)
	}
	if current == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return snapshotGraphView(ctx, current)
}

func snapshotGraphView(ctx context.Context, store graph.GraphStore) (*graph.Graph, error) {
	if store == nil {
		return nil, graph.ErrStoreUnavailable
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, graph.ErrStoreUnavailable
	}
	view := graph.GraphViewFromSnapshot(snapshot)
	if view == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return view, nil
}

func currentOrStoredTenantGraphView(ctx context.Context, deps *serverDependencies) (*graph.Graph, error) {
	if deps == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	return currentOrStoredGraphView(ctx, deps.CurrentSecurityGraphForTenant(tenantID), deps.CurrentSecurityGraphStoreForTenant(tenantID))
}

func snapshotBackedTenantGraphView(ctx context.Context, deps *serverDependencies) (*graph.Graph, error) {
	if deps == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	return snapshotBackedGraphView(ctx, deps.CurrentSecurityGraphForTenant(tenantID), deps.CurrentSecurityGraphStoreForTenant(tenantID))
}
