package api

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
)

func currentOrStoredGraphView(ctx context.Context, current *graph.Graph, store graph.GraphStore) (*graph.Graph, error) {
	if current != nil {
		return current, nil
	}
	return snapshotGraphView(ctx, store)
}

func currentOrStoredGraphMetadata(ctx context.Context, current *graph.Graph, store graph.GraphStore) (graph.Metadata, error) {
	if current != nil {
		return current.GraphMetadata(ctx)
	}
	return graph.GraphMetadataFromStore(ctx, store)
}

func currentOrStoredGraphSnapshotRecord(ctx context.Context, current *graph.Graph, store graph.GraphStore) (*graph.GraphSnapshotRecord, error) {
	if record := graph.CurrentGraphSnapshotRecord(current); record != nil {
		return record, nil
	}
	if metadataStore, ok := graph.AsGraphMetadataStore(store); ok {
		meta, err := metadataStore.GraphMetadata(ctx)
		if err == nil {
			record := graph.CurrentGraphSnapshotRecordFromMetadata(meta)
			if record != nil {
				return record, nil
			}
		}
	}
	view, err := snapshotGraphView(ctx, store)
	if err != nil {
		return nil, err
	}
	record := graph.CurrentGraphSnapshotRecord(view)
	if record == nil {
		return nil, nil
	}
	return record, nil
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
