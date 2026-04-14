package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func graphHasReadableData(g *graph.Graph) bool {
	return g != nil && (g.NodeCount() > 0 || g.EdgeCount() > 0)
}

func (a *App) currentOrStoredSecurityGraphView() (*graph.Graph, error) {
	return a.currentOrStoredSecurityGraphViewWithSnapshotLoader(func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error) {
		snapshot, _, _, err := store.LoadLatestSnapshot()
		return snapshot, err
	})
}

func (a *App) currentOrStoredPassiveSecurityGraphView() (*graph.Graph, error) {
	return a.currentOrStoredSecurityGraphViewWithSnapshotLoader(func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error) {
		snapshot, _, _, err := store.PeekLatestSnapshot()
		return snapshot, err
	})
}

func (a *App) currentOrStoredPassiveGraphSnapshotRecord() (*graph.GraphSnapshotRecord, error) {
	if a == nil {
		return nil, nil
	}
	if current := graph.CurrentGraphSnapshotRecord(a.currentLiveSecurityGraph()); current != nil {
		return current, nil
	}
	if snapshot, err := a.currentConfiguredSecurityGraphSnapshot(context.Background()); err == nil && snapshot != nil {
		if current := graph.CurrentGraphSnapshotRecord(graph.GraphViewFromSnapshot(snapshot)); current != nil {
			return current, nil
		}
	} else if err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *App) currentOrStoredSecurityGraphViewWithSnapshotLoader(loadSnapshot func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}

	current := a.currentLiveSecurityGraph()
	if graphHasReadableData(current) {
		return current, nil
	}
	if view, err := a.currentConfiguredSecurityGraphView(context.Background()); err != nil {
		return nil, err
	} else if view != nil {
		return view, nil
	}
	if view, err := a.storedSecurityGraphViewWithSnapshotLoader(loadSnapshot); err != nil || view != nil {
		return view, err
	}
	return nil, nil
}

func (a *App) storedSecurityGraphViewWithSnapshotLoader(loadSnapshot func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	if a.GraphSnapshots == nil || loadSnapshot == nil {
		return nil, nil
	}
	snapshot, err := loadSnapshot(a.GraphSnapshots)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no snapshots found") {
			return nil, nil
		}
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	return graph.GraphViewFromSnapshot(snapshot), nil
}

func (a *App) currentOrStoredSecurityGraphViewForTenant(tenantID string) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return a.currentOrStoredSecurityGraphView()
	}
	if current := a.currentLiveSecurityGraph(); current != nil {
		return a.CurrentSecurityGraphForTenant(tenantID), nil
	}
	view, err := a.currentOrStoredSecurityGraphView()
	if err != nil || view == nil {
		return view, err
	}
	return view.SubgraphForTenant(tenantID), nil
}

func (a *App) requireReadableSecurityGraph() (*graph.Graph, error) {
	if a == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	g, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve readable security graph", "error", err)
		}
		return nil, fmt.Errorf("security graph not initialized")
	}
	if g == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return g, nil
}

func (a *App) WaitForReadableSecurityGraph(ctx context.Context) *graph.Graph {
	if a == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if current := a.currentLiveSecurityGraph(); current != nil {
		if a.graphReady == nil {
			resolved := a.CurrentSecurityGraph()
			if !graphHasReadableData(resolved) {
				return nil
			}
			return resolved
		}
		if !a.WaitForGraph(ctx) {
			if !graphHasReadableData(current) {
				resolved := a.CurrentSecurityGraph()
				if !graphHasReadableData(resolved) {
					return nil
				}
				return resolved
			}
			return current
		}
		resolved := a.CurrentSecurityGraph()
		if !graphHasReadableData(resolved) {
			return nil
		}
		return resolved
	}
	securityGraph, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve readable security graph", "error", err)
		}
		return nil
	}
	if !graphHasReadableData(securityGraph) {
		return nil
	}
	return securityGraph
}

func (a *App) currentConfiguredSecurityGraphSnapshot(ctx context.Context) (*graph.Snapshot, error) {
	if a == nil {
		return nil, nil
	}
	store, err := a.currentConfiguredSecurityGraphStore(ctx)
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			return nil, nil
		}
		return nil, err
	}
	if store == nil {
		return nil, nil
	}
	return store.Snapshot(ctx)
}

func (a *App) currentConfiguredSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	snapshot, err := a.currentConfiguredSecurityGraphSnapshot(ctx)
	if err != nil || snapshot == nil {
		return nil, err
	}
	return graph.GraphViewFromSnapshot(snapshot), nil
}
