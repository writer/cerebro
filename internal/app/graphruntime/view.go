package graphruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (a *Runtime) CurrentOrStoredSecurityGraphView() (*graph.Graph, error) {
	return a.currentOrStoredSecurityGraphViewWithSnapshotLoader(func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error) {
		snapshot, _, _, err := store.LoadLatestSnapshot()
		return snapshot, err
	})
}

func (a *Runtime) CurrentOrStoredPassiveSecurityGraphView() (*graph.Graph, error) {
	return a.currentOrStoredSecurityGraphViewWithSnapshotLoader(func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error) {
		snapshot, _, _, err := store.PeekLatestSnapshot()
		return snapshot, err
	})
}

func (a *Runtime) StoredSecurityGraphViewWithSnapshotLoader(loadSnapshot func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	store := a.graphSnapshots()
	if store == nil || loadSnapshot == nil {
		return nil, nil
	}
	snapshot, err := loadSnapshot(store)
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

func (a *Runtime) CurrentOrStoredPassiveGraphSnapshotRecord() (*graph.GraphSnapshotRecord, error) {
	if a == nil {
		return nil, nil
	}
	if current := graph.CurrentGraphSnapshotRecord(a.currentLiveSecurityGraph()); current != nil {
		return current, nil
	}
	if snapshot, err := a.CurrentConfiguredSecurityGraphSnapshot(a.backgroundContext()); err == nil && snapshot != nil {
		if current := graph.CurrentGraphSnapshotRecord(graph.GraphViewFromSnapshot(snapshot)); current != nil {
			return current, nil
		}
	} else if err != nil {
		return nil, err
	}
	if current := graph.CurrentGraphSnapshotRecord(a.CurrentSecurityGraph()); current != nil {
		return current, nil
	}
	return nil, nil
}

func (a *Runtime) currentOrStoredSecurityGraphViewWithSnapshotLoader(loadSnapshot func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}

	current := a.currentLiveSecurityGraph()
	if current != nil && (current.NodeCount() > 0 || current.EdgeCount() > 0) {
		return current, nil
	}
	if view, err := a.CurrentConfiguredSecurityGraphView(a.backgroundContext()); err != nil {
		return nil, err
	} else if view != nil {
		return view, nil
	}
	if view, err := a.StoredSecurityGraphViewWithSnapshotLoader(loadSnapshot); err != nil || view != nil {
		return view, err
	}
	return current, nil
}

func (a *Runtime) CurrentOrStoredSecurityGraphViewForTenant(tenantID string) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return a.CurrentOrStoredSecurityGraphView()
	}
	if current := a.currentLiveSecurityGraph(); current != nil {
		return a.CurrentSecurityGraphForTenant(tenantID), nil
	}
	view, err := a.CurrentOrStoredSecurityGraphView()
	if err != nil || view == nil {
		return view, err
	}
	return view.SubgraphForTenant(tenantID), nil
}

func (a *Runtime) RequireReadableSecurityGraph() (*graph.Graph, error) {
	if a == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	g, err := a.CurrentOrStoredSecurityGraphView()
	if err != nil {
		if a.logger() != nil {
			a.logger().Warn("failed to resolve readable security graph", "error", err)
		}
		return nil, fmt.Errorf("security graph not initialized")
	}
	if g == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return g, nil
}

func (a *Runtime) WaitForReadableSecurityGraph(ctx context.Context) *graph.Graph {
	if a == nil {
		return nil
	}
	if ctx == nil {
		ctx = a.backgroundContext()
	}
	if current := a.currentLiveSecurityGraph(); current != nil {
		if !a.hasGraphReadySignal() {
			if current.NodeCount() == 0 {
				return nil
			}
			return current
		}
		if !a.waitForGraph(ctx) {
			if current.NodeCount() == 0 {
				return nil
			}
			return current
		}
		return a.currentLiveSecurityGraph()
	}
	securityGraph, err := a.CurrentOrStoredSecurityGraphView()
	if err != nil {
		if a.logger() != nil {
			a.logger().Warn("failed to resolve readable security graph", "error", err)
		}
		return nil
	}
	if securityGraph == nil || securityGraph.NodeCount() == 0 {
		return nil
	}
	return securityGraph
}

func (a *Runtime) CurrentConfiguredSecurityGraphSnapshot(ctx context.Context) (*graph.Snapshot, error) {
	if a == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = a.backgroundContext()
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

func (a *Runtime) CurrentConfiguredSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	snapshot, err := a.CurrentConfiguredSecurityGraphSnapshot(ctx)
	if err != nil || snapshot == nil {
		return nil, err
	}
	return graph.GraphViewFromSnapshot(snapshot), nil
}
