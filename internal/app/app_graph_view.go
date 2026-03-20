package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

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
	if current := graph.CurrentGraphSnapshotRecord(a.CurrentSecurityGraph()); current != nil {
		return current, nil
	}
	store := a.platformGraphSnapshotStoreForTool()
	if store == nil {
		return nil, nil
	}
	snapshot, record, _, err := store.PeekLatestSnapshot()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no snapshots found") {
			return nil, nil
		}
		return nil, err
	}
	if record != nil {
		current := *record
		current.Current = true
		return &current, nil
	}
	if snapshot == nil {
		return nil, nil
	}
	return graph.CurrentGraphSnapshotRecord(graph.GraphViewFromSnapshot(snapshot)), nil
}

func (a *App) currentOrStoredSecurityGraphViewWithSnapshotLoader(loadSnapshot func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	if current := a.CurrentSecurityGraph(); current != nil {
		return current, nil
	}
	return a.storedSecurityGraphViewWithSnapshotLoader(loadSnapshot)
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
	if current := a.CurrentSecurityGraph(); current != nil {
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
	if current := a.CurrentSecurityGraph(); current != nil {
		if a.graphReady == nil {
			if current.NodeCount() == 0 {
				return nil
			}
			return current
		}
		if !a.WaitForGraph(ctx) {
			if current.NodeCount() == 0 {
				return nil
			}
			return current
		}
		return a.CurrentSecurityGraph()
	}
	securityGraph, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve readable security graph", "error", err)
		}
		return nil
	}
	if securityGraph == nil || securityGraph.NodeCount() == 0 {
		return nil
	}
	return securityGraph
}
