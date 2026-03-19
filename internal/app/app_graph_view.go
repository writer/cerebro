package app

import (
	"fmt"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) currentOrStoredSecurityGraphView() (*graph.Graph, error) {
	if a == nil {
		return nil, nil
	}
	if current := a.CurrentSecurityGraph(); current != nil {
		return current, nil
	}
	if a.GraphSnapshots == nil {
		return nil, nil
	}
	snapshot, _, _, err := a.GraphSnapshots.LoadLatestSnapshot()
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
