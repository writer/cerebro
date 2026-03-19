package app

import (
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
