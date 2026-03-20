package app

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) ensureSecurityGraph() *graph.Graph {
	if a == nil {
		return nil
	}

	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
		a.configureGraphRuntimeBehavior(a.SecurityGraph)
	}
	return a.SecurityGraph
}

func (a *App) waitForSecurityGraphReady(ctx context.Context) error {
	if a == nil || a.graphReady == nil {
		return nil
	}
	select {
	case <-a.graphReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
