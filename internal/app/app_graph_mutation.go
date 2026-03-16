package app

import (
	"context"
	"fmt"

	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) MutateSecurityGraph(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	return a.MutateSecurityGraphMaybe(ctx, func(g *graph.Graph) (bool, error) {
		if err := mutate(g); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (a *App) MutateSecurityGraphMaybe(ctx context.Context, mutate func(*graph.Graph) (bool, error)) (*graph.Graph, error) {
	if a == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	if mutate == nil {
		return a.CurrentSecurityGraph(), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	a.graphUpdateMu.Lock()
	defer a.graphUpdateMu.Unlock()

	current := a.CurrentSecurityGraph()
	if current == nil {
		current = graph.New()
		a.configureGraphRuntimeBehavior(current)
	}

	candidate := current.Clone()
	a.configureGraphRuntimeBehavior(candidate)

	changed, err := mutate(candidate)
	if err != nil {
		return nil, err
	}
	if !changed {
		return current, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	candidate.BuildIndex()
	meta := current.Metadata()
	meta.NodeCount = candidate.NodeCount()
	meta.EdgeCount = candidate.EdgeCount()
	candidate.SetMetadata(meta)
	a.setSecurityGraph(candidate)
	return candidate, nil
}
