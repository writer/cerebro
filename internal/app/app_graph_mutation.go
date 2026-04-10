package app

import (
	"context"
	"fmt"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	if err := a.requireGraphWriterLease("mutate security graph"); err != nil {
		return nil, err
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

	current, err := a.currentMutableSecurityGraphBase()
	if err != nil {
		return nil, err
	}
	beforeNodeCount := current.NodeCount()
	beforeEdgeCount := current.EdgeCount()
	ctx, span := telemetry.StartSpan(ctx, "cerebro.graph", "cerebro.graph.mutate",
		attribute.Int("cerebro.graph.before_node_count", beforeNodeCount),
		attribute.Int("cerebro.graph.before_edge_count", beforeEdgeCount),
	)
	defer span.End()

	candidate := current.Clone()
	a.configureGraphRuntimeBehavior(candidate)

	changed, err := mutate(candidate)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	span.SetAttributes(attribute.Bool("cerebro.graph.changed", changed))
	if !changed {
		span.SetAttributes(
			attribute.Int("cerebro.graph.before_node_count", beforeNodeCount),
			attribute.Int("cerebro.graph.before_edge_count", beforeEdgeCount),
			attribute.Int("cerebro.graph.after_node_count", beforeNodeCount),
			attribute.Int("cerebro.graph.after_edge_count", beforeEdgeCount),
			attribute.Int("cerebro.graph.mutation_count", 0),
		)
		return current, nil
	}
	if err := ctx.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := a.requireGraphWriterLease("mutate security graph"); err != nil {
		return nil, err
	}

	_, indexSpan := telemetry.StartSpan(ctx, "cerebro.graph", "cerebro.graph.index_update",
		attribute.Int("cerebro.graph.before_node_count", beforeNodeCount),
		attribute.Int("cerebro.graph.before_edge_count", beforeEdgeCount),
	)
	candidate.BuildIndex()
	indexSpan.SetAttributes(
		attribute.Int("cerebro.graph.after_node_count", candidate.NodeCount()),
		attribute.Int("cerebro.graph.after_edge_count", candidate.EdgeCount()),
	)
	indexSpan.End()
	meta := current.Metadata()
	meta.NodeCount = candidate.NodeCount()
	meta.EdgeCount = candidate.EdgeCount()
	candidate.SetMetadata(meta)
	if err := a.syncConfiguredSecurityGraphStore(ctx, candidate); err != nil {
		return nil, err
	}
	if a.SecurityGraphBuilder != nil {
		a.SecurityGraphBuilder.ReplaceGraph(candidate)
	}
	a.publishSecurityGraphRuntimeView(candidate)

	afterNodeCount := candidate.NodeCount()
	afterEdgeCount := candidate.EdgeCount()
	mutationCount := absInt(afterNodeCount-beforeNodeCount) + absInt(afterEdgeCount-beforeEdgeCount)
	span.SetAttributes(
		attribute.Int("cerebro.graph.before_node_count", beforeNodeCount),
		attribute.Int("cerebro.graph.before_edge_count", beforeEdgeCount),
		attribute.Int("cerebro.graph.after_node_count", afterNodeCount),
		attribute.Int("cerebro.graph.after_edge_count", afterEdgeCount),
		attribute.Int("cerebro.graph.mutation_count", mutationCount),
	)
	return candidate, nil
}

func (a *App) currentMutableSecurityGraphBase() (*graph.Graph, error) {
	if a == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	if current := a.CurrentSecurityGraph(); current != nil {
		return current, nil
	}
	stored, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve mutable security graph base", "error", err)
		}
		return nil, fmt.Errorf("security graph not initialized")
	}
	if stored != nil {
		a.configureGraphRuntimeBehavior(stored)
		return stored, nil
	}

	empty := graph.New()
	a.configureGraphRuntimeBehavior(empty)
	return empty, nil
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
