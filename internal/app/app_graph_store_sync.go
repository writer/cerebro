package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) syncConfiguredSecurityGraphStore(ctx context.Context, g *graph.Graph) error {
	if a == nil || a.configuredSecurityGraphStore == nil || g == nil {
		return nil
	}
	if ctx == nil {
		ctx = a.backgroundContext()
	}
	store := a.configuredSecurityGraphStore
	if err := store.EnsureIndexes(ctx); err != nil {
		return fmt.Errorf("ensure configured graph store: %w", err)
	}
	current, err := store.Snapshot(ctx)
	if err != nil && !errors.Is(err, graph.ErrStoreUnavailable) {
		return fmt.Errorf("snapshot configured graph store: %w", err)
	}
	if current == nil {
		current = &graph.Snapshot{
			Version:   "0",
			CreatedAt: time.Now().UTC(),
		}
	}
	desired := graph.CreateSnapshot(g)
	if desired == nil {
		return nil
	}
	diff := graph.DiffSnapshots(current, desired)
	desiredNodes := make(map[string]*graph.Node, len(desired.Nodes))
	for _, node := range desired.Nodes {
		if node == nil || node.ID == "" {
			continue
		}
		desiredNodes[node.ID] = node
	}
	desiredEdges := make(map[string]*graph.Edge, len(desired.Edges))
	for _, edge := range desired.Edges {
		if edge == nil || edge.ID == "" {
			continue
		}
		desiredEdges[edge.ID] = edge
	}

	for _, node := range diff.NodesAdded {
		if desiredNode := desiredNodes[node.ID]; desiredNode != nil {
			if err := store.UpsertNode(ctx, desiredNode); err != nil {
				return fmt.Errorf("upsert configured graph node %s: %w", desiredNode.ID, err)
			}
		}
	}
	for _, change := range diff.NodesModified {
		if desiredNode := desiredNodes[change.NodeID]; desiredNode != nil {
			if err := store.UpsertNode(ctx, desiredNode); err != nil {
				return fmt.Errorf("update configured graph node %s: %w", desiredNode.ID, err)
			}
		}
	}
	for _, edge := range diff.EdgesRemoved {
		if err := store.DeleteEdge(ctx, edge.ID); err != nil {
			return fmt.Errorf("delete configured graph edge %s: %w", edge.ID, err)
		}
	}
	for _, node := range diff.NodesRemoved {
		if err := store.DeleteNode(ctx, node.ID); err != nil {
			return fmt.Errorf("delete configured graph node %s: %w", node.ID, err)
		}
	}
	for _, edge := range diff.EdgesAdded {
		if desiredEdge := desiredEdges[edge.ID]; desiredEdge != nil {
			if err := store.UpsertEdge(ctx, desiredEdge); err != nil {
				return fmt.Errorf("upsert configured graph edge %s: %w", desiredEdge.ID, err)
			}
		}
	}
	a.configuredSecurityGraphReady = true
	return nil
}
