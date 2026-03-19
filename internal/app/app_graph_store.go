package app

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

type liveGraphStore struct {
	current  func() *graph.Graph
	fallback func() (*graph.Graph, error)
	writable bool
}

func (a *App) CurrentSecurityGraphStore() graph.GraphStore {
	if a == nil {
		return nil
	}
	return liveGraphStore{
		current: a.CurrentSecurityGraph,
		fallback: func() (*graph.Graph, error) {
			return a.storedPassiveSecurityGraphView()
		},
		writable: true,
	}
}

func (a *App) CurrentSecurityGraphStoreForTenant(tenantID string) graph.GraphStore {
	if a == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return a.CurrentSecurityGraphStore()
	}
	return liveGraphStore{
		current: func() *graph.Graph {
			if a.CurrentSecurityGraph() == nil {
				return nil
			}
			return a.CurrentSecurityGraphForTenant(tenantID)
		},
		fallback: func() (*graph.Graph, error) {
			view, err := a.storedPassiveSecurityGraphView()
			if err != nil || view == nil {
				return view, err
			}
			return view.SubgraphForTenant(tenantID), nil
		},
		writable: false,
	}
}

func (s liveGraphStore) UpsertNode(ctx context.Context, node *graph.Node) error {
	g, err := s.currentGraphForWrite(ctx)
	if err != nil {
		return err
	}
	return g.UpsertNode(ctx, node)
}

func (s liveGraphStore) UpsertNodesBatch(ctx context.Context, nodes []*graph.Node) error {
	g, err := s.currentGraphForWrite(ctx)
	if err != nil {
		return err
	}
	return g.UpsertNodesBatch(ctx, nodes)
}

func (s liveGraphStore) UpsertEdge(ctx context.Context, edge *graph.Edge) error {
	g, err := s.currentGraphForWrite(ctx)
	if err != nil {
		return err
	}
	return g.UpsertEdge(ctx, edge)
}

func (s liveGraphStore) UpsertEdgesBatch(ctx context.Context, edges []*graph.Edge) error {
	g, err := s.currentGraphForWrite(ctx)
	if err != nil {
		return err
	}
	return g.UpsertEdgesBatch(ctx, edges)
}

func (s liveGraphStore) DeleteNode(ctx context.Context, id string) error {
	g, err := s.currentGraphForWrite(ctx)
	if err != nil {
		return err
	}
	return g.DeleteNode(ctx, id)
}

func (s liveGraphStore) LookupNode(ctx context.Context, id string) (*graph.Node, bool, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, false, err
	}
	return g.LookupNode(ctx, id)
}

func (s liveGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*graph.Edge, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.LookupOutEdges(ctx, nodeID)
}

func (s liveGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*graph.Edge, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.LookupInEdges(ctx, nodeID)
}

func (s liveGraphStore) LookupNodesByKind(ctx context.Context, kinds ...graph.NodeKind) ([]*graph.Node, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.LookupNodesByKind(ctx, kinds...)
}

func (s liveGraphStore) CountNodes(ctx context.Context) (int, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return 0, err
	}
	return g.CountNodes(ctx)
}

func (s liveGraphStore) CountEdges(ctx context.Context) (int, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return 0, err
	}
	return g.CountEdges(ctx)
}

func (s liveGraphStore) EnsureIndexes(ctx context.Context) error {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return err
	}
	return g.EnsureIndexes(ctx)
}

func (s liveGraphStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.Snapshot(ctx)
}

func (s liveGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*graph.BlastRadiusResult, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.BlastRadius(ctx, principalID, maxDepth)
}

func (s liveGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*graph.ReverseAccessResult, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.ReverseAccess(ctx, resourceID, maxDepth)
}

func (s liveGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*graph.EffectiveAccessResult, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
}

func (s liveGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*graph.CascadingBlastRadiusResult, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.CascadingBlastRadius(ctx, sourceID, maxDepth)
}

func (s liveGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts graph.ExtractSubgraphOptions) (*graph.Graph, error) {
	g, err := s.currentGraph(ctx)
	if err != nil {
		return nil, err
	}
	return g.ExtractSubgraph(ctx, rootID, opts)
}

func (s liveGraphStore) currentGraph(ctx context.Context) (*graph.Graph, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if s.current != nil {
		g := s.current()
		if g != nil {
			return g, nil
		}
	}
	if s.fallback != nil {
		g, err := s.fallback()
		if err != nil {
			return nil, err
		}
		if g != nil {
			return g, nil
		}
	}
	return nil, graph.ErrStoreUnavailable
}

func (s liveGraphStore) currentGraphForWrite(ctx context.Context) (*graph.Graph, error) {
	if !s.writable {
		if err := graphStoreContextErr(ctx); err != nil {
			return nil, err
		}
		return nil, graph.ErrStoreReadOnly
	}
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s.current != nil {
		g := s.current()
		if g != nil {
			return g, nil
		}
	}
	if s.fallback != nil {
		g, err := s.fallback()
		if err != nil {
			return nil, err
		}
		if g != nil {
			return nil, graph.ErrStoreReadOnly
		}
	}
	return nil, graph.ErrStoreUnavailable
}

func graphStoreContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
