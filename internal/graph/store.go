package graph

import (
	"context"
	"errors"
)

// ErrStoreUnavailable is returned when a live graph-backed store has no active
// graph to service the request.
var ErrStoreUnavailable = errors.New("graph store unavailable")

// ErrStoreReadOnly is returned when a caller attempts to mutate a read-only
// graph store view, such as a tenant-scoped projection backed by ephemeral
// subgraph extraction.
var ErrStoreReadOnly = errors.New("graph store is read-only")

// GraphStore defines the first migration seam between the current in-memory
// graph engine and future external graph backends.
//
// The in-memory *Graph implements this contract directly so app/api code can
// begin depending on a store abstraction without changing existing graph
// internals first.
type GraphStore interface {
	UpsertNode(ctx context.Context, node *Node) error
	UpsertNodesBatch(ctx context.Context, nodes []*Node) error
	UpsertEdge(ctx context.Context, edge *Edge) error
	UpsertEdgesBatch(ctx context.Context, edges []*Edge) error
	DeleteNode(ctx context.Context, id string) error

	LookupNode(ctx context.Context, id string) (*Node, bool, error)
	LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error)
	LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error)
	LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error)
	CountNodes(ctx context.Context) (int, error)
	CountEdges(ctx context.Context) (int, error)
	EnsureIndexes(ctx context.Context) error

	Snapshot(ctx context.Context) (*Snapshot, error)
	BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error)
	EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error)
	CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error)
	ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error)
}

var _ GraphStore = (*Graph)(nil)

func (g *Graph) UpsertNode(ctx context.Context, node *Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.AddNode(node)
	return nil
}

func (g *Graph) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.AddNodesBatch(nodes)
	return nil
}

func (g *Graph) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.AddEdge(edge)
	return nil
}

func (g *Graph) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.AddEdgesBatch(edges)
	return nil
}

func (g *Graph) DeleteNode(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.RemoveNode(id)
	return nil
}

func (g *Graph) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if g == nil {
		return nil, false, ErrStoreUnavailable
	}
	node, ok := g.GetNode(id)
	return node, ok, nil
}

func (g *Graph) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return g.GetOutEdges(nodeID), nil
}

func (g *Graph) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return g.GetInEdges(nodeID), nil
}

func (g *Graph) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return g.GetNodesByKind(kinds...), nil
}

func (g *Graph) CountNodes(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if g == nil {
		return 0, ErrStoreUnavailable
	}
	return g.NodeCount(), nil
}

func (g *Graph) CountEdges(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if g == nil {
		return 0, ErrStoreUnavailable
	}
	return g.EdgeCount(), nil
}

func (g *Graph) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrStoreUnavailable
	}
	g.BuildIndex()
	return nil
}

func (g *Graph) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return CreateSnapshot(g), nil
}

func (g *Graph) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return BlastRadius(g, principalID, maxDepth), nil
}

func (g *Graph) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return EffectiveAccess(g, principalID, resourceID, maxDepth), nil
}

func (g *Graph) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return CascadingBlastRadius(g, sourceID, maxDepth), nil
}

func (g *Graph) ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return ExtractSubgraph(g, rootID, opts), nil
}

func graphStoreContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
