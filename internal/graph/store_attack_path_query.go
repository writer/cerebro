package graph

import "context"

// AttackPathQueryStore exposes store-native attack-path and chokepoint reads
// without requiring callers to materialize a full graph view first.
type AttackPathQueryStore interface {
	AttackPaths(ctx context.Context, maxDepth int) (*SimulationResult, error)
	SimulateAttackPathFix(ctx context.Context, nodeID string, maxDepth int) (*FixSimulation, error)
	Chokepoints(ctx context.Context, maxDepth int) ([]*Chokepoint, error)
}

func AsAttackPathQueryStore(store GraphStore) (AttackPathQueryStore, bool) {
	if store == nil {
		return nil, false
	}
	queryStore, ok := store.(AttackPathQueryStore)
	return queryStore, ok
}

var _ AttackPathQueryStore = (*Graph)(nil)
var _ AttackPathQueryStore = (*SnapshotGraphStore)(nil)
var _ AttackPathQueryStore = (*TenantScopedReadOnlyGraphStore)(nil)
var _ AttackPathQueryStore = (*NeptuneGraphStore)(nil)

func (g *Graph) AttackPaths(ctx context.Context, maxDepth int) (*SimulationResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrStoreUnavailable
	}
	return NewAttackPathSimulator(g).Simulate(maxDepth), nil
}

func (g *Graph) SimulateAttackPathFix(ctx context.Context, nodeID string, maxDepth int) (*FixSimulation, error) {
	result, err := g.AttackPaths(ctx, maxDepth)
	if err != nil {
		return nil, err
	}
	return (&AttackPathSimulator{}).SimulateFix(result, nodeID), nil
}

func (g *Graph) Chokepoints(ctx context.Context, maxDepth int) ([]*Chokepoint, error) {
	result, err := g.AttackPaths(ctx, maxDepth)
	if err != nil {
		return nil, err
	}
	return append([]*Chokepoint(nil), result.Chokepoints...), nil
}

func (s *SnapshotGraphStore) AttackPaths(ctx context.Context, maxDepth int) (*SimulationResult, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.AttackPaths(ctx, maxDepth)
}

func (s *SnapshotGraphStore) SimulateAttackPathFix(ctx context.Context, nodeID string, maxDepth int) (*FixSimulation, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.SimulateAttackPathFix(ctx, nodeID, maxDepth)
}

func (s *SnapshotGraphStore) Chokepoints(ctx context.Context, maxDepth int) ([]*Chokepoint, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.Chokepoints(ctx, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) AttackPaths(ctx context.Context, maxDepth int) (*SimulationResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return SimulateAttackPathsFromStore(s.scopeContext(ctx), s.store, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) SimulateAttackPathFix(ctx context.Context, nodeID string, maxDepth int) (*FixSimulation, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return SimulateAttackPathFixFromStore(s.scopeContext(ctx), s.store, nodeID, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) Chokepoints(ctx context.Context, maxDepth int) ([]*Chokepoint, error) {
	result, err := s.AttackPaths(ctx, maxDepth)
	if err != nil {
		return nil, err
	}
	return append([]*Chokepoint(nil), result.Chokepoints...), nil
}

func (s *NeptuneGraphStore) AttackPaths(ctx context.Context, maxDepth int) (*SimulationResult, error) {
	return SimulateAttackPathsFromStore(ctx, s, maxDepth)
}

func (s *NeptuneGraphStore) SimulateAttackPathFix(ctx context.Context, nodeID string, maxDepth int) (*FixSimulation, error) {
	return SimulateAttackPathFixFromStore(ctx, s, nodeID, maxDepth)
}

func (s *NeptuneGraphStore) Chokepoints(ctx context.Context, maxDepth int) ([]*Chokepoint, error) {
	result, err := s.AttackPaths(ctx, maxDepth)
	if err != nil {
		return nil, err
	}
	return append([]*Chokepoint(nil), result.Chokepoints...), nil
}
