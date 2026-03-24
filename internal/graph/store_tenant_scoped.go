package graph

import (
	"context"
)

type TenantScopeAwareGraphStore interface {
	SupportsTenantReadScope() bool
}

func SupportsTenantReadScope(store GraphStore) bool {
	if store == nil {
		return false
	}
	scoped, ok := store.(TenantScopeAwareGraphStore)
	return ok && scoped.SupportsTenantReadScope()
}

type TenantScopedReadOnlyGraphStore struct {
	store    GraphStore
	tenantID string
}

var _ GraphStore = (*TenantScopedReadOnlyGraphStore)(nil)
var _ TenantScopeAwareGraphStore = (*TenantScopedReadOnlyGraphStore)(nil)

func NewTenantScopedReadOnlyGraphStore(store GraphStore, tenantID string) *TenantScopedReadOnlyGraphStore {
	return &TenantScopedReadOnlyGraphStore{
		store:    store,
		tenantID: tenantID,
	}
}

func (s *TenantScopedReadOnlyGraphStore) SupportsTenantReadScope() bool {
	if s == nil {
		return false
	}
	return SupportsTenantReadScope(s.store)
}

func (s *TenantScopedReadOnlyGraphStore) UpsertNode(ctx context.Context, _ *Node) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) UpsertNodesBatch(ctx context.Context, _ []*Node) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) UpsertEdge(ctx context.Context, _ *Edge) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) UpsertEdgesBatch(ctx context.Context, _ []*Edge) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) DeleteNode(ctx context.Context, _ string) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) DeleteEdge(ctx context.Context, _ string) error {
	return tenantScopedReadOnlyGraphStoreWriteErr(ctx, s)
}

func (s *TenantScopedReadOnlyGraphStore) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.store == nil {
		return nil, false, ErrStoreUnavailable
	}
	return s.store.LookupNode(s.scopeContext(ctx), id)
}

func (s *TenantScopedReadOnlyGraphStore) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.store == nil {
		return nil, false, ErrStoreUnavailable
	}
	return s.store.LookupEdge(s.scopeContext(ctx), id)
}

func (s *TenantScopedReadOnlyGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.LookupOutEdges(s.scopeContext(ctx), nodeID)
}

func (s *TenantScopedReadOnlyGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.LookupInEdges(s.scopeContext(ctx), nodeID)
}

func (s *TenantScopedReadOnlyGraphStore) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.LookupNodesByKind(s.scopeContext(ctx), kinds...)
}

func (s *TenantScopedReadOnlyGraphStore) CountNodes(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.store == nil {
		return 0, ErrStoreUnavailable
	}
	return s.store.CountNodes(s.scopeContext(ctx))
}

func (s *TenantScopedReadOnlyGraphStore) CountEdges(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.store == nil {
		return 0, ErrStoreUnavailable
	}
	return s.store.CountEdges(s.scopeContext(ctx))
}

func (s *TenantScopedReadOnlyGraphStore) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil {
		return ErrStoreUnavailable
	}
	return s.store.EnsureIndexes(s.scopeContext(ctx))
}

func (s *TenantScopedReadOnlyGraphStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.Snapshot(s.scopeContext(ctx))
}

func (s *TenantScopedReadOnlyGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.BlastRadius(s.scopeContext(ctx), principalID, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.ReverseAccess(s.scopeContext(ctx), resourceID, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.EffectiveAccess(s.scopeContext(ctx), principalID, resourceID, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.CascadingBlastRadius(s.scopeContext(ctx), sourceID, maxDepth)
}

func (s *TenantScopedReadOnlyGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.ExtractSubgraph(s.scopeContext(ctx), rootID, opts)
}

func (s *TenantScopedReadOnlyGraphStore) scopeContext(ctx context.Context) context.Context {
	if s == nil {
		return ctx
	}
	return WithTenantScope(ctx, s.tenantID)
}

func tenantScopedReadOnlyGraphStoreWriteErr(ctx context.Context, store *TenantScopedReadOnlyGraphStore) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if store == nil || store.store == nil {
		return ErrStoreUnavailable
	}
	return ErrStoreReadOnly
}
