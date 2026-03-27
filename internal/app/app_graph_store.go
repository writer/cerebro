package app

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/graph"
)

type graphStoreLayer struct {
	writable bool
	resolve  func(context.Context) (graph.GraphStore, error)
}

type tieredGraphStore struct {
	layers []graphStoreLayer
}

type tenantGraphStoreResolver struct {
	tenantID string

	mu          sync.RWMutex
	source      *graph.Graph
	sourceVer   uint64
	store       graph.GraphStore
	unavailable bool
}

type tenantSnapshotStoreResolver struct {
	tenantID string

	mu          sync.RWMutex
	source      *graph.SnapshotGraphStore
	store       graph.GraphStore
	unavailable bool
}

func (a *App) CurrentSecurityGraphStore() graph.GraphStore {
	if a == nil {
		return nil
	}
	layers := make([]graphStoreLayer, 0, 3)
	layers = append(layers, graphStoreLayer{
		writable: true,
		resolve: func(ctx context.Context) (graph.GraphStore, error) {
			return a.currentConfiguredSecurityGraphStore(ctx)
		},
	})
	layers = append(layers, graphStoreLayer{
		writable: true,
		resolve: func(ctx context.Context) (graph.GraphStore, error) {
			return resolveCurrentGraphStore(ctx, a.currentLiveSecurityGraph())
		},
	})
	layers = append(layers, graphStoreLayer{
		resolve: func(ctx context.Context) (graph.GraphStore, error) {
			return a.currentPassiveSnapshotStore(ctx)
		},
	})
	return tieredGraphStore{layers: layers}
}

func (a *App) CurrentSecurityGraphStoreForTenant(tenantID string) graph.GraphStore {
	if a == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return a.CurrentSecurityGraphStore()
	}
	liveResolver := &tenantGraphStoreResolver{tenantID: tenantID}
	passiveResolver := &tenantSnapshotStoreResolver{tenantID: tenantID}
	return tieredGraphStore{
		layers: []graphStoreLayer{
			{
				resolve: func(ctx context.Context) (graph.GraphStore, error) {
					store, err := a.currentConfiguredSnapshotGraphStore(graph.WithTenantScope(ctx, tenantID))
					if err != nil {
						return nil, err
					}
					return passiveResolver.Resolve(ctx, store)
				},
			},
			{
				resolve: func(ctx context.Context) (graph.GraphStore, error) {
					return liveResolver.ResolveCurrent(ctx, a.currentLiveSecurityGraph(), func() *graph.Graph {
						return a.CurrentSecurityGraphForTenant(tenantID)
					})
				},
			},
			{
				resolve: func(ctx context.Context) (graph.GraphStore, error) {
					return a.currentWarmTenantGraphStore(ctx, tenantID)
				},
			},
			{
				resolve: func(ctx context.Context) (graph.GraphStore, error) {
					store, err := a.currentPassiveSnapshotGraphStore(ctx)
					if err != nil {
						return nil, err
					}
					return passiveResolver.Resolve(ctx, store)
				},
			},
		},
	}
}

func (s tieredGraphStore) UpsertNode(ctx context.Context, node *graph.Node) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.UpsertNode(ctx, node)
}

func (s tieredGraphStore) UpsertNodesBatch(ctx context.Context, nodes []*graph.Node) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.UpsertNodesBatch(ctx, nodes)
}

func (s tieredGraphStore) UpsertEdge(ctx context.Context, edge *graph.Edge) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.UpsertEdge(ctx, edge)
}

func (s tieredGraphStore) UpsertEdgesBatch(ctx context.Context, edges []*graph.Edge) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.UpsertEdgesBatch(ctx, edges)
}

func (s tieredGraphStore) DeleteNode(ctx context.Context, id string) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.DeleteNode(ctx, id)
}

func (s tieredGraphStore) DeleteEdge(ctx context.Context, id string) error {
	store, err := s.currentGraphStoreForWrite(ctx)
	if err != nil {
		return err
	}
	return store.DeleteEdge(ctx, id)
}

func (s tieredGraphStore) LookupNode(ctx context.Context, id string) (*graph.Node, bool, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, false, err
	}
	return store.LookupNode(ctx, id)
}

func (s tieredGraphStore) LookupEdge(ctx context.Context, id string) (*graph.Edge, bool, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, false, err
	}
	return store.LookupEdge(ctx, id)
}

func (s tieredGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*graph.Edge, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.LookupOutEdges(ctx, nodeID)
}

func (s tieredGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*graph.Edge, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.LookupInEdges(ctx, nodeID)
}

func (s tieredGraphStore) LookupNodesByKind(ctx context.Context, kinds ...graph.NodeKind) ([]*graph.Node, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.LookupNodesByKind(ctx, kinds...)
}

func (s tieredGraphStore) CountNodes(ctx context.Context) (int, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return 0, err
	}
	return store.CountNodes(ctx)
}

func (s tieredGraphStore) CountEdges(ctx context.Context) (int, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return 0, err
	}
	return store.CountEdges(ctx)
}

func (s tieredGraphStore) EnsureIndexes(ctx context.Context) error {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return err
	}
	return store.EnsureIndexes(ctx)
}

func (s tieredGraphStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.Snapshot(ctx)
}

func (s tieredGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*graph.BlastRadiusResult, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.BlastRadius(ctx, principalID, maxDepth)
}

func (s tieredGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*graph.ReverseAccessResult, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.ReverseAccess(ctx, resourceID, maxDepth)
}

func (s tieredGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*graph.EffectiveAccessResult, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
}

func (s tieredGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*graph.CascadingBlastRadiusResult, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.CascadingBlastRadius(ctx, sourceID, maxDepth)
}

func (s tieredGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts graph.ExtractSubgraphOptions) (*graph.Graph, error) {
	store, err := s.currentGraphStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.ExtractSubgraph(ctx, rootID, opts)
}

func (s tieredGraphStore) currentGraphStore(ctx context.Context) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	for _, layer := range s.layers {
		if layer.resolve == nil {
			continue
		}
		store, err := layer.resolve(ctx)
		switch {
		case err == nil && store != nil:
			return store, nil
		case errors.Is(err, graph.ErrStoreUnavailable):
			continue
		case err != nil:
			return nil, err
		}
	}
	return nil, graph.ErrStoreUnavailable
}

func (s tieredGraphStore) currentGraphStoreForWrite(ctx context.Context) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	for _, layer := range s.layers {
		if layer.resolve == nil {
			continue
		}
		store, err := layer.resolve(ctx)
		switch {
		case err == nil && store != nil && layer.writable:
			return store, nil
		case err == nil && store != nil:
			return nil, graph.ErrStoreReadOnly
		case errors.Is(err, graph.ErrStoreUnavailable):
			continue
		case err != nil:
			return nil, err
		}
	}
	return nil, graph.ErrStoreUnavailable
}

func resolveCurrentGraphStore(ctx context.Context, current *graph.Graph) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if current == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return current, nil
}

func (a *App) currentConfiguredSecurityGraphStore(ctx context.Context) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.configuredSecurityGraphStore == nil || !a.configuredSecurityGraphReady {
		return nil, graph.ErrStoreUnavailable
	}
	return a.configuredSecurityGraphStore, nil
}

func resolveTenantGraphStore(ctx context.Context, current *graph.Graph, tenantID string) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if current == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return current, nil
	}
	if !current.HasScopedNodesForTenant(tenantID) {
		return nil, graph.ErrStoreUnavailable
	}
	scoped, hasScopedNodes := current.SubgraphForTenantWithScopedNodes(tenantID)
	if !hasScopedNodes {
		return nil, graph.ErrStoreUnavailable
	}
	return scoped, nil
}

func (r *tenantGraphStoreResolver) Resolve(ctx context.Context, current *graph.Graph) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if current == nil {
		return nil, graph.ErrStoreUnavailable
	}
	version := current.CurrentVersion()
	if store, unavailable, ok := r.cached(current, version); ok {
		if unavailable || store == nil {
			return nil, graph.ErrStoreUnavailable
		}
		return store, nil
	}
	store, err := resolveTenantGraphStore(ctx, current, r.tenantID)
	switch {
	case err == nil && store != nil:
		r.storeResult(current, version, store, false)
		return store, nil
	case errors.Is(err, graph.ErrStoreUnavailable):
		r.storeResult(current, version, nil, true)
		return nil, graph.ErrStoreUnavailable
	default:
		return nil, err
	}
}

func (r *tenantGraphStoreResolver) ResolveCurrent(ctx context.Context, current *graph.Graph, currentForTenant func() *graph.Graph) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if current == nil {
		return nil, graph.ErrStoreUnavailable
	}
	version := current.CurrentVersion()
	if store, unavailable, ok := r.cached(current, version); ok {
		if unavailable || store == nil {
			return nil, graph.ErrStoreUnavailable
		}
		return store, nil
	}
	if !current.HasScopedNodesForTenant(r.tenantID) {
		r.storeResult(current, version, nil, true)
		return nil, graph.ErrStoreUnavailable
	}
	store, err := resolveCurrentGraphStore(ctx, currentForTenant())
	switch {
	case err == nil && store != nil:
		r.storeResult(current, version, store, false)
		return store, nil
	case errors.Is(err, graph.ErrStoreUnavailable):
		r.storeResult(current, version, nil, true)
		return nil, graph.ErrStoreUnavailable
	default:
		return nil, err
	}
}

func (r *tenantGraphStoreResolver) cached(current *graph.Graph, version uint64) (graph.GraphStore, bool, bool) {
	if r == nil || current == nil {
		return nil, false, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.source != current || r.sourceVer != version {
		return nil, false, false
	}
	return r.store, r.unavailable, true
}

func (r *tenantGraphStoreResolver) storeResult(current *graph.Graph, version uint64, store graph.GraphStore, unavailable bool) {
	if r == nil || current == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.source = current
	r.sourceVer = version
	r.store = store
	r.unavailable = unavailable
}

func (a *App) currentPassiveSnapshotStore(ctx context.Context) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.GraphSnapshots == nil {
		return nil, graph.ErrStoreUnavailable
	}
	snapshotStore := a.GraphSnapshots
	if cached := a.cachedPassiveSnapshotStore(snapshotStore); cached != nil {
		return cached, nil
	}
	a.passiveSnapshotStoreMu.Lock()
	defer a.passiveSnapshotStoreMu.Unlock()
	if cached := a.cachedPassiveSnapshotStoreLocked(snapshotStore); cached != nil {
		return cached, nil
	}
	snapshot, record, source, err := snapshotStore.PeekLatestSnapshot()
	if err != nil {
		if isNoSnapshotsGraphStoreErr(err) {
			return nil, graph.ErrStoreUnavailable
		}
		return nil, err
	}
	if snapshot == nil {
		return nil, graph.ErrStoreUnavailable
	}
	store := graph.NewSnapshotGraphStore(snapshot)
	status := snapshotStore.Status()
	a.passiveSnapshotStoreOwner = snapshotStore
	a.passiveSnapshotStoreSource = strings.TrimSpace(source)
	a.passiveSnapshotStoreID = passiveSnapshotStoreCacheID(a.passiveSnapshotStoreSource, record, status)
	a.passiveSnapshotStoreStatusID = passiveSnapshotStoreCacheID(a.passiveSnapshotStoreSource, nil, status)
	a.passiveSnapshotStore = store
	return store, nil
}

func (a *App) currentPassiveSnapshotGraphStore(ctx context.Context) (*graph.SnapshotGraphStore, error) {
	store, err := a.currentPassiveSnapshotStore(ctx)
	if err != nil {
		return nil, err
	}
	snapshotStore, ok := store.(*graph.SnapshotGraphStore)
	if !ok || snapshotStore == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return snapshotStore, nil
}

func (a *App) currentConfiguredSnapshotGraphStore(ctx context.Context) (*graph.SnapshotGraphStore, error) {
	snapshot, err := a.currentConfiguredSecurityGraphSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return graph.NewSnapshotGraphStore(snapshot), nil
}

func (a *App) currentWarmTenantGraphStore(ctx context.Context, tenantID string) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if a == nil || !a.retainHotSecurityGraph() {
		return nil, graph.ErrStoreUnavailable
	}
	manager := a.ensureTenantSecurityGraphShards()
	if manager == nil {
		return nil, graph.ErrStoreUnavailable
	}
	scoped := manager.WarmStoreForTenant(tenantID)
	if scoped == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return scoped, nil
}

func (r *tenantSnapshotStoreResolver) Resolve(ctx context.Context, store *graph.SnapshotGraphStore) (graph.GraphStore, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, graph.ErrStoreUnavailable
	}
	if cached, unavailable, ok := r.cached(store); ok {
		if unavailable || cached == nil {
			return nil, graph.ErrStoreUnavailable
		}
		return cached, nil
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			r.storeResult(store, nil, true)
		}
		return nil, err
	}
	view := graph.GraphViewFromSnapshot(snapshot)
	scoped, err := resolveTenantGraphStore(ctx, view, r.tenantID)
	switch {
	case err == nil && scoped != nil:
		r.storeResult(store, scoped, false)
		return scoped, nil
	case errors.Is(err, graph.ErrStoreUnavailable):
		r.storeResult(store, nil, true)
		return nil, graph.ErrStoreUnavailable
	default:
		return nil, err
	}
}

func (r *tenantSnapshotStoreResolver) cached(store *graph.SnapshotGraphStore) (graph.GraphStore, bool, bool) {
	if r == nil || store == nil {
		return nil, false, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.source != store {
		return nil, false, false
	}
	return r.store, r.unavailable, true
}

func (r *tenantSnapshotStoreResolver) storeResult(source *graph.SnapshotGraphStore, store graph.GraphStore, unavailable bool) {
	if r == nil || source == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.source = source
	r.store = store
	r.unavailable = unavailable
}

func graphStoreContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func isNoSnapshotsGraphStoreErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no snapshots found")
}

func (a *App) cachedPassiveSnapshotStore(store *graph.GraphPersistenceStore) *graph.SnapshotGraphStore {
	if a == nil || store == nil {
		return nil
	}
	a.passiveSnapshotStoreMu.RLock()
	defer a.passiveSnapshotStoreMu.RUnlock()
	return a.cachedPassiveSnapshotStoreLocked(store)
}

func (a *App) cachedPassiveSnapshotStoreLocked(store *graph.GraphPersistenceStore) *graph.SnapshotGraphStore {
	if a == nil || store == nil || a.passiveSnapshotStore == nil {
		return nil
	}
	if a.passiveSnapshotStoreOwner != store {
		return nil
	}
	cacheID := passiveSnapshotStoreCacheID(a.passiveSnapshotStoreSource, nil, store.Status())
	if cacheID != "" && cacheID != a.passiveSnapshotStoreID && cacheID != a.passiveSnapshotStoreStatusID {
		return nil
	}
	return a.passiveSnapshotStore
}

func passiveSnapshotStoreCacheID(source string, record *graph.GraphSnapshotRecord, status graph.GraphPersistenceStatus) string {
	if record != nil {
		if id := strings.TrimSpace(record.ID); id != "" {
			return id
		}
	}
	_ = source
	return strings.TrimSpace(status.LastPersistedSnapshot)
}
