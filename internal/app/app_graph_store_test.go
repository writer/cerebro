package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type recordingSnapshotGraphStore struct {
	graph.GraphStore
	snapshot *graph.Snapshot
	scope    graph.TenantReadScope
}

func (r *recordingSnapshotGraphStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	scope, _ := graph.TenantReadScopeFromContext(ctx)
	r.scope = scope
	return r.snapshot, nil
}

func TestCurrentSecurityGraphStoreTracksLiveGraphSwap(t *testing.T) {
	application := &App{}

	first := graph.New()
	first.AddNode(&graph.Node{ID: "service:first", Kind: graph.NodeKindService})
	application.setSecurityGraph(first)

	store := application.CurrentSecurityGraphStore()
	if store == nil {
		t.Fatal("expected live graph store")
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:first"); err != nil || !ok {
		t.Fatalf("LookupNode(first) = (%v, %v), want present; err=%v", ok, err, err)
	}

	second := graph.New()
	second.AddNode(&graph.Node{ID: "service:second", Kind: graph.NodeKindService})
	application.setSecurityGraph(second)

	if _, ok, err := store.LookupNode(context.Background(), "service:second"); err != nil || !ok {
		t.Fatalf("LookupNode(second) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:first"); err != nil {
		t.Fatalf("LookupNode(first after swap) error = %v", err)
	} else if ok {
		t.Fatal("expected swapped store view to stop serving the old graph")
	}
}

func TestCurrentSecurityGraphStoreUsesConfiguredBackendWhenLiveGraphUnavailable(t *testing.T) {
	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:configured", Kind: graph.NodeKindService})
	configured.BuildIndex()

	application := &App{}
	setConfiguredGraphFromGraph(t, application, configured)

	graphStore := application.CurrentSecurityGraphStore()
	if graphStore == nil {
		t.Fatal("expected graph store wrapper")
	}

	if _, ok, err := graphStore.LookupNode(context.Background(), "service:configured"); err != nil || !ok {
		t.Fatalf("LookupNode(configured) = (%v, %v), want present; err=%v", ok, err, err)
	}
}

func TestCurrentSecurityGraphStorePrefersConfiguredBackendWhenReady(t *testing.T) {
	application := &App{}

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService})
	application.setSecurityGraph(live)

	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:remote", Kind: graph.NodeKindService})
	application.configuredSecurityGraphStore = configured
	application.configuredSecurityGraphReady = true

	store := application.CurrentSecurityGraphStore()
	if store == nil {
		t.Fatal("expected graph store wrapper")
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:remote"); err != nil || !ok {
		t.Fatalf("LookupNode(service:remote) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:live"); err != nil {
		t.Fatalf("LookupNode(service:live) error = %v", err)
	} else if ok {
		t.Fatal("expected configured backend to be preferred over the live graph for reads")
	}
}

func TestTenantGraphStoreResolverCachesScopedStoreUntilSourceChanges(t *testing.T) {
	resolver := &tenantGraphStoreResolver{tenantID: "tenant-a"}
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))

	first, err := resolver.Resolve(context.Background(), source)
	if err != nil {
		t.Fatalf("Resolve(first) error = %v", err)
	}
	second, err := resolver.Resolve(context.Background(), source)
	if err != nil {
		t.Fatalf("Resolve(second) error = %v", err)
	}
	firstGraph, ok := first.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", first)
	}
	secondGraph, ok := second.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", second)
	}
	if firstGraph != secondGraph {
		t.Fatal("expected tenant graph resolver to reuse the scoped graph for the same source")
	}

	source.AddNode(&graph.Node{ID: "service:tenant-a:new", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	third, err := resolver.Resolve(context.Background(), source)
	if err != nil {
		t.Fatalf("Resolve(third) error = %v", err)
	}
	thirdGraph, ok := third.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", third)
	}
	if thirdGraph == secondGraph {
		t.Fatal("expected tenant graph resolver to refresh after the source graph mutates in place")
	}
	if _, ok := thirdGraph.GetNode("service:tenant-a:new"); !ok {
		t.Fatal("expected refreshed tenant graph to include new tenant node after in-place mutation")
	}

	updated := source.Clone()
	updated.AddNode(&graph.Node{ID: "service:tenant-a:next", Kind: graph.NodeKindService, TenantID: "tenant-a"})

	fourth, err := resolver.Resolve(context.Background(), updated)
	if err != nil {
		t.Fatalf("Resolve(fourth) error = %v", err)
	}
	fourthGraph, ok := fourth.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", fourth)
	}
	if fourthGraph == thirdGraph {
		t.Fatal("expected tenant graph resolver to refresh after the source graph changes")
	}
	if _, ok := fourthGraph.GetNode("service:tenant-a:next"); !ok {
		t.Fatal("expected refreshed tenant graph to include new tenant node after source swap")
	}
}

func TestCurrentSecurityGraphStoreForTenantRecognizesNonStringPropertyTenantIDs(t *testing.T) {
	application := &App{}

	source := graph.New()
	source.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService})
	source.AddNode(&graph.Node{
		ID:         "service:tenant-42",
		Kind:       graph.NodeKindService,
		Properties: map[string]any{"tenant_id": 42},
	})
	source.AddNode(&graph.Node{
		ID:         "service:tenant-7",
		Kind:       graph.NodeKindService,
		Properties: map[string]any{"tenant_id": 7},
	})
	source.BuildIndex()
	application.setSecurityGraph(source)

	store := application.CurrentSecurityGraphStoreForTenant("42")
	if store == nil {
		t.Fatal("expected tenant-scoped graph store")
	}

	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-42"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-42) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-7"); err != nil {
		t.Fatalf("LookupNode(tenant-7) error = %v", err)
	} else if ok {
		t.Fatal("expected tenant store to exclude foreign-tenant nodes")
	}
}

func TestTenantSnapshotStoreResolverCachesScopedStoreUntilSnapshotChanges(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	snapshot, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	base := graph.NewSnapshotGraphStore(snapshot)
	resolver := &tenantSnapshotStoreResolver{tenantID: "tenant-a"}

	first, err := resolver.Resolve(context.Background(), base)
	if err != nil {
		t.Fatalf("Resolve(first) error = %v", err)
	}
	second, err := resolver.Resolve(context.Background(), base)
	if err != nil {
		t.Fatalf("Resolve(second) error = %v", err)
	}
	firstGraph, ok := first.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", first)
	}
	secondGraph, ok := second.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", second)
	}
	if firstGraph != secondGraph {
		t.Fatal("expected tenant snapshot resolver to reuse the scoped graph for the same snapshot store")
	}

	updated := source.Clone()
	updated.AddNode(&graph.Node{ID: "service:tenant-a:new", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	updated.BuildIndex()
	nextSnapshot, err := updated.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot(updated) error = %v", err)
	}
	nextBase := graph.NewSnapshotGraphStore(nextSnapshot)

	third, err := resolver.Resolve(context.Background(), nextBase)
	if err != nil {
		t.Fatalf("Resolve(third) error = %v", err)
	}
	thirdGraph, ok := third.(*graph.Graph)
	if !ok {
		t.Fatalf("expected graph-backed tenant store, got %T", third)
	}
	if thirdGraph == secondGraph {
		t.Fatal("expected tenant snapshot resolver to refresh after the snapshot store changes")
	}
	if _, ok := thirdGraph.GetNode("service:tenant-a:new"); !ok {
		t.Fatal("expected refreshed tenant snapshot graph to include new tenant node")
	}
}

func TestCurrentSecurityGraphStoreForTenantScopesAndTracksLiveGraphSwap(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}

	first := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	application.setSecurityGraph(first)

	store := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if store == nil {
		t.Fatal("expected tenant-scoped graph store")
	}

	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-b"); err != nil {
		t.Fatalf("LookupNode(tenant-b) error = %v", err)
	} else if ok {
		t.Fatal("expected tenant store to exclude foreign-tenant nodes")
	}

	next := first.Clone()
	next.AddNode(&graph.Node{ID: "service:tenant-a:new", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	next.BuildIndex()
	next.SetMetadata(graph.Metadata{
		BuiltAt:   time.Date(2026, time.March, 17, 23, 5, 0, 0, time.UTC),
		NodeCount: next.NodeCount(),
		EdgeCount: next.EdgeCount(),
	})
	application.setSecurityGraph(next)

	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a:new"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a:new) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-b"); err != nil {
		t.Fatalf("LookupNode(tenant-b after swap) error = %v", err)
	} else if ok {
		t.Fatal("expected tenant store to remain scoped after source swap")
	}
}

func TestCurrentSecurityGraphStoreForTenantUsesConfiguredBackendWhenLiveGraphUnavailable(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	application := &App{}
	setConfiguredSnapshotGraphFromGraph(t, application, source)

	graphStore := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if graphStore == nil {
		t.Fatal("expected tenant-scoped graph store")
	}

	if _, ok, err := graphStore.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := graphStore.LookupNode(context.Background(), "service:tenant-b"); err != nil {
		t.Fatalf("LookupNode(tenant-b) error = %v", err)
	} else if ok {
		t.Fatal("expected tenant store to exclude foreign-tenant nodes")
	}
}

func TestCurrentSecurityGraphStoreForTenantScopesConfiguredSnapshotReads(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	snapshot, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	recording := &recordingSnapshotGraphStore{
		GraphStore: graph.NewSnapshotGraphStore(snapshot),
		snapshot:   snapshot,
	}
	application := &App{}
	application.configuredSecurityGraphStore = recording
	application.configuredSecurityGraphReady = true

	store := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if store == nil {
		t.Fatal("expected tenant-scoped graph store")
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if got := recording.scope.TenantIDs; !reflect.DeepEqual(got, []string{"tenant-a"}) {
		t.Fatalf("configured snapshot scope = %#v, want [tenant-a]", got)
	}
	if recording.scope.CrossTenant {
		t.Fatalf("configured snapshot scope CrossTenant = true, want false")
	}
}

func TestCurrentSecurityGraphStoreDoesNotFallbackToPersistedSnapshots(t *testing.T) {
	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:persisted", Kind: graph.NodeKindService})
	persisted.BuildIndex()

	application := &App{GraphSnapshots: mustPersistToolGraph(t, persisted)}

	graphStore := application.CurrentSecurityGraphStore()
	if graphStore == nil {
		t.Fatal("expected graph store wrapper")
	}
	if _, _, err := graphStore.LookupNode(context.Background(), "service:persisted"); !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("LookupNode() error = %v, want ErrStoreUnavailable", err)
	}
}

func TestCurrentSecurityGraphStoreForTenantDoesNotFallbackToPersistedSnapshots(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	application := &App{GraphSnapshots: mustPersistToolGraph(t, source)}

	graphStore := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if graphStore == nil {
		t.Fatal("expected tenant-scoped graph store wrapper")
	}
	if _, _, err := graphStore.LookupNode(context.Background(), "service:tenant-a"); !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("LookupNode() error = %v, want ErrStoreUnavailable", err)
	}
}

func TestCurrentSecurityGraphStoreForTenantReturnsUnavailableWhenTenantMissingFromSnapshot(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	application := &App{}
	setConfiguredSnapshotGraphFromGraph(t, application, source)

	graphStore := application.CurrentSecurityGraphStoreForTenant("tenant-missing")
	if graphStore == nil {
		t.Fatal("expected tenant-scoped graph store wrapper")
	}

	if _, _, err := graphStore.LookupNode(context.Background(), "service:shared"); !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("LookupNode() error = %v, want ErrStoreUnavailable", err)
	}
	if err := graphStore.UpsertNode(context.Background(), &graph.Node{ID: "service:tenant-missing", Kind: graph.NodeKindService, TenantID: "tenant-missing"}); !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("UpsertNode() error = %v, want ErrStoreUnavailable", err)
	}
}

func TestCurrentSecurityGraphStoreForTenantUsesWarmShardAfterLiveGraphClear(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	application := &App{
		Config: &Config{
			GraphSnapshotPath:               basePath,
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}

	live := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 15, 0, 0, time.UTC))
	application.setSecurityGraph(live)

	store := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if store == nil {
		t.Fatal("expected tenant-scoped graph store")
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a live) = (%v, %v), want present; err=%v", ok, err, err)
	}

	application.setSecurityGraph(nil)
	application.GraphSnapshots = nil

	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode(tenant-a warm) = (%v, %v), want present; err=%v", ok, err, err)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-b"); err != nil {
		t.Fatalf("LookupNode(tenant-b warm) error = %v", err)
	} else if ok {
		t.Fatal("expected tenant store warm recovery to remain scoped")
	}
}

func TestCurrentWarmTenantGraphStoreUsesSnapshotBackedWarmTierAfterHotEviction(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	application := &App{
		Config: &Config{
			GraphSnapshotPath:               basePath,
			GraphTenantShardIdleTTL:         time.Hour,
			GraphTenantWarmShardTTL:         24 * time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}

	now := time.Date(2026, time.March, 20, 14, 0, 0, 0, time.UTC)
	manager := application.ensureTenantSecurityGraphShards()
	manager.now = func() time.Time { return now }

	live := buildTenantShardTestGraph(time.Date(2026, time.March, 20, 13, 0, 0, 0, time.UTC))
	application.setSecurityGraph(live)
	if scoped := application.CurrentSecurityGraphForTenant("tenant-a"); scoped == nil {
		t.Fatal("expected tenant shard to seed hot and warm tiers")
	}

	now = now.Add(2 * time.Hour)
	if evicted := manager.EvictExpired(now); evicted != 1 {
		t.Fatalf("EvictExpired() = %d, want 1", evicted)
	}
	application.setSecurityGraph(nil)

	store, err := application.currentWarmTenantGraphStore(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("currentWarmTenantGraphStore() error = %v", err)
	}
	if _, ok := store.(*graph.SnapshotGraphStore); !ok {
		t.Fatalf("expected warm-tier store to stay snapshot-backed, got %T", store)
	}
}

func TestCurrentSecurityGraphStoreForTenantRejectsWrites(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	application.setSecurityGraph(source)

	store := application.CurrentSecurityGraphStoreForTenant("tenant-a")
	if store == nil {
		t.Fatal("expected tenant-scoped graph store")
	}

	err := store.UpsertNode(context.Background(), &graph.Node{ID: "service:tenant-a:new", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	if !errors.Is(err, graph.ErrStoreReadOnly) {
		t.Fatalf("UpsertNode() error = %v, want ErrStoreReadOnly", err)
	}
	if _, ok := source.GetNode("service:tenant-a:new"); ok {
		t.Fatal("expected tenant-scoped store write to leave source graph unchanged")
	}
}

func TestCurrentSecurityGraphStoreTreatsConfiguredSnapshotAsReadOnly(t *testing.T) {
	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:configured", Kind: graph.NodeKindService})
	configured.BuildIndex()

	application := &App{}
	setConfiguredSnapshotGraphFromGraph(t, application, configured)

	graphStore := application.CurrentSecurityGraphStore()
	if graphStore == nil {
		t.Fatal("expected graph store wrapper")
	}

	err := graphStore.UpsertNode(context.Background(), &graph.Node{ID: "service:new", Kind: graph.NodeKindService})
	if !errors.Is(err, graph.ErrStoreReadOnly) {
		t.Fatalf("UpsertNode() error = %v, want ErrStoreReadOnly", err)
	}

	if _, ok, err := graphStore.LookupNode(context.Background(), "service:new"); err != nil {
		t.Fatalf("LookupNode(service:new) error = %v", err)
	} else if ok {
		t.Fatal("expected configured snapshot store to remain unchanged after rejected write")
	}
}

func TestCurrentSecurityGraphStoreReturnsUnavailableWhenGraphMissing(t *testing.T) {
	application := &App{}
	store := application.CurrentSecurityGraphStore()
	if store == nil {
		t.Fatal("expected live graph store wrapper")
	}
	if _, _, err := store.LookupNode(context.Background(), "service:none"); !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("LookupNode() error = %v, want ErrStoreUnavailable", err)
	}
}

func TestMutateSecurityGraphSyncsConfiguredBackend(t *testing.T) {
	application := &App{}

	base := graph.New()
	base.AddNode(&graph.Node{ID: "service:existing", Kind: graph.NodeKindService})
	application.setSecurityGraph(base)

	configured := graph.New()
	application.configuredSecurityGraphStore = configured
	application.configuredSecurityGraphReady = false

	mutated, err := application.MutateSecurityGraph(context.Background(), func(g *graph.Graph) error {
		g.AddNode(&graph.Node{ID: "service:new", Kind: graph.NodeKindService, Name: "new"})
		return nil
	})
	if err != nil {
		t.Fatalf("MutateSecurityGraph() error = %v", err)
	}
	if mutated == nil {
		t.Fatal("expected mutated graph")
	}
	if !application.configuredSecurityGraphReady {
		t.Fatal("expected configured graph store to be marked ready after sync")
	}
	if _, ok, err := configured.LookupNode(context.Background(), "service:new"); err != nil || !ok {
		t.Fatalf("configured store LookupNode(service:new) = (%v, %v), want present; err=%v", ok, err, err)
	}
}
