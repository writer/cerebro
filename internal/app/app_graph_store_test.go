package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

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

func TestCurrentSecurityGraphStoreUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:persisted", Kind: graph.NodeKindService})
	persisted.BuildIndex()

	store := mustPersistToolGraph(t, persisted)
	application := &App{GraphSnapshots: store}

	graphStore := application.CurrentSecurityGraphStore()
	if graphStore == nil {
		t.Fatal("expected graph store wrapper")
	}

	if _, ok, err := graphStore.LookupNode(context.Background(), "service:persisted"); err != nil || !ok {
		t.Fatalf("LookupNode(persisted) = (%v, %v), want present; err=%v", ok, err, err)
	}

	status := store.Status()
	if status.LastRecoveredSnapshot != "" || status.LastRecoverySource != "" {
		t.Fatalf("expected passive snapshot read to avoid recovery bookkeeping, got %+v", status)
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

func TestCurrentSecurityGraphStoreForTenantUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	source := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC))
	store := mustPersistToolGraph(t, source)
	application := &App{GraphSnapshots: store}

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

	status := store.Status()
	if status.LastRecoveredSnapshot != "" || status.LastRecoverySource != "" {
		t.Fatalf("expected passive snapshot read to avoid recovery bookkeeping, got %+v", status)
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

func TestCurrentSecurityGraphStoreTreatsPersistedSnapshotAsReadOnly(t *testing.T) {
	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:persisted", Kind: graph.NodeKindService})
	persisted.BuildIndex()

	store := mustPersistToolGraph(t, persisted)
	application := &App{GraphSnapshots: store}

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
		t.Fatal("expected persisted snapshot fallback to remain unchanged after rejected write")
	}

	status := store.Status()
	if status.LastRecoveredSnapshot != "" || status.LastRecoverySource != "" {
		t.Fatalf("expected passive snapshot fallback to avoid recovery bookkeeping, got %+v", status)
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
