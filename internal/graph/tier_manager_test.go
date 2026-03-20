package graph

import (
	"context"
	"testing"
	"time"
)

func TestTierManagerDemotesExpiredHotGraphsToWarmAndReloadsLazily(t *testing.T) {
	now := time.Date(2026, time.March, 20, 10, 0, 0, 0, time.UTC)
	manager := NewTierManager(TierManagerOptions{
		HotRetention:     time.Hour,
		WarmRetention:    24 * time.Hour,
		HotMaxEntries:    4,
		WarmBasePath:     t.TempDir(),
		WarmMaxSnapshots: 1,
		Now: func() time.Time {
			return now
		},
	})

	live := buildTierManagerTestGraph("service:tenant-a")
	manager.PromoteHot("gen-a", "tenant-a", live, now)
	if got := manager.HotGraph("gen-a", "tenant-a"); got != live {
		t.Fatalf("HotGraph() = %p, want %p", got, live)
	}

	now = now.Add(2 * time.Hour)
	if evicted := manager.Evict(now); evicted != 1 {
		t.Fatalf("Evict() = %d, want 1", evicted)
	}
	if got := manager.HotGraph("gen-a", "tenant-a"); got != nil {
		t.Fatalf("expected hot entry to demote to warm, got %p", got)
	}

	store, ok := manager.WarmStore("gen-a", "tenant-a").(*SnapshotGraphStore)
	if !ok || store == nil {
		t.Fatal("expected warm snapshot-backed store")
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode() = (%v, %v), want present; err=%v", ok, err, err)
	}
	if store.view != nil {
		t.Fatal("expected warm-tier point lookups not to hydrate a full graph view")
	}

	rehydrated := manager.WarmGraph("gen-a", "tenant-a")
	if rehydrated == nil {
		t.Fatal("expected warm-tier hydration to rebuild a graph")
	}
	if rehydrated == live {
		t.Fatal("expected warm-tier hydration to return a new graph instance")
	}
	if _, ok := rehydrated.GetNode("service:tenant-a"); !ok {
		t.Fatal("expected warm-tier hydration to preserve tenant node")
	}
}

func TestTierManagerEvictsLeastRecentlyUsedHotGraphToWarm(t *testing.T) {
	now := time.Date(2026, time.March, 20, 11, 0, 0, 0, time.UTC)
	manager := NewTierManager(TierManagerOptions{
		HotRetention:     12 * time.Hour,
		WarmRetention:    24 * time.Hour,
		HotMaxEntries:    1,
		WarmBasePath:     t.TempDir(),
		WarmMaxSnapshots: 1,
		Now: func() time.Time {
			return now
		},
	})

	first := buildTierManagerTestGraph("service:first")
	second := buildTierManagerTestGraph("service:second")
	manager.PromoteHot("gen-a", "tenant-a", first, now)

	now = now.Add(time.Minute)
	manager.PromoteHot("gen-a", "tenant-b", second, now)

	if got := manager.HotGraph("gen-a", "tenant-a"); got != nil {
		t.Fatalf("expected tenant-a to be evicted from hot tier, got %p", got)
	}
	if got := manager.HotGraph("gen-a", "tenant-b"); got != second {
		t.Fatalf("HotGraph(tenant-b) = %p, want %p", got, second)
	}
	if store := manager.WarmStore("gen-a", "tenant-a"); store == nil {
		t.Fatal("expected LRU eviction to demote tenant-a into warm tier")
	}
}

func TestTierManagerKeepsPinnedHotGraphDuringEviction(t *testing.T) {
	now := time.Date(2026, time.March, 20, 12, 0, 0, 0, time.UTC)
	manager := NewTierManager(TierManagerOptions{
		HotRetention:     time.Hour,
		WarmRetention:    24 * time.Hour,
		HotMaxEntries:    1,
		WarmBasePath:     t.TempDir(),
		WarmMaxSnapshots: 1,
		Now: func() time.Time {
			return now
		},
		Pin: func(key string) bool {
			return key == "tenant-a"
		},
	})

	first := buildTierManagerTestGraph("service:first")
	second := buildTierManagerTestGraph("service:second")
	manager.PromoteHot("gen-a", "tenant-a", first, now)

	now = now.Add(2 * time.Hour)
	manager.PromoteHot("gen-a", "tenant-b", second, now)

	if got := manager.HotGraph("gen-a", "tenant-a"); got != first {
		t.Fatalf("expected pinned tenant-a to remain hot, got %p want %p", got, first)
	}
	if got := manager.HotGraph("gen-a", "tenant-b"); got == second {
		t.Fatal("expected unpinned tenant-b to demote under hot-tier pressure")
	}
	if store := manager.WarmStore("gen-a", "tenant-b"); store == nil {
		t.Fatal("expected unpinned tenant-b to move into warm tier")
	}
}

func TestTierManagerEvictsExpiredNilHotGraphEntry(t *testing.T) {
	now := time.Date(2026, time.March, 20, 12, 30, 0, 0, time.UTC)
	manager := NewTierManager(TierManagerOptions{
		HotRetention: time.Hour,
		Now: func() time.Time {
			return now
		},
	})
	manager.hot["tenant-a"] = tierManagerHotEntry{
		generation: "gen-a",
		lastAccess: now.Add(-2 * time.Hour),
	}

	if evicted := manager.Evict(now); evicted != 1 {
		t.Fatalf("Evict() = %d, want 1", evicted)
	}
	if _, ok := manager.hot["tenant-a"]; ok {
		t.Fatal("expected expired nil hot entry to be removed")
	}
}

func TestTierManagerCleansExpiredWarmSnapshots(t *testing.T) {
	now := time.Date(2026, time.March, 20, 13, 0, 0, 0, time.UTC)
	manager := NewTierManager(TierManagerOptions{
		HotRetention:     time.Hour,
		WarmRetention:    24 * time.Hour,
		HotMaxEntries:    1,
		WarmBasePath:     t.TempDir(),
		WarmMaxSnapshots: 1,
		Now: func() time.Time {
			return now
		},
	})

	manager.SaveWarm("gen-a", "tenant-a", buildTierManagerTestGraph("service:warm"), now)
	if store := manager.WarmStore("gen-a", "tenant-a"); store == nil {
		t.Fatal("expected warm tier to contain saved graph")
	}

	now = now.Add(25 * time.Hour)
	manager.Evict(now)
	if store := manager.WarmStore("gen-a", "tenant-a"); store != nil {
		t.Fatal("expected expired warm snapshot to be cleaned up")
	}
}

func buildTierManagerTestGraph(nodeID string) *Graph {
	g := New()
	g.AddNode(&Node{ID: nodeID, Kind: NodeKindService})
	g.BuildIndex()
	g.SetMetadata(Metadata{
		BuiltAt:   time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC),
		NodeCount: g.NodeCount(),
		EdgeCount: g.EdgeCount(),
	})
	return g
}
