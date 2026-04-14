package app

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
)

func TestCurrentSecurityGraphForTenantReusesShardUntilSourceSwap(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}

	live := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 20, 0, 0, 0, time.UTC))
	application.setSecurityGraph(live)

	first := application.CurrentSecurityGraphForTenant("tenant-a")
	second := application.CurrentSecurityGraphForTenant("tenant-a")
	if first == nil || second == nil {
		t.Fatal("expected tenant shard to be available")
	}
	if first != second {
		t.Fatalf("expected tenant shard reuse, got %p then %p", first, second)
	}
	if first == live {
		t.Fatal("expected tenant shard to differ from global live graph")
	}

	next := live.Clone()
	next.AddNode(&graph.Node{ID: "service:tenant-a:new", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	next.BuildIndex()
	next.SetMetadata(graph.Metadata{
		BuiltAt:   time.Date(2026, time.March, 17, 20, 5, 0, 0, time.UTC),
		NodeCount: next.NodeCount(),
		EdgeCount: next.EdgeCount(),
	})
	application.setSecurityGraph(next)

	third := application.CurrentSecurityGraphForTenant("tenant-a")
	if third == nil {
		t.Fatal("expected tenant shard after live graph swap")
		return
	}
	if third == first {
		t.Fatalf("expected source swap to invalidate tenant shard cache, still got %p", third)
	}
	if _, ok := third.GetNode("service:tenant-a:new"); !ok {
		t.Fatal("expected refreshed tenant shard to include nodes from new live graph")
	}
}

func TestTenantGraphShardManagerEvictsIdleShards(t *testing.T) {
	manager := newTenantGraphShardManager(time.Minute, time.Hour, "", 1, nil, nil)
	now := time.Date(2026, time.March, 17, 21, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.BuildIndex()

	first := manager.GraphForTenant(live, "tenant-a")
	if first == nil {
		t.Fatal("expected initial tenant shard")
		return
	}

	now = now.Add(2 * time.Minute)
	if evicted := manager.EvictExpired(now); evicted != 1 {
		t.Fatalf("expected one idle shard eviction, got %d", evicted)
	}

	second := manager.GraphForTenant(live, "tenant-a")
	if second == nil {
		t.Fatal("expected tenant shard rebuild after eviction")
		return
	}
	if second == first {
		t.Fatalf("expected eviction to force shard rebuild, still got %p", second)
	}
}

func TestTenantGraphShardManagerPromoteHotShardReturnsShardWithoutCachingOnSourceRace(t *testing.T) {
	manager := newTenantGraphShardManager(time.Minute, time.Hour, "", 1, nil, nil)
	now := time.Date(2026, time.March, 17, 21, 5, 0, 0, time.UTC)

	staleSource := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 20, 0, 0, 0, time.UTC))
	currentSource := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 20, 10, 0, 0, time.UTC))

	manager.source = currentSource
	manager.generation = tenantGraphSourceGeneration(currentSource)

	shard := staleSource.SubgraphForTenant("tenant-a")
	if shard == nil {
		t.Fatal("expected stale tenant shard to exist")
		return
	}

	returned := manager.promoteHotShard(staleSource, tenantGraphSourceGeneration(staleSource), "tenant-a", shard, now)
	if returned != shard {
		t.Fatalf("expected computed shard to be returned on race, got %p want %p", returned, shard)
	}
	if got := manager.tiers.HotGraph(manager.generation, "tenant-a"); got != nil {
		t.Fatal("did not expect stale shard to be promoted into hot cache")
	}
}

func TestTenantGraphShardManagerPromoteHotShardReturnsWarmShardWithoutCachingWhenLiveGraphAppears(t *testing.T) {
	manager := newTenantGraphShardManager(time.Minute, time.Hour, "", 1, nil, nil)
	now := time.Date(2026, time.March, 17, 21, 10, 0, 0, time.UTC)

	currentSource := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 20, 10, 0, 0, time.UTC))
	manager.source = currentSource
	manager.generation = tenantGraphSourceGeneration(currentSource)

	warmShard := currentSource.SubgraphForTenant("tenant-a")
	if warmShard == nil {
		t.Fatal("expected warm tenant shard to exist")
		return
	}

	returned := manager.promoteHotShard(nil, manager.generation, "tenant-a", warmShard, now)
	if returned != warmShard {
		t.Fatalf("expected warm shard to be returned while skipping cache promotion, got %p want %p", returned, warmShard)
	}
	if got := manager.tiers.HotGraph(manager.generation, "tenant-a"); got != nil {
		t.Fatal("did not expect warm shard to be promoted when live graph reappeared")
	}
}

func TestEnsureTenantSecurityGraphShardsDoesNotWaitOnSecurityGraphLock(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL: time.Minute,
		},
	}

	application.securityGraphInitMu.Lock()
	done := make(chan struct{})
	go func() {
		_ = application.ensureTenantSecurityGraphShards()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		application.securityGraphInitMu.Unlock()
		t.Fatal("ensureTenantSecurityGraphShards blocked on securityGraphInitMu")
	}

	application.securityGraphInitMu.Unlock()
}

func TestCurrentSecurityGraphForTenantUsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	live := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 22, 0, 0, 0, time.UTC))
	application := &App{
		Config: &Config{
			GraphSnapshotPath:               basePath,
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}
	setConfiguredSnapshotGraphFromGraph(t, application, live)

	scoped := application.CurrentSecurityGraphForTenant("tenant-a")
	if scoped == nil {
		t.Fatal("expected tenant shard resolved from configured graph")
		return
	}
	if _, ok := scoped.GetNode("service:tenant-a"); !ok {
		t.Fatal("expected tenant shard to include tenant-a node")
	}
	if _, ok := scoped.GetNode("service:tenant-b"); ok {
		t.Fatal("expected tenant shard to exclude tenant-b node")
	}
}

func TestCurrentSecurityGraphForTenantReusesWarmShardAfterLiveGraphClear(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	application := &App{
		Config: &Config{
			GraphSnapshotPath:               basePath,
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}

	live := buildTenantShardTestGraph(time.Date(2026, time.March, 17, 22, 15, 0, 0, time.UTC))
	application.setSecurityGraph(live)

	first := application.CurrentSecurityGraphForTenant("tenant-a")
	if first == nil {
		t.Fatal("expected warm tier seed from live graph")
		return
	}

	application.setSecurityGraph(nil)
	application.GraphSnapshots = nil

	second := application.CurrentSecurityGraphForTenant("tenant-a")
	if second == nil {
		t.Fatal("expected tenant shard recovered from warm tier after live graph clear")
		return
	}
	if second == first {
		t.Fatalf("expected warm-tier recovery to rebuild shard, still got %p", second)
	}
	if _, ok := second.GetNode("service:tenant-a"); !ok {
		t.Fatal("expected warm shard to preserve tenant-a node")
	}
}

func TestTenantGraphShardManagerPinsTenantsWithOpenFindings(t *testing.T) {
	store := findings.NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:          "finding:tenant-a",
		PolicyID:    "tenant-a-open",
		PolicyName:  "Tenant A Open Finding",
		Severity:    "high",
		Description: "open finding for pinning",
		Resource: map[string]any{
			"tenant_id": "tenant-a",
		},
	})

	manager := newTenantGraphShardManager(time.Minute, time.Hour, "", 1, nil, store)
	now := time.Date(2026, time.March, 17, 23, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.BuildIndex()

	if shard := manager.GraphForTenant(live, "tenant-a"); shard == nil {
		t.Fatal("expected initial tenant shard")
		return
	}

	now = now.Add(2 * time.Minute)
	if evicted := manager.EvictExpired(now); evicted != 0 {
		t.Fatalf("expected pinned tenant shard to survive eviction, got %d evictions", evicted)
	}
	if shard := manager.GraphForTenant(live, "tenant-a"); shard == nil {
		t.Fatal("expected pinned tenant shard to remain available")
		return
	}

	if !store.Resolve("finding:tenant-a") {
		t.Fatal("expected finding resolution to succeed")
	}
	now = now.Add(2 * time.Minute)
	if evicted := manager.EvictExpired(now); evicted != 1 {
		t.Fatalf("expected tenant shard eviction after findings resolved, got %d", evicted)
	}
}

func TestTenantGraphShardManagerGraphForTenantAvoidsDoubleEviction(t *testing.T) {
	store := &countingFindingStore{Store: findings.NewStore()}
	store.Upsert(context.Background(), policy.Finding{
		ID:          "finding:tenant-a",
		PolicyID:    "tenant-a-open",
		PolicyName:  "Tenant A Open Finding",
		Severity:    "high",
		Description: "open finding for pinning",
		Resource: map[string]any{
			"tenant_id": "tenant-a",
		},
	})

	manager := newTenantGraphShardManager(time.Minute, time.Hour, "", 1, nil, store)
	now := time.Date(2026, time.March, 17, 23, 5, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.BuildIndex()

	if shard := manager.GraphForTenant(live, "tenant-a"); shard == nil {
		t.Fatal("expected initial tenant shard")
		return
	}

	now = now.Add(2 * time.Minute)
	store.countCalls = 0
	if shard := manager.GraphForTenant(live, "tenant-a"); shard == nil {
		t.Fatal("expected pinned tenant shard to remain available")
		return
	}
	if store.countCalls != 1 {
		t.Fatalf("Count() called %d times, want 1", store.countCalls)
	}
}

func BenchmarkCurrentSecurityGraphForTenant(b *testing.B) {
	live := graph.New()
	for tenant := 0; tenant < 12; tenant++ {
		tenantID := fmt.Sprintf("tenant-%d", tenant)
		for service := 0; service < 120; service++ {
			serviceID := fmt.Sprintf("service:%s:%d", tenantID, service)
			live.AddNode(&graph.Node{
				ID:       serviceID,
				Kind:     graph.NodeKindService,
				TenantID: tenantID,
			})
			if service == 0 {
				continue
			}
			prevID := fmt.Sprintf("service:%s:%d", tenantID, service-1)
			live.AddEdge(&graph.Edge{
				ID:     fmt.Sprintf("depends:%s:%d", tenantID, service),
				Source: prevID,
				Target: serviceID,
				Kind:   graph.EdgeKindDependsOn,
			})
		}
	}
	for shared := 0; shared < 80; shared++ {
		sharedID := fmt.Sprintf("service:shared:%d", shared)
		live.AddNode(&graph.Node{ID: sharedID, Kind: graph.NodeKindService})
		live.AddEdge(&graph.Edge{
			ID:     fmt.Sprintf("shared-edge:%d", shared),
			Source: sharedID,
			Target: "service:tenant-3:0",
			Kind:   graph.EdgeKindDependsOn,
		})
	}
	live.BuildIndex()
	live.SetMetadata(graph.Metadata{
		BuiltAt:   time.Date(2026, time.March, 17, 23, 30, 0, 0, time.UTC),
		NodeCount: live.NodeCount(),
		EdgeCount: live.EdgeCount(),
	})

	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         time.Hour,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
	}
	application.setSecurityGraph(live)

	b.Run("subgraph_for_tenant", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scoped := live.SubgraphForTenant("tenant-3")
			if scoped == nil || scoped.NodeCount() == 0 {
				b.Fatal("expected tenant subgraph")
			}
		}
	})

	b.Run("cached_tenant_shard", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scoped := application.CurrentSecurityGraphForTenant("tenant-3")
			if scoped == nil || scoped.NodeCount() == 0 {
				b.Fatal("expected cached tenant shard")
			}
		}
	})
}

func buildTenantShardTestGraph(builtAt time.Time) *graph.Graph {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "shared"})
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, TenantID: "tenant-b"})
	live.AddEdge(&graph.Edge{ID: "shared-a", Source: "service:shared", Target: "service:tenant-a", Kind: graph.EdgeKindDependsOn})
	live.AddEdge(&graph.Edge{ID: "shared-b", Source: "service:shared", Target: "service:tenant-b", Kind: graph.EdgeKindDependsOn})
	live.BuildIndex()
	live.SetMetadata(graph.Metadata{
		BuiltAt:   builtAt,
		NodeCount: live.NodeCount(),
		EdgeCount: live.EdgeCount(),
	})
	return live
}

type countingFindingStore struct {
	*findings.Store
	countCalls int
}

func (s *countingFindingStore) Count(filter findings.FindingFilter) int {
	s.countCalls++
	return s.Store.Count(filter)
}
