package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestCurrentSecurityGraphForTenantReusesShardUntilSourceSwap(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL: 10 * time.Minute,
		},
	}

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "shared"})
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, TenantID: "tenant-b"})
	live.AddEdge(&graph.Edge{ID: "shared-a", Source: "service:shared", Target: "service:tenant-a", Kind: graph.EdgeKindDependsOn})
	live.AddEdge(&graph.Edge{ID: "shared-b", Source: "service:shared", Target: "service:tenant-b", Kind: graph.EdgeKindDependsOn})
	live.BuildIndex()
	live.SetMetadata(graph.Metadata{
		BuiltAt:   time.Date(2026, time.March, 17, 20, 0, 0, 0, time.UTC),
		NodeCount: live.NodeCount(),
		EdgeCount: live.EdgeCount(),
	})
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
	}
	if third == first {
		t.Fatalf("expected source swap to invalidate tenant shard cache, still got %p", third)
	}
	if _, ok := third.GetNode("service:tenant-a:new"); !ok {
		t.Fatal("expected refreshed tenant shard to include nodes from new live graph")
	}
}

func TestTenantGraphShardManagerEvictsIdleShards(t *testing.T) {
	manager := newTenantGraphShardManager(time.Minute)
	now := time.Date(2026, time.March, 17, 21, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	live.BuildIndex()

	first := manager.GraphForTenant(live, "tenant-a")
	if first == nil {
		t.Fatal("expected initial tenant shard")
	}

	now = now.Add(2 * time.Minute)
	if evicted := manager.EvictExpired(now); evicted != 1 {
		t.Fatalf("expected one idle shard eviction, got %d", evicted)
	}

	second := manager.GraphForTenant(live, "tenant-a")
	if second == nil {
		t.Fatal("expected tenant shard rebuild after eviction")
	}
	if second == first {
		t.Fatalf("expected eviction to force shard rebuild, still got %p", second)
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

	application := &App{
		Config: &Config{
			GraphTenantShardIdleTTL: time.Hour,
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
