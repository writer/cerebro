package graph

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestTenantReaderRequiresExplicitScopeForMultiTenantGraph(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, TenantID: "tenant-a"})
	g.AddNode(&Node{ID: "service:tenant-b", Kind: NodeKindService, TenantID: "tenant-b"})

	if _, err := g.NewTenantReader(context.Background()); !errors.Is(err, ErrTenantScopeRequired) {
		t.Fatalf("NewTenantReader() error = %v, want %v", err, ErrTenantScopeRequired)
	}
}

func TestTenantReaderAllowsSingleTenantGraphWithoutExplicitScope(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:shared", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, TenantID: "tenant-a"})

	reader, err := g.NewTenantReader(context.Background())
	if err != nil {
		t.Fatalf("NewTenantReader() error = %v", err)
	}
	if got := nodeIDs(reader.GetAllNodes()); !slices.Equal(got, []string{"service:tenant-a", "user:shared"}) {
		t.Fatalf("GetAllNodes() = %#v", got)
	}
}

func TestTenantReaderFiltersNodesAndEdgesByTenantScope(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:shared", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, TenantID: "tenant-a"})
	g.AddNode(&Node{ID: "service:tenant-b", Kind: NodeKindService, TenantID: "tenant-b"})
	g.AddEdge(&Edge{ID: "shared-a", Source: "user:shared", Target: "service:tenant-a", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "shared-b", Source: "user:shared", Target: "service:tenant-b", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	reader, err := g.NewTenantReader(WithTenantScope(context.Background(), "tenant-a"))
	if err != nil {
		t.Fatalf("NewTenantReader() error = %v", err)
	}

	if got := nodeIDs(reader.GetAllNodes()); !slices.Equal(got, []string{"service:tenant-a", "user:shared"}) {
		t.Fatalf("GetAllNodes() = %#v", got)
	}
	if _, ok := reader.GetNode("service:tenant-b"); ok {
		t.Fatal("expected tenant-b node to be filtered out")
	}
	outEdges := reader.GetOutEdges("user:shared")
	if len(outEdges) != 1 || outEdges[0].ID != "shared-a" {
		t.Fatalf("GetOutEdges(user:shared) = %#v", edgeIDs(outEdges))
	}
	stats := reader.Stats()
	if !slices.Equal(stats.VisibleTenants, []string{"tenant-a"}) {
		t.Fatalf("Stats().VisibleTenants = %#v", stats.VisibleTenants)
	}
	if stats.TotalTenants != 0 {
		t.Fatalf("Stats().TotalTenants = %d, want 0 without cross-tenant scope", stats.TotalTenants)
	}
	if stats.NodeCounts != nil {
		t.Fatalf("Stats().NodeCounts = %#v, want nil without cross-tenant scope", stats.NodeCounts)
	}
}

func TestTenantReaderAllowsCrossTenantScopeAndAudits(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, TenantID: "tenant-a"})
	g.AddNode(&Node{ID: "service:tenant-b", Kind: NodeKindService, TenantID: "tenant-b"})

	var (
		called        bool
		gotActor      string
		gotReason     string
		gotTenantList []string
	)
	previous := tenantReadAuditHook
	tenantReadAuditHook = func(scope TenantReadScope, visibleTenants []string) {
		called = true
		gotActor = scope.AuditActor
		gotReason = scope.AuditReason
		gotTenantList = append([]string(nil), visibleTenants...)
	}
	t.Cleanup(func() {
		tenantReadAuditHook = previous
	})

	reader, err := g.NewTenantReader(WithCrossTenantScope(context.Background(), "platform-admin", "capacity_planning"))
	if err != nil {
		t.Fatalf("NewTenantReader() error = %v", err)
	}
	if got := nodeIDs(reader.GetAllNodes()); !slices.Equal(got, []string{"service:tenant-a", "service:tenant-b"}) {
		t.Fatalf("GetAllNodes() = %#v", got)
	}
	if !called {
		t.Fatal("expected cross-tenant audit hook to fire")
	}
	if gotActor != "platform-admin" || gotReason != "capacity_planning" {
		t.Fatalf("audit hook scope = actor=%q reason=%q", gotActor, gotReason)
	}
	if !slices.Equal(gotTenantList, []string{"tenant-a", "tenant-b"}) {
		t.Fatalf("audit hook visible tenants = %#v", gotTenantList)
	}
	stats := reader.Stats()
	if stats.TotalTenants != 2 {
		t.Fatalf("Stats().TotalTenants = %d, want 2", stats.TotalTenants)
	}
	if stats.NodeCounts["tenant-a"] != 1 || stats.NodeCounts["tenant-b"] != 1 {
		t.Fatalf("Stats().NodeCounts = %#v", stats.NodeCounts)
	}
}

func BenchmarkTenantReaderGetAllNodes(b *testing.B) {
	g := New()
	for tenantIdx := 0; tenantIdx < 4; tenantIdx++ {
		tenantID := fmt.Sprintf("tenant-%d", tenantIdx)
		for nodeIdx := 0; nodeIdx < 2500; nodeIdx++ {
			g.AddNode(&Node{
				ID:       fmt.Sprintf("service:%s:%d", tenantID, nodeIdx),
				Kind:     NodeKindService,
				TenantID: tenantID,
			})
		}
	}

	reader, err := g.NewTenantReader(WithTenantScope(context.Background(), "tenant-1"))
	if err != nil {
		b.Fatalf("NewTenantReader() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nodes := reader.GetAllNodes()
		if len(nodes) != 2500 {
			b.Fatalf("GetAllNodes() = %d, want 2500", len(nodes))
		}
	}
}

func nodeIDs(nodes []*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		out = append(out, node.ID)
	}
	slices.Sort(out)
	return out
}

func edgeIDs(edges []*Edge) []string {
	out := make([]string, 0, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		out = append(out, edge.ID)
	}
	slices.Sort(out)
	return out
}
