package graph

import "testing"

func TestAddNodeNormalizesTenantIDFromProperties(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Properties: map[string]any{
			"tenant_id": "tenant-a",
		},
	})

	node, ok := g.GetNode("service:payments")
	if !ok {
		t.Fatal("expected node to be present")
	}
	if node.TenantID != "tenant-a" {
		t.Fatalf("expected tenant_id to normalize onto node, got %q", node.TenantID)
	}
	if got := readString(node.Properties, "tenant_id"); got != "tenant-a" {
		t.Fatalf("expected tenant_id property to remain set, got %q", got)
	}
}

func TestSubgraphForTenantFiltersTenantScopedNodes(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:shared", Kind: NodeKindUser, Name: "shared"})
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, Name: "a", TenantID: "tenant-a"})
	g.AddNode(&Node{ID: "service:tenant-b", Kind: NodeKindService, Name: "b", TenantID: "tenant-b"})
	g.AddEdge(&Edge{ID: "shared-a", Source: "user:shared", Target: "service:tenant-a", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "shared-b", Source: "user:shared", Target: "service:tenant-b", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	scoped := g.SubgraphForTenant("tenant-a")
	if scoped == nil {
		t.Fatal("expected scoped graph")
	}
	if _, ok := scoped.GetNode("service:tenant-a"); !ok {
		t.Fatal("expected tenant-a node to remain visible")
	}
	if _, ok := scoped.GetNode("user:shared"); !ok {
		t.Fatal("expected shared node to remain visible")
	}
	if _, ok := scoped.GetNode("service:tenant-b"); ok {
		t.Fatal("expected tenant-b node to be filtered out")
	}
	if got := len(scoped.GetOutEdges("user:shared")); got != 1 {
		t.Fatalf("expected only one remaining shared edge, got %d", got)
	}
}

func TestSubgraphForTenantKeepsSharedNodesWhenTenantHasNoNodes(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:shared", Kind: NodeKindUser, Name: "shared"})
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, Name: "a", TenantID: "tenant-a"})
	g.AddEdge(&Edge{ID: "shared-a", Source: "user:shared", Target: "service:tenant-a", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	scoped := g.SubgraphForTenant("tenant-missing")
	if scoped == nil {
		t.Fatal("expected tenant-scoped view to retain shared nodes")
	}
	if _, ok := scoped.GetNode("user:shared"); !ok {
		t.Fatal("expected shared node to remain visible")
	}
	if _, ok := scoped.GetNode("service:tenant-a"); ok {
		t.Fatal("expected foreign tenant node to be filtered out")
	}
}

func TestSubgraphForTenantWithScopedNodesReportsTenantPresence(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:shared", Kind: NodeKindUser, Name: "shared"})
	g.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, Name: "a", TenantID: "tenant-a"})
	g.BuildIndex()

	scoped, hasScopedNodes := g.SubgraphForTenantWithScopedNodes("tenant-a")
	if scoped == nil {
		t.Fatal("expected scoped graph")
	}
	if !hasScopedNodes {
		t.Fatal("expected tenant-a scoped nodes to be reported")
	}

	missing, hasMissingScopedNodes := g.SubgraphForTenantWithScopedNodes("tenant-missing")
	if missing == nil {
		t.Fatal("expected missing-tenant scoped graph")
	}
	if hasMissingScopedNodes {
		t.Fatal("did not expect missing tenant to report scoped nodes")
	}
	if _, ok := missing.GetNode("user:shared"); !ok {
		t.Fatal("expected shared node to remain visible for missing tenant")
	}
}
