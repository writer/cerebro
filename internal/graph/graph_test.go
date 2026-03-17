package graph

import (
	"testing"
)

func TestGraph_AddNode(t *testing.T) {
	g := New()

	node := &Node{
		ID:       "arn:aws:iam::123456789012:user/alice",
		Kind:     NodeKindUser,
		Name:     "alice",
		Provider: "aws",
		Account:  "123456789012",
	}

	g.AddNode(node)

	got, ok := g.GetNode(node.ID)
	if !ok {
		t.Fatal("expected node to be found")
	}
	if got.Name != "alice" {
		t.Errorf("expected name alice, got %s", got.Name)
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := New()

	// Add nodes
	user := &Node{ID: "user:alice", Kind: NodeKindUser}
	role := &Node{ID: "role:admin", Kind: NodeKindRole}
	g.AddNode(user)
	g.AddNode(role)

	// Add edge
	edge := &Edge{
		ID:     "user:alice->role:admin",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	}
	g.AddEdge(edge)

	// Verify outbound edges
	outEdges := g.GetOutEdges("user:alice")
	if len(outEdges) != 1 {
		t.Errorf("expected 1 outbound edge, got %d", len(outEdges))
	}

	// Verify inbound edges
	inEdges := g.GetInEdges("role:admin")
	if len(inEdges) != 1 {
		t.Errorf("expected 1 inbound edge, got %d", len(inEdges))
	}
}

func TestGraph_GetNodesByKind(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "bucket:data", Kind: NodeKindBucket})

	users := g.GetNodesByKind(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	identities := g.GetNodesByKind(NodeKindUser, NodeKindRole)
	if len(identities) != 3 {
		t.Errorf("expected 3 identities, got %d", len(identities))
	}
}

func TestGraph_NodeCount(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "1"})
	g.AddNode(&Node{ID: "2"})
	g.AddNode(&Node{ID: "3"})

	if g.NodeCount() != 3 {
		t.Errorf("expected 3 nodes, got %d", g.NodeCount())
	}
}

func TestGraph_EdgeCount(t *testing.T) {
	g := New()

	g.AddEdge(&Edge{ID: "1", Source: "a", Target: "b"})
	g.AddEdge(&Edge{ID: "2", Source: "b", Target: "c"})

	if g.EdgeCount() != 2 {
		t.Errorf("expected 2 edges, got %d", g.EdgeCount())
	}
}

func TestGraph_Clear(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "1"})
	g.AddEdge(&Edge{ID: "1", Source: "a", Target: "b"})

	g.Clear()

	if g.NodeCount() != 0 {
		t.Error("expected 0 nodes after clear")
	}
	if g.EdgeCount() != 0 {
		t.Error("expected 0 edges after clear")
	}
}

func TestGraph_BuildIndex(t *testing.T) {
	g := New()

	// Add test nodes
	g.AddNode(&Node{
		ID:       "user:alice",
		Kind:     NodeKindUser,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskHigh,
	})
	g.AddNode(&Node{
		ID:       "user:bob",
		Kind:     NodeKindUser,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskLow,
	})
	g.AddNode(&Node{
		ID:       "role:admin",
		Kind:     NodeKindRole,
		Account:  "987654321098",
		Provider: "aws",
		Risk:     RiskCritical,
	})
	g.AddNode(&Node{
		ID:       "bucket:data",
		Kind:     NodeKindBucket,
		Account:  "123456789012",
		Provider: "aws",
		Risk:     RiskMedium,
		Properties: map[string]interface{}{
			"public_access_block_enabled": false,
		},
	})

	// Build index
	g.BuildIndex()

	if !g.IsIndexBuilt() {
		t.Error("expected index to be built")
	}

	// Test kind index
	users := g.GetNodesByKindIndexed(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected 2 users from index, got %d", len(users))
	}

	// Test account index
	account1Nodes := g.GetNodesByAccountIndexed("123456789012")
	if len(account1Nodes) != 3 {
		t.Errorf("expected 3 nodes in account 123456789012, got %d", len(account1Nodes))
	}

	// Test risk index
	criticalNodes := g.GetNodesByRisk(RiskCritical)
	if len(criticalNodes) != 1 {
		t.Errorf("expected 1 critical node, got %d", len(criticalNodes))
	}

	// Test crown jewels (high + critical risk)
	crownJewels := g.GetCrownJewels()
	if len(crownJewels) != 2 { // alice (high) and admin (critical)
		t.Errorf("expected 2 crown jewels, got %d", len(crownJewels))
	}

	// Test internet-facing (bucket with public access)
	internetFacing := g.GetInternetFacingNodes()
	if len(internetFacing) != 1 {
		t.Errorf("expected 1 internet-facing node, got %d", len(internetFacing))
	}
}

func TestGraph_BuildIndexSkipsRebuildWhenCurrent(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:       "service:payments",
		Kind:     NodeKindService,
		Name:     "Payments",
		Provider: "aws",
	})

	g.BuildIndex()

	g.mu.Lock()
	g.entitySearchDocs["sentinel"] = entitySearchDocument{ID: "sentinel"}
	g.mu.Unlock()

	g.BuildIndex()

	g.mu.RLock()
	_, ok := g.entitySearchDocs["sentinel"]
	g.mu.RUnlock()
	if !ok {
		t.Fatal("expected BuildIndex to skip redundant rebuild when index is already current")
	}
}

func TestGraph_BuildIndexSkipsRuntimeArtifactsFromEntitySearch(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "workload:payments",
		Kind: NodeKindWorkload,
		Name: "Payments",
	})
	g.AddNode(&Node{
		ID:   "observation:exec",
		Kind: NodeKindObservation,
		Name: "Runtime Exec",
	})
	g.AddNode(&Node{
		ID:   "evidence:alert",
		Kind: NodeKindEvidence,
		Name: "Detection Evidence",
	})

	g.BuildIndex()

	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.entitySearchDocs["workload:payments"]; !ok {
		t.Fatal("expected workload to remain entity-search indexed")
	}
	if _, ok := g.entitySearchDocs["observation:exec"]; ok {
		t.Fatal("expected observation nodes to be excluded from entity-search indexing")
	}
	if _, ok := g.entitySearchDocs["evidence:alert"]; ok {
		t.Fatal("expected evidence nodes to be excluded from entity-search indexing")
	}
}

func TestGraph_BuildIndexDefersEntitySuggestionIndexConstruction(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "workload:payments",
		Kind: NodeKindWorkload,
		Name: "Payments",
	})

	g.BuildIndex()

	g.mu.RLock()
	if _, ok := g.entitySearchDocs["workload:payments"]; !ok {
		g.mu.RUnlock()
		t.Fatal("expected workload search document to exist after BuildIndex")
	}
	if len(g.entitySuggestIndex) != 0 {
		g.mu.RUnlock()
		t.Fatal("expected BuildIndex to defer entity suggestion index construction")
	}
	g.mu.RUnlock()

	suggestions := SuggestEntities(g, EntitySuggestOptions{Prefix: "pa", Limit: 5})
	if suggestions.Count != 1 {
		t.Fatalf("expected deferred suggestion index to be built on demand, got %#v", suggestions)
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.entitySuggestIndex) == 0 {
		t.Fatal("expected suggestion index to be populated after on-demand build")
	}
}

func TestGraph_InvalidateIndex(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "test", Kind: NodeKindUser})
	g.BuildIndex()

	if !g.IsIndexBuilt() {
		t.Error("expected index to be built")
	}

	g.InvalidateIndex()

	if g.IsIndexBuilt() {
		t.Error("expected index to be invalidated")
	}
}

func TestGraph_IndexFallback(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "123"})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser, Account: "456"})

	// Test without building index - should fall back to scan
	users := g.GetNodesByKindIndexed(NodeKindUser)
	if len(users) != 2 {
		t.Errorf("expected fallback to find 2 users, got %d", len(users))
	}

	accountNodes := g.GetNodesByAccountIndexed("123")
	if len(accountNodes) != 1 {
		t.Errorf("expected fallback to find 1 node in account, got %d", len(accountNodes))
	}
}

func TestGraph_CrossAccountEdgesIndexed(t *testing.T) {
	g := New()

	// Add nodes in different accounts
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.AddNode(&Node{ID: "role:viewer", Kind: NodeKindRole, Account: "111"})

	// Add cross-account edge
	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})

	// Add same-account edge
	g.AddEdge(&Edge{
		ID:     "same-1",
		Source: "user:alice",
		Target: "role:viewer",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": false,
		},
	})

	g.BuildIndex()

	crossEdges := g.GetCrossAccountEdgesIndexed()
	if len(crossEdges) != 1 {
		t.Errorf("expected 1 cross-account edge, got %d", len(crossEdges))
	}
}

func TestGraph_RemoveNode(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "bucket:data", Kind: NodeKindBucket})

	g.AddEdge(&Edge{ID: "e1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "role:admin", Target: "bucket:data", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "bucket:data", Target: "user:alice", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	g.BuildIndex()
	if !g.IsIndexBuilt() {
		t.Fatal("expected index to be built")
	}

	if !g.RemoveNode("role:admin") {
		t.Fatal("expected RemoveNode to delete existing node")
	}
	if g.IsIndexBuilt() {
		t.Fatal("expected RemoveNode to invalidate index")
	}
	if _, ok := g.GetNode("role:admin"); ok {
		t.Fatal("expected removed node to be absent")
	}

	if len(g.GetOutEdges("user:alice")) != 0 {
		t.Fatal("expected edges targeting removed node to be deleted")
	}
	if len(g.GetOutEdges("role:admin")) != 0 {
		t.Fatal("expected removed source edge list to be deleted")
	}
	if len(g.GetInEdges("role:admin")) != 0 {
		t.Fatal("expected removed target edge list to be deleted")
	}
	if g.EdgeCount() != 1 {
		t.Fatalf("expected 1 remaining edge, got %d", g.EdgeCount())
	}
	if g.RemoveNode("missing-node") {
		t.Fatal("expected RemoveNode to return false for missing node")
	}
}

func TestGraph_RemoveEdge(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole})
	g.AddEdge(&Edge{ID: "e1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	g.BuildIndex()
	if !g.IsIndexBuilt() {
		t.Fatal("expected index to be built")
	}

	if !g.RemoveEdge("user:alice", "role:admin", EdgeKindCanAssume) {
		t.Fatal("expected RemoveEdge to remove matching edges")
	}
	if g.IsIndexBuilt() {
		t.Fatal("expected RemoveEdge to invalidate index")
	}

	if got := len(g.GetOutEdges("user:alice")); got != 1 {
		t.Fatalf("expected 1 remaining out edge, got %d", got)
	}
	if g.GetOutEdges("user:alice")[0].Kind != EdgeKindCanRead {
		t.Fatalf("expected remaining edge kind to be %q", EdgeKindCanRead)
	}
	if got := len(g.GetInEdges("role:admin")); got != 1 {
		t.Fatalf("expected 1 remaining in edge, got %d", got)
	}
	if g.RemoveEdge("user:alice", "role:admin", EdgeKindCanDelete) {
		t.Fatal("expected RemoveEdge to return false when nothing is removed")
	}
}

func TestGraph_RemoveEdgesByNode(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "a", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "b", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "c", Kind: NodeKindBucket})
	g.AddEdge(&Edge{ID: "e1", Source: "a", Target: "b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "b", Target: "c", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "c", Target: "b", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	g.BuildIndex()
	g.RemoveEdgesByNode("b")

	if g.IsIndexBuilt() {
		t.Fatal("expected RemoveEdgesByNode to invalidate index")
	}
	if len(g.GetOutEdges("a")) != 0 {
		t.Fatal("expected outgoing edge to removed node to be deleted")
	}
	if len(g.GetOutEdges("b")) != 0 {
		t.Fatal("expected outgoing edges from target node to be deleted")
	}
	if len(g.GetInEdges("b")) != 0 {
		t.Fatal("expected inbound edges to target node to be deleted")
	}
	if g.EdgeCount() != 0 {
		t.Fatalf("expected all edges touching node b to be removed, got %d", g.EdgeCount())
	}
}

func TestGraph_SetNodeProperty(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "node-1", Kind: NodeKindUser})
	g.BuildIndex()

	if !g.SetNodeProperty("node-1", "department", "security") {
		t.Fatal("expected SetNodeProperty to update existing node")
	}
	if g.IsIndexBuilt() {
		t.Fatal("expected SetNodeProperty to invalidate index")
	}
	n, ok := g.GetNode("node-1")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if got := n.Properties["department"]; got != "security" {
		t.Fatalf("expected property to be set, got %v", got)
	}
	if g.SetNodeProperty("missing", "k", "v") {
		t.Fatal("expected SetNodeProperty to return false for missing node")
	}
}

func TestGraph_Clone(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:       "node-1",
		Kind:     NodeKindUser,
		Name:     "original",
		Findings: []string{"f1"},
		Properties: map[string]any{
			"flat": "value",
			"nested": map[string]any{
				"key": "value",
			},
			"arr": []any{"x", map[string]any{"inner": "y"}},
		},
		Tags: map[string]string{"env": "prod"},
	})
	g.AddNode(&Node{ID: "node-2", Kind: NodeKindRole})
	g.AddEdge(&Edge{
		ID:     "e1",
		Source: "node-1",
		Target: "node-2",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"reason": "delegation",
		},
	})

	clone := g.Clone()
	if clone == g {
		t.Fatal("expected Clone to return a distinct graph")
	}
	if clone.NodeCount() != g.NodeCount() {
		t.Fatalf("expected clone node count %d, got %d", g.NodeCount(), clone.NodeCount())
	}
	if clone.EdgeCount() != g.EdgeCount() {
		t.Fatalf("expected clone edge count %d, got %d", g.EdgeCount(), clone.EdgeCount())
	}

	clonedNode, ok := clone.GetNode("node-1")
	if !ok {
		t.Fatal("expected cloned node to exist")
	}
	clonedNode.Name = "changed"
	clonedNode.Properties["flat"] = "changed"
	clonedNode.Properties["nested"].(map[string]any)["key"] = "changed"
	clonedNode.Properties["arr"].([]any)[1].(map[string]any)["inner"] = "changed"
	clonedNode.Tags["env"] = "dev"
	clonedNode.Findings[0] = "f2"

	origNode, ok := g.GetNode("node-1")
	if !ok {
		t.Fatal("expected original node to exist")
	}
	if origNode.Name != "original" {
		t.Fatalf("expected original name to remain unchanged, got %q", origNode.Name)
	}
	if got := origNode.Properties["flat"]; got != "value" {
		t.Fatalf("expected original flat property to remain unchanged, got %v", got)
	}
	if got := origNode.Properties["nested"].(map[string]any)["key"]; got != "value" {
		t.Fatalf("expected original nested property to remain unchanged, got %v", got)
	}
	if got := origNode.Properties["arr"].([]any)[1].(map[string]any)["inner"]; got != "y" {
		t.Fatalf("expected original nested array value to remain unchanged, got %v", got)
	}
	if got := origNode.Tags["env"]; got != "prod" {
		t.Fatalf("expected original tag to remain unchanged, got %v", got)
	}
	if got := origNode.Findings[0]; got != "f1" {
		t.Fatalf("expected original findings to remain unchanged, got %v", got)
	}

	clonedEdge := clone.GetOutEdges("node-1")[0]
	clonedEdge.Properties["reason"] = "changed"
	origEdge := g.GetOutEdges("node-1")[0]
	if got := origEdge.Properties["reason"]; got != "delegation" {
		t.Fatalf("expected original edge properties to remain unchanged, got %v", got)
	}
}
