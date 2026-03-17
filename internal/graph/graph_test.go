package graph

import (
	"testing"
	"time"
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

func TestGraph_IncrementalNodeLookupIndexesTrackNodeMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:       "workload:payments",
		Kind:     NodeKindWorkload,
		Account:  "acct-a",
		Provider: "aws",
		Risk:     RiskLow,
	})
	g.BuildIndex()

	g.AddNode(&Node{
		ID:       "identity:alice",
		Kind:     NodeKindUser,
		Name:     "Alice",
		Account:  "acct-a",
		Provider: "aws",
		Risk:     RiskHigh,
		Properties: map[string]any{
			"internet_exposed": true,
		},
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to remain built after AddNode")
	}
	g.mu.RLock()
	if !g.nodeLookupIndexBuilt {
		g.mu.RUnlock()
		t.Fatal("expected node lookup indexes to remain built after AddNode")
	}
	g.mu.RUnlock()
	if got := len(g.GetNodesByKindIndexed(NodeKindUser)); got != 1 {
		t.Fatalf("GetNodesByKindIndexed(user) = %d, want 1", got)
	}
	if got := len(g.GetNodesByAccountIndexed("acct-a")); got != 2 {
		t.Fatalf("GetNodesByAccountIndexed(acct-a) = %d, want 2", got)
	}
	if got := len(g.GetNodesByRisk(RiskHigh)); got != 1 {
		t.Fatalf("GetNodesByRisk(high) = %d, want 1", got)
	}
	if got := len(g.GetInternetFacingNodes()); got != 1 {
		t.Fatalf("GetInternetFacingNodes() = %d, want 1", got)
	}
	if got := len(g.GetCrownJewels()); got != 1 {
		t.Fatalf("GetCrownJewels() = %d, want 1", got)
	}
	results := SearchEntities(g, EntitySearchOptions{Query: "alice", Limit: 5})
	if results.Count != 1 || results.Results[0].Entity.ID != "identity:alice" {
		t.Fatalf("SearchEntities(alice) = %#v, want identity:alice", results)
	}

	g.AddNode(&Node{
		ID:       "identity:alice",
		Kind:     NodeKindRole,
		Name:     "Prod Role",
		Account:  "acct-b",
		Provider: "gcp",
		Risk:     RiskCritical,
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to remain built after replacement")
	}
	if got := len(g.GetNodesByKindIndexed(NodeKindUser)); got != 0 {
		t.Fatalf("GetNodesByKindIndexed(user) after replace = %d, want 0", got)
	}
	if got := len(g.GetNodesByKindIndexed(NodeKindRole)); got != 1 {
		t.Fatalf("GetNodesByKindIndexed(role) after replace = %d, want 1", got)
	}
	if got := len(g.GetNodesByAccountIndexed("acct-a")); got != 1 {
		t.Fatalf("GetNodesByAccountIndexed(acct-a) after replace = %d, want 1", got)
	}
	if got := len(g.GetNodesByAccountIndexed("acct-b")); got != 1 {
		t.Fatalf("GetNodesByAccountIndexed(acct-b) after replace = %d, want 1", got)
	}
	if got := len(g.GetNodesByRisk(RiskHigh)); got != 0 {
		t.Fatalf("GetNodesByRisk(high) after replace = %d, want 0", got)
	}
	if got := len(g.GetNodesByRisk(RiskCritical)); got != 1 {
		t.Fatalf("GetNodesByRisk(critical) after replace = %d, want 1", got)
	}
	if got := len(g.GetInternetFacingNodes()); got != 0 {
		t.Fatalf("GetInternetFacingNodes() after replace = %d, want 0", got)
	}
	if got := len(g.GetCrownJewels()); got != 1 {
		t.Fatalf("GetCrownJewels() after replace = %d, want 1", got)
	}
	results = SearchEntities(g, EntitySearchOptions{Query: "prod role", Limit: 5})
	if results.Count != 1 || results.Results[0].Entity.ID != "identity:alice" {
		t.Fatalf("SearchEntities(prod role) = %#v, want identity:alice", results)
	}

	if !g.RemoveNode("identity:alice") {
		t.Fatal("expected RemoveNode to remove replacement node")
	}
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to remain built after removal")
	}
	if got := len(g.GetNodesByKindIndexed(NodeKindRole)); got != 0 {
		t.Fatalf("GetNodesByKindIndexed(role) after removal = %d, want 0", got)
	}
	if got := len(g.GetNodesByAccountIndexed("acct-b")); got != 0 {
		t.Fatalf("GetNodesByAccountIndexed(acct-b) after removal = %d, want 0", got)
	}
	if got := len(g.GetNodesByRisk(RiskCritical)); got != 0 {
		t.Fatalf("GetNodesByRisk(critical) after removal = %d, want 0", got)
	}
	if got := len(g.GetCrownJewels()); got != 0 {
		t.Fatalf("GetCrownJewels() after removal = %d, want 0", got)
	}
	if results := SearchEntities(g, EntitySearchOptions{Query: "prod role", Limit: 5}); results.Count != 0 {
		t.Fatalf("SearchEntities(prod role) after removal = %#v, want 0 results", results)
	}
}

func TestGraph_IncrementalNodeLookupIndexesStayBuiltAcrossNonLookupMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "workload:payments", Kind: NodeKindWorkload, Account: "acct-a", Risk: RiskLow})
	g.AddNode(&Node{ID: "workload:queue", Kind: NodeKindWorkload, Account: "acct-a", Risk: RiskMedium})
	g.BuildIndex()

	g.AddEdge(&Edge{
		ID:     "payments-queue",
		Source: "workload:payments",
		Target: "workload:queue",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to stay built after AddEdge")
	}
	g.mu.RLock()
	if !g.nodeLookupIndexBuilt {
		g.mu.RUnlock()
		t.Fatal("expected node lookup indexes to stay built after AddEdge")
	}
	g.mu.RUnlock()
	if got := len(g.GetNodesByAccountIndexed("acct-a")); got != 2 {
		t.Fatalf("GetNodesByAccountIndexed(acct-a) after AddEdge = %d, want 2", got)
	}

	if !g.SetNodeProperty("workload:payments", "internet_exposed", true) {
		t.Fatal("expected SetNodeProperty to succeed")
	}
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to stay built after SetNodeProperty")
	}
	g.mu.RLock()
	if !g.nodeLookupIndexBuilt {
		g.mu.RUnlock()
		t.Fatal("expected node lookup indexes to stay built after SetNodeProperty")
	}
	g.mu.RUnlock()
	if got := len(g.GetNodesByKindIndexed(NodeKindWorkload)); got != 2 {
		t.Fatalf("GetNodesByKindIndexed(workload) after SetNodeProperty = %d, want 2", got)
	}
	if got := len(g.GetInternetFacingNodes()); got != 1 {
		t.Fatalf("GetInternetFacingNodes() after SetNodeProperty = %d, want 1", got)
	}

	g.AddNode(&Node{
		ID:       "db:prod",
		Kind:     NodeKindDatabase,
		Account:  "acct-a",
		Provider: "aws",
		Risk:     RiskLow,
	})
	if !g.SetNodeProperty("db:prod", "data_classification", "restricted") {
		t.Fatal("expected SetNodeProperty(data_classification) to succeed")
	}
	if got := len(g.GetCrownJewels()); got != 1 {
		t.Fatalf("GetCrownJewels() after crown-jewel property set = %d, want 1", got)
	}
}

func TestGraph_IncrementalNodeLookupIndexedResultsAreDetachedFromFutureMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "workload:a", Kind: NodeKindWorkload, Account: "acct-a", Risk: RiskLow})
	g.AddNode(&Node{ID: "workload:b", Kind: NodeKindWorkload, Account: "acct-a", Risk: RiskLow})
	g.BuildIndex()

	kindNodes := g.GetNodesByKindIndexed(NodeKindWorkload)
	accountNodes := g.GetNodesByAccountIndexed("acct-a")
	riskNodes := g.GetNodesByRisk(RiskLow)

	if !g.RemoveNode("workload:a") {
		t.Fatal("expected RemoveNode to succeed")
	}

	if got := len(accountNodes); got != 2 {
		t.Fatalf("len(accountNodes) = %d, want 2", got)
	}
	if got := len(kindNodes); got != 2 {
		t.Fatalf("len(kindNodes) = %d, want 2", got)
	}
	if got := len(riskNodes); got != 2 {
		t.Fatalf("len(riskNodes) = %d, want 2", got)
	}
	assertNodeIDs := func(name string, nodes []*Node, wantIDs ...string) {
		t.Helper()
		got := make(map[string]int, len(nodes))
		for _, node := range nodes {
			if node == nil {
				got["<nil>"]++
				continue
			}
			got[node.ID]++
		}
		for _, id := range wantIDs {
			if got[id] == 0 {
				t.Fatalf("%s missing %q in %#v", name, id, nodes)
			}
			got[id]--
			if got[id] == 0 {
				delete(got, id)
			}
		}
		if len(got) != 0 {
			t.Fatalf("%s has unexpected members %#v", name, got)
		}
	}
	assertNodeIDs("kindNodes", kindNodes, "workload:a", "workload:b")
	assertNodeIDs("accountNodes", accountNodes, "workload:a", "workload:b")
	assertNodeIDs("riskNodes", riskNodes, "workload:a", "workload:b")
}

func TestRemoveIndexedNodeLockedClearsCompactedTail(t *testing.T) {
	nodes := []*Node{
		{ID: "workload:a"},
		{ID: "workload:b"},
		{ID: "workload:c"},
	}

	compacted := removeIndexedNodeLocked(nodes, "workload:b")
	if got := len(compacted); got != 2 {
		t.Fatalf("len(compacted) = %d, want 2", got)
	}
	if compacted[0] == nil || compacted[0].ID != "workload:a" {
		t.Fatalf("compacted[0] = %#v, want workload:a", compacted[0])
	}
	if compacted[1] == nil || compacted[1].ID != "workload:c" {
		t.Fatalf("compacted[1] = %#v, want workload:c", compacted[1])
	}
	if nodes[2] != nil {
		t.Fatalf("nodes[2] = %#v, want nil tail after compaction", nodes[2])
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

func TestGraph_IncrementalCrossAccountEdgesStayBuiltAcrossEdgeMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.AddNode(&Node{ID: "role:viewer", Kind: NodeKindRole, Account: "111"})
	g.BuildIndex()

	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to stay built after AddEdge")
	}
	g.mu.RLock()
	if !g.crossAccountIndexBuilt {
		g.mu.RUnlock()
		t.Fatal("expected cross-account edge index to stay built after AddEdge")
	}
	g.mu.RUnlock()
	if got := len(g.GetCrossAccountEdgesIndexed()); got != 1 {
		t.Fatalf("len(GetCrossAccountEdgesIndexed()) after AddEdge = %d, want 1", got)
	}

	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:viewer",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": false,
		},
	})
	if got := len(g.GetCrossAccountEdgesIndexed()); got != 0 {
		t.Fatalf("len(GetCrossAccountEdgesIndexed()) after replace = %d, want 0", got)
	}

	g.AddEdge(&Edge{
		ID:     "cross-2",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})
	if !g.RemoveNode("role:admin") {
		t.Fatal("expected RemoveNode(role:admin) to succeed")
	}
	if got := len(g.GetCrossAccountEdgesIndexed()); got != 0 {
		t.Fatalf("len(GetCrossAccountEdgesIndexed()) after RemoveNode = %d, want 0", got)
	}
}

func TestGraph_IncrementalCrossAccountEdgesIndexedResultsAreDetached(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.BuildIndex()
	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})

	edges := g.GetCrossAccountEdgesIndexed()
	if !g.RemoveEdge("user:alice", "role:admin", EdgeKindCanAssume) {
		t.Fatal("expected RemoveEdge to succeed")
	}

	if got := len(edges); got != 1 {
		t.Fatalf("len(edges) = %d, want 1", got)
	}
	if edges[0] == nil || edges[0].ID != "cross-1" {
		t.Fatalf("edges[0] = %#v, want cross-1", edges[0])
	}
}

func TestGraph_RemoveCrossAccountEdgeLockedClearsCompactedTail(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.AddNode(&Node{ID: "role:auditor", Kind: NodeKindRole, Account: "333"})
	g.BuildIndex()
	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})
	g.AddEdge(&Edge{
		ID:     "cross-2",
		Source: "user:alice",
		Target: "role:auditor",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})

	g.mu.Lock()
	defer g.mu.Unlock()

	if got := len(g.crossAccountEdge); got != 2 {
		t.Fatalf("len(crossAccountEdge) = %d, want 2", got)
	}
	backing := g.crossAccountEdge[:cap(g.crossAccountEdge)]
	g.removeCrossAccountEdgeLocked(g.crossAccountEdge[0])
	if got := len(g.crossAccountEdge); got != 1 {
		t.Fatalf("len(crossAccountEdge) after removal = %d, want 1", got)
	}
	if backing[1] != nil {
		t.Fatalf("compacted tail retained %#v, want nil", backing[1])
	}
}

func TestGraph_ClearEdgesInvalidatesCrossAccountIndex(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Account: "222"})
	g.AddEdge(&Edge{
		ID:     "cross-1",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Properties: map[string]any{
			"cross_account": true,
		},
	})
	g.BuildIndex()

	g.ClearEdges()

	if !g.nodeLookupIndexBuilt {
		t.Fatal("expected node lookup index to remain built after ClearEdges")
	}
	if g.crossAccountIndexBuilt {
		t.Fatal("expected cross-account index to be invalidated after ClearEdges")
	}
	if got := len(g.GetCrossAccountEdgesIndexed()); got != 0 {
		t.Fatalf("len(GetCrossAccountEdgesIndexed()) after ClearEdges = %d, want 0", got)
	}
}

func TestGraph_IncrementalARNPrefixIndexStayBuiltAcrossNodeMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-west-2:123456789012:function:payments",
		Kind: NodeKindFunction,
	})
	g.BuildIndex()

	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-west-2:123456789012:function:queue",
		Kind: NodeKindFunction,
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to stay built after AddNode")
	}
	if !g.HasResourceARNPrefixIndex() {
		t.Fatal("expected ARN prefix index to stay built after AddNode")
	}
	if got := len(g.GetResourceNodesByARNPrefix("lambda:function")); got != 2 {
		t.Fatalf("len(GetResourceNodesByARNPrefix(lambda:function)) after AddNode = %d, want 2", got)
	}

	g.AddNode(&Node{
		ID:   "arn:aws:rds:us-west-2:123456789012:db:queue",
		Kind: NodeKindDatabase,
	})
	if got := len(g.GetResourceNodesByARNPrefix("lambda:function")); got != 2 {
		t.Fatalf("len(GetResourceNodesByARNPrefix(lambda:function)) after add = %d, want 2", got)
	}
	if got := len(g.GetResourceNodesByARNPrefix("rds:db")); got != 1 {
		t.Fatalf("len(GetResourceNodesByARNPrefix(rds:db)) after add = %d, want 1", got)
	}

	if !g.RemoveNode("arn:aws:lambda:us-west-2:123456789012:function:queue") {
		t.Fatal("expected RemoveNode to succeed")
	}
	if got := len(g.GetResourceNodesByARNPrefix("lambda:function")); got != 1 {
		t.Fatalf("len(GetResourceNodesByARNPrefix(lambda:function)) after RemoveNode = %d, want 1", got)
	}
}

func TestGraph_IncrementalARNPrefixIndexedResultsAreDetached(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-west-2:123456789012:function:payments",
		Kind: NodeKindFunction,
	})
	g.BuildIndex()

	nodes := g.GetResourceNodesByARNPrefix("lambda:function")
	if !g.RemoveNode("arn:aws:lambda:us-west-2:123456789012:function:payments") {
		t.Fatal("expected RemoveNode to succeed")
	}

	if got := len(nodes); got != 1 {
		t.Fatalf("len(nodes) = %d, want 1", got)
	}
	if nodes[0] == nil || nodes[0].ID != "arn:aws:lambda:us-west-2:123456789012:function:payments" {
		t.Fatalf("nodes[0] = %#v, want payments function", nodes[0])
	}
}

func TestFindMatchingNodesUsesIncrementalARNPrefixIndexAfterNodeMutation(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-west-2:123456789012:function:payments",
		Kind: NodeKindFunction,
	})
	g.BuildIndex()

	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-west-2:123456789012:function:payments-canary",
		Kind: NodeKindFunction,
	})
	if !g.IsIndexBuilt() {
		t.Fatal("expected derived index to stay built after AddNode")
	}
	if !g.HasResourceARNPrefixIndex() {
		t.Fatal("expected ARN prefix index to stay built after AddNode")
	}

	matches := FindMatchingNodes(g, "arn:aws:lambda:us-west-2:123456789012:function:payments*")
	if len(matches) != 2 {
		t.Fatalf("len(matches) = %d, want 2", len(matches))
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
	if !g.IsIndexBuilt() {
		t.Fatal("expected RemoveNode to keep derived index current")
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
	if !g.IsIndexBuilt() {
		t.Fatal("expected RemoveEdge to keep derived index current")
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

	if !g.IsIndexBuilt() {
		t.Fatal("expected RemoveEdgesByNode to keep derived index current")
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
	if !g.IsIndexBuilt() {
		t.Fatal("expected SetNodeProperty to keep derived index current")
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

func TestGraphCloneSharesPropertyHistoryUntilMutation(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "customer:shared",
		Kind:       NodeKindCustomer,
		Properties: map[string]any{"health_score": 100.0},
	})

	now = base.Add(1 * time.Hour)
	g.SetNodeProperty("customer:shared", "health_score", 90.0)
	now = base.Add(2 * time.Hour)
	g.SetNodeProperty("customer:shared", "health_score", 80.0)

	clone := g.Clone()

	g.mu.RLock()
	origNode := g.nodes["customer:shared"]
	origHistory := origNode.PropertyHistory["health_score"]
	g.mu.RUnlock()

	clone.mu.RLock()
	clonedNode := clone.nodes["customer:shared"]
	clonedHistory := clonedNode.PropertyHistory["health_score"]
	clone.mu.RUnlock()

	if len(origHistory) == 0 || len(clonedHistory) == 0 {
		t.Fatal("expected property history to exist on both graphs")
	}
	if &origHistory[0] != &clonedHistory[0] {
		t.Fatal("expected cloned graph to share immutable property history slices before mutation")
	}

	now = base.Add(3 * time.Hour)
	if !clone.SetNodeProperty("customer:shared", "health_score", 70.0) {
		t.Fatal("expected clone SetNodeProperty to succeed")
	}

	g.mu.RLock()
	origHistory = g.nodes["customer:shared"].PropertyHistory["health_score"]
	g.mu.RUnlock()

	clone.mu.RLock()
	clonedHistory = clone.nodes["customer:shared"].PropertyHistory["health_score"]
	clone.mu.RUnlock()

	if len(origHistory) != 3 {
		t.Fatalf("expected original history length 3, got %d", len(origHistory))
	}
	if len(clonedHistory) != 4 {
		t.Fatalf("expected clone history length 4 after mutation, got %d", len(clonedHistory))
	}
	if &origHistory[0] == &clonedHistory[0] {
		t.Fatal("expected property history slice to detach on clone mutation")
	}
	if got := origHistory[len(origHistory)-1].Value; got != 80.0 {
		t.Fatalf("expected original latest history value 80.0, got %#v", got)
	}
	if got := clonedHistory[len(clonedHistory)-1].Value; got != 70.0 {
		t.Fatalf("expected cloned latest history value 70.0, got %#v", got)
	}
}

func TestGraphCloneKeepsSchemaValidationCountersWritable(t *testing.T) {
	requiredKind := NodeKind("test_clone_required_kind_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:               requiredKind,
		Categories:         []NodeKindCategory{NodeCategoryBusiness},
		RequiredProperties: []string{"owner"},
	}); err != nil {
		t.Fatalf("register required kind: %v", err)
	}

	g := New()
	clone := g.Clone()

	clone.AddNode(&Node{ID: "node:warn", Kind: requiredKind, Name: "warn"})

	stats := clone.SchemaValidationStats()
	if stats.NodeWarnings == 0 {
		t.Fatalf("expected cloned graph to record schema warnings, got %#v", stats)
	}
	if stats.NodeWarningByCode == nil {
		t.Fatal("expected cloned graph warning counters to stay writable")
	}
}

func TestGraphCloneHistoryReadsDetachMutableSnapshotValues(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "customer:mutable-history",
		Kind:       NodeKindCustomer,
		Properties: map[string]any{"state": map[string]any{"version": "v1"}},
	})

	now = base.Add(1 * time.Hour)
	if !g.SetNodeProperty("customer:mutable-history", "state", map[string]any{"version": "v2"}) {
		t.Fatal("expected SetNodeProperty to succeed")
	}

	clone := g.Clone()

	readHistory := clone.GetNodePropertyHistory("customer:mutable-history", "state", 0)
	if len(readHistory) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(readHistory))
	}

	mutable, ok := readHistory[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("expected map snapshot value, got %#v", readHistory[0].Value)
	}
	mutable["version"] = "tampered"

	origHistory := g.GetNodePropertyHistory("customer:mutable-history", "state", 0)
	cloneHistory := clone.GetNodePropertyHistory("customer:mutable-history", "state", 0)

	if got := origHistory[0].Value.(map[string]any)["version"]; got != "v1" {
		t.Fatalf("expected original history snapshot to remain v1, got %#v", got)
	}
	if got := cloneHistory[0].Value.(map[string]any)["version"]; got != "v1" {
		t.Fatalf("expected cloned history snapshot to remain v1, got %#v", got)
	}
}
