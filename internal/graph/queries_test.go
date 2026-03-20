package graph

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func setupTestGraph() *Graph {
	g := New()

	// Add identities
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice", Account: "111111111111"})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser, Name: "bob", Account: "111111111111"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin", Account: "111111111111"})
	g.AddNode(&Node{ID: "role:cross-account", Kind: NodeKindRole, Name: "cross-account", Account: "222222222222"})

	// Add resources
	g.AddNode(&Node{ID: "bucket:sensitive", Kind: NodeKindBucket, Name: "sensitive", Account: "111111111111", Risk: RiskCritical})
	g.AddNode(&Node{ID: "bucket:public", Kind: NodeKindBucket, Name: "public", Account: "111111111111", Risk: RiskHigh})
	g.AddNode(&Node{ID: "db:production", Kind: NodeKindDatabase, Name: "production", Account: "222222222222", Risk: RiskCritical})

	// Add edges
	// alice -> admin role
	g.AddEdge(&Edge{ID: "e1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	// admin role -> sensitive bucket (read/write)
	g.AddEdge(&Edge{
		ID: "e2", Source: "role:admin", Target: "bucket:sensitive", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow,
		Properties: map[string]any{"actions": []string{"s3:PutObject", "s3:GetObject"}},
	})
	// admin role -> cross-account role
	g.AddEdge(&Edge{
		ID: "e3", Source: "role:admin", Target: "role:cross-account", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow,
		Properties: map[string]any{"cross_account": true},
	})
	// cross-account role -> production db
	g.AddEdge(&Edge{ID: "e4", Source: "role:cross-account", Target: "db:production", Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow})

	// bob -> public bucket only
	g.AddEdge(&Edge{ID: "e5", Source: "user:bob", Target: "bucket:public", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	// Add a deny edge
	g.AddEdge(&Edge{ID: "e6", Source: "user:bob", Target: "bucket:sensitive", Kind: EdgeKindCanRead, Effect: EdgeEffectDeny, Priority: 100})

	return g
}

func TestBlastRadius(t *testing.T) {
	g := setupTestGraph()

	t.Run("alice blast radius", func(t *testing.T) {
		result := BlastRadius(g, "user:alice", 3)

		if result.PrincipalID != "user:alice" {
			t.Errorf("expected principal ID user:alice, got %s", result.PrincipalID)
		}

		if result.TotalCount < 2 {
			t.Errorf("expected at least 2 reachable resources, got %d", result.TotalCount)
		}

		if !result.CrossAccountRisk {
			t.Error("expected cross-account risk to be detected")
		}

		// Should reach: bucket:sensitive, db:production
		foundSensitive := false
		foundProduction := false
		for _, rn := range result.ReachableNodes {
			if rn.Node.ID == "bucket:sensitive" {
				foundSensitive = true
			}
			if rn.Node.ID == "db:production" {
				foundProduction = true
			}
		}
		if !foundSensitive {
			t.Error("expected to reach bucket:sensitive")
		}
		if !foundProduction {
			t.Error("expected to reach db:production")
		}

		// Check risk summary
		if result.RiskSummary.Critical < 2 {
			t.Errorf("expected at least 2 critical resources, got %d", result.RiskSummary.Critical)
		}
	})

	t.Run("bob blast radius", func(t *testing.T) {
		result := BlastRadius(g, "user:bob", 3)

		// Bob should only reach public bucket
		if result.TotalCount != 1 {
			t.Errorf("expected 1 reachable resource, got %d", result.TotalCount)
		}

		if result.CrossAccountRisk {
			t.Error("bob should not have cross-account risk")
		}
	})

	t.Run("non-existent principal", func(t *testing.T) {
		result := BlastRadius(g, "user:nonexistent", 3)

		if result.TotalCount != 0 {
			t.Errorf("expected 0 reachable resources for non-existent user, got %d", result.TotalCount)
		}
	})
}

func TestBlastRadius_DenyChecksFallbackWhenOrdinalsAreInvalid(t *testing.T) {
	newGraph := func() *Graph {
		g := New()
		g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Name: "start"})
		g.AddNode(&Node{ID: "bucket:allowed", Kind: NodeKindBucket, Name: "allowed"})
		g.AddNode(&Node{ID: "bucket:blocked", Kind: NodeKindBucket, Name: "blocked"})
		g.AddEdge(&Edge{ID: "allow-allowed", Source: "user:start", Target: "bucket:allowed", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
		g.AddEdge(&Edge{ID: "allow-blocked", Source: "user:start", Target: "bucket:blocked", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
		g.AddEdge(&Edge{ID: "deny-blocked", Source: "user:start", Target: "bucket:blocked", Kind: EdgeKindCanRead, Effect: EdgeEffectDeny})
		return g
	}

	assertBlockedRemainsDenied := func(t *testing.T, result *BlastRadiusResult) {
		t.Helper()
		reachable := make(map[string]struct{}, len(result.ReachableNodes))
		for _, node := range result.ReachableNodes {
			reachable[node.Node.ID] = struct{}{}
		}
		if _, ok := reachable["bucket:allowed"]; !ok {
			t.Fatal("expected blast radius to keep the allowed target reachable")
		}
		if _, ok := reachable["bucket:blocked"]; ok {
			t.Fatal("expected blast radius to keep the denied target unreachable")
		}
	}

	t.Run("invalid source ordinal falls back to source node id", func(t *testing.T) {
		g := newGraph()

		g.mu.Lock()
		g.nodes["user:start"].ordinal = InvalidNodeOrdinal
		g.mu.Unlock()

		assertBlockedRemainsDenied(t, BlastRadius(g, "user:start", 1))
	})

	t.Run("invalid target ordinal falls back to target node id", func(t *testing.T) {
		g := newGraph()

		g.mu.Lock()
		g.edgeByID["allow-blocked"].targetOrd = InvalidNodeOrdinal
		g.edgeByID["deny-blocked"].targetOrd = InvalidNodeOrdinal
		g.mu.Unlock()

		assertBlockedRemainsDenied(t, BlastRadius(g, "user:start", 1))
	})
}

func TestBlastRadius_CacheIsolationAndInvalidation(t *testing.T) {
	g := setupTestGraph()

	first := BlastRadius(g, "user:alice", 3)
	if first.TotalCount == 0 {
		t.Fatal("expected blast radius results for alice")
	}

	// Mutating the returned object should not poison cached results.
	first.ReachableNodes = nil
	first.TotalCount = 0

	second := BlastRadius(g, "user:alice", 3)
	if second.TotalCount == 0 {
		t.Fatal("expected cached blast radius result to remain intact")
	}

	// Graph mutation should invalidate cache and include the new resource.
	g.AddNode(&Node{
		ID:      "bucket:cache-test",
		Kind:    NodeKindBucket,
		Name:    "cache-test",
		Account: "111111111111",
		Risk:    RiskLow,
	})
	g.AddEdge(&Edge{
		ID:     "edge:cache-test",
		Source: "role:admin",
		Target: "bucket:cache-test",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	third := BlastRadius(g, "user:alice", 3)
	found := false
	for _, rn := range third.ReachableNodes {
		if rn.Node.ID == "bucket:cache-test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected blast radius to include post-mutation resource after cache invalidation")
	}
}

func TestBlastRadius_CacheInvalidationUsesVersioning(t *testing.T) {
	g := setupTestGraph()

	computeCalls := 0
	blastRadiusComputeHook = func(_ string, _ int) {
		computeCalls++
	}
	defer func() {
		blastRadiusComputeHook = nil
	}()

	if got := countBlastRadiusCacheEntries(g); got != 0 {
		t.Fatalf("expected empty blast radius cache, got %d entries", got)
	}

	BlastRadius(g, "user:alice", 3)
	BlastRadius(g, "user:bob", 3)
	if computeCalls != 2 {
		t.Fatalf("expected 2 blast radius computations, got %d", computeCalls)
	}
	if got := countBlastRadiusCacheEntries(g); got != 2 {
		t.Fatalf("expected 2 cached blast radius entries before mutation, got %d", got)
	}

	g.AddNode(&Node{
		ID:      "bucket:versioned-cache",
		Kind:    NodeKindBucket,
		Name:    "versioned-cache",
		Account: "111111111111",
		Risk:    RiskLow,
	})

	if got := countBlastRadiusCacheEntries(g); got != 2 {
		t.Fatalf("expected version invalidation to leave cached entries in place, got %d", got)
	}
	if !g.blastRadiusNeedsCompaction {
		t.Fatal("expected mutation to mark blast radius cache for deferred compaction")
	}

	BlastRadius(g, "user:alice", 3)
	if computeCalls != 3 {
		t.Fatalf("expected stale cache entry to force recomputation after mutation, got %d computations", computeCalls)
	}
	if got := countBlastRadiusCacheEntries(g); got != 1 {
		t.Fatalf("expected recomputation to compact stale cache entries, got %d entries", got)
	}
	if g.blastRadiusNeedsCompaction {
		t.Fatal("expected deferred compaction marker to clear after stale cache cleanup")
	}
}

func TestBlastRadius_DoesNotCacheMissingPrincipal(t *testing.T) {
	g := setupTestGraph()

	result := BlastRadius(g, "user:missing", 3)
	if result.PrincipalID != "user:missing" {
		t.Fatalf("expected missing principal result, got %#v", result.PrincipalID)
	}
	if got := countBlastRadiusCacheEntries(g); got != 0 {
		t.Fatalf("expected missing principal lookups to skip cache writes, got %d entries", got)
	}
}

func TestBlastRadius_DoesNotStoreStaleEntryAfterVersionAdvance(t *testing.T) {
	g := setupTestGraph()

	hooked := false
	blastRadiusCacheStoreHook = func(g *Graph, version uint64) {
		if hooked {
			return
		}
		hooked = true
		g.AddNode(&Node{
			ID:      "bucket:stale-write-race",
			Kind:    NodeKindBucket,
			Name:    "stale-write-race",
			Account: "111111111111",
			Risk:    RiskLow,
		})
	}
	defer func() {
		blastRadiusCacheStoreHook = nil
	}()

	result := BlastRadius(g, "user:alice", 3)
	if result.TotalCount == 0 {
		t.Fatal("expected blast radius results for alice")
	}
	if got := countBlastRadiusCacheEntries(g); got != 0 {
		t.Fatalf("expected stale version write to be skipped after graph mutation, got %d cache entries", got)
	}

	BlastRadius(g, "user:alice", 3)
	if got := countBlastRadiusCacheEntries(g); got != 1 {
		t.Fatalf("expected follow-up computation on current version to populate one cache entry, got %d", got)
	}
}

func TestBlastRadius_StaleWriterDoesNotCompactCurrentEntries(t *testing.T) {
	g := setupTestGraph()

	hooked := false
	blastRadiusCacheBeforeWriteHook = func(g *Graph, version uint64) {
		if hooked {
			return
		}
		hooked = true

		g.AddNode(&Node{
			ID:      "bucket:compaction-race",
			Kind:    NodeKindBucket,
			Name:    "compaction-race",
			Account: "111111111111",
			Risk:    RiskLow,
		})

		currentVersion := g.currentBlastRadiusCacheVersion()
		g.blastRadiusCache.Store(blastRadiusCacheKey{principalID: "user:bob", maxDepth: 3}, &cachedBlastRadius{
			version: currentVersion,
			result:  &BlastRadiusResult{PrincipalID: "user:bob"},
		})
	}
	defer func() {
		blastRadiusCacheBeforeWriteHook = nil
	}()

	staleVersion := g.currentBlastRadiusCacheVersion()
	g.putBlastRadiusInCache("user:alice", 3, staleVersion, &BlastRadiusResult{PrincipalID: "user:alice"})

	raw, ok := g.blastRadiusCache.Load(blastRadiusCacheKey{principalID: "user:bob", maxDepth: 3})
	if !ok {
		t.Fatal("expected current-version cache entry to survive stale writer")
	}
	cached, ok := raw.(*cachedBlastRadius)
	if !ok || cached == nil {
		t.Fatalf("expected cached blast radius entry, got %#v", raw)
	}
	if cached.version != g.currentBlastRadiusCacheVersion() {
		t.Fatalf("cached.version = %d, want current version %d", cached.version, g.currentBlastRadiusCacheVersion())
	}

	if _, ok := g.blastRadiusCache.Load(blastRadiusCacheKey{principalID: "user:alice", maxDepth: 3}); ok {
		t.Fatal("expected stale writer to skip caching its obsolete result")
	}
}

func TestBlastRadius_StaleReaderDoesNotDeleteFreshEntry(t *testing.T) {
	g := setupTestGraph()

	key := blastRadiusCacheKey{principalID: "user:alice", maxDepth: 3}
	g.blastRadiusCache.Store(key, &cachedBlastRadius{
		version: 0,
		result:  &BlastRadiusResult{PrincipalID: "user:alice"},
	})

	hooked := false
	blastRadiusCacheAfterLoadHook = func(g *Graph, loadedKey blastRadiusCacheKey) {
		if hooked {
			return
		}
		hooked = true
		if loadedKey != key {
			t.Fatalf("loaded key = %#v, want %#v", loadedKey, key)
		}
		g.blastRadiusCache.Store(key, &cachedBlastRadius{
			version: g.currentBlastRadiusCacheVersion(),
			result:  &BlastRadiusResult{PrincipalID: "user:alice", TotalCount: 42},
		})
	}
	defer func() {
		blastRadiusCacheAfterLoadHook = nil
	}()

	if cached, ok := g.getBlastRadiusFromCache("user:alice", 3); ok || cached != nil {
		t.Fatalf("expected stale loaded entry to miss cache, got (%#v, %v)", cached, ok)
	}

	raw, ok := g.blastRadiusCache.Load(key)
	if !ok {
		t.Fatal("expected fresh cache entry to remain after stale read miss")
	}
	cached, ok := raw.(*cachedBlastRadius)
	if !ok || cached == nil {
		t.Fatalf("expected cached blast radius entry, got %#v", raw)
	}
	if cached.version != g.currentBlastRadiusCacheVersion() {
		t.Fatalf("cached.version = %d, want current version %d", cached.version, g.currentBlastRadiusCacheVersion())
	}
	if cached.result == nil || cached.result.TotalCount != 42 {
		t.Fatalf("cached.result = %#v, want TotalCount 42", cached.result)
	}
}

func TestBlastRadius_CompactionRetainsFlagAcrossConcurrentMutation(t *testing.T) {
	g := setupTestGraph()

	key := blastRadiusCacheKey{principalID: "user:alice", maxDepth: 3}
	g.blastRadiusCache.Store(key, &cachedBlastRadius{
		version: 0,
		result:  &BlastRadiusResult{PrincipalID: "user:alice"},
	})

	g.mu.Lock()
	g.blastRadiusNeedsCompaction = true
	version := g.blastRadiusVersion
	g.mu.Unlock()

	hooked := false
	blastRadiusCacheAfterCompactionScanHook = func(g *Graph, scannedVersion uint64, removed int) {
		if hooked {
			return
		}
		hooked = true
		if scannedVersion != version {
			t.Fatalf("scannedVersion = %d, want %d", scannedVersion, version)
		}
		if removed != 1 {
			t.Fatalf("removed = %d, want 1", removed)
		}
		g.AddNode(&Node{
			ID:      "bucket:compaction-flag-race",
			Kind:    NodeKindBucket,
			Name:    "compaction-flag-race",
			Account: "111111111111",
		})
	}
	defer func() {
		blastRadiusCacheAfterCompactionScanHook = nil
	}()

	g.maybeCompactStaleBlastRadiusCache(version)

	if !g.blastRadiusNeedsCompaction {
		t.Fatal("expected concurrent mutation to keep compaction flag set")
	}
	if got := g.currentBlastRadiusCacheVersion(); got == version {
		t.Fatalf("expected graph version to advance, still %d", got)
	}
	if got := countBlastRadiusCacheEntries(g); got != 0 {
		t.Fatalf("expected stale cache entry to be removed, got %d entries", got)
	}
}

func countBlastRadiusCacheEntries(g *Graph) int {
	count := 0
	g.blastRadiusCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func TestReverseAccess(t *testing.T) {
	g := setupTestGraph()

	t.Run("sensitive bucket reverse access", func(t *testing.T) {
		result := ReverseAccess(g, "bucket:sensitive", 3)

		if result.ResourceID != "bucket:sensitive" {
			t.Errorf("expected resource ID bucket:sensitive, got %s", result.ResourceID)
		}

		// Should find alice (via admin role)
		foundAlice := false
		for _, acc := range result.AccessibleBy {
			if acc.Node.ID == "user:alice" {
				foundAlice = true
			}
		}
		if !foundAlice {
			t.Error("expected alice to have access to sensitive bucket")
		}
	})

	t.Run("production db reverse access", func(t *testing.T) {
		result := ReverseAccess(g, "db:production", 3)

		// Should find path from alice through admin and cross-account roles
		if result.TotalCount == 0 {
			t.Error("expected at least one accessor for production db")
		}
	})
}

func TestEffectiveAccess(t *testing.T) {
	g := setupTestGraph()

	t.Run("alice to sensitive bucket - allowed", func(t *testing.T) {
		result := EffectiveAccess(g, "user:alice", "bucket:sensitive", 3)

		if !result.Allowed {
			t.Error("expected alice to have access to sensitive bucket")
		}
	})

	t.Run("bob to public bucket - allowed", func(t *testing.T) {
		result := EffectiveAccess(g, "user:bob", "bucket:public", 3)

		if !result.Allowed {
			t.Error("expected bob to have access to public bucket")
		}
	})

	t.Run("bob to production db - denied", func(t *testing.T) {
		result := EffectiveAccess(g, "user:bob", "db:production", 3)

		if result.Allowed {
			t.Error("expected bob to NOT have access to production db")
		}
	})
}

func TestEffectiveAccess_CycleHandling(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:cycle", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:a", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "role:b", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "bucket:cycle", Kind: NodeKindBucket, Account: "111"})

	g.AddEdge(&Edge{ID: "u-a", Source: "user:cycle", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "a-b", Source: "role:a", Target: "role:b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "b-a", Source: "role:b", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "b-bucket", Source: "role:b", Target: "bucket:cycle", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	result := EffectiveAccess(g, "user:cycle", "bucket:cycle", 6)
	if !result.Allowed {
		t.Fatal("expected cycle traversal to find allowed access")
	}
	if len(result.AllowedBy) != 3 {
		t.Fatalf("expected 3 edges in allowed path, got %d", len(result.AllowedBy))
	}
}

func TestBlastRadius_DepthLimit(t *testing.T) {
	g := New()

	// Create a deep chain: user -> role1 -> role2 -> role3 -> resource
	g.AddNode(&Node{ID: "user:deep", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:1", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "role:2", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "role:3", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "bucket:deep", Kind: NodeKindBucket, Account: "111"})

	g.AddEdge(&Edge{ID: "e1", Source: "user:deep", Target: "role:1", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "role:1", Target: "role:2", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "role:2", Target: "role:3", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e4", Source: "role:3", Target: "bucket:deep", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	t.Run("depth 2 should not reach bucket", func(t *testing.T) {
		result := BlastRadius(g, "user:deep", 2)
		if result.TotalCount != 0 {
			t.Errorf("with depth 2, should not reach bucket, got %d resources", result.TotalCount)
		}
	})

	t.Run("depth 4 should reach bucket", func(t *testing.T) {
		result := BlastRadius(g, "user:deep", 4)
		if result.TotalCount != 1 {
			t.Errorf("with depth 4, should reach 1 resource, got %d", result.TotalCount)
		}
	})
}

func TestBlastRadius_CycleHandling(t *testing.T) {
	g := New()

	// Create a cycle: role1 -> role2 -> role1
	g.AddNode(&Node{ID: "role:cycle1", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "role:cycle2", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "bucket:cycle", Kind: NodeKindBucket, Account: "111"})

	g.AddEdge(&Edge{ID: "e1", Source: "role:cycle1", Target: "role:cycle2", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "role:cycle2", Target: "role:cycle1", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "role:cycle2", Target: "bucket:cycle", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	// Should not infinite loop
	result := BlastRadius(g, "role:cycle1", 10)
	if result.TotalCount != 1 {
		t.Errorf("expected 1 reachable resource despite cycle, got %d", result.TotalCount)
	}
}

func TestBlastRadius_DenyPreventsAccess(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:denied", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "bucket:denied", Kind: NodeKindBucket, Account: "111"})

	// Allow edge
	g.AddEdge(&Edge{ID: "e1", Source: "user:denied", Target: "bucket:denied", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	// Deny edge with higher priority
	g.AddEdge(&Edge{ID: "e2", Source: "user:denied", Target: "bucket:denied", Kind: EdgeKindCanRead, Effect: EdgeEffectDeny, Priority: 100})

	result := BlastRadius(g, "user:denied", 3)
	if result.TotalCount != 0 {
		t.Errorf("deny should block access, but got %d resources", result.TotalCount)
	}
}

func TestReverseAccess_MultiplePathsToResource(t *testing.T) {
	g := New()

	// Multiple users can access the same resource
	g.AddNode(&Node{ID: "user:multi1", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "user:multi2", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:shared", Kind: NodeKindRole, Account: "111"})
	g.AddNode(&Node{ID: "bucket:shared", Kind: NodeKindBucket, Account: "111"})

	// Direct access
	g.AddEdge(&Edge{ID: "e1", Source: "user:multi1", Target: "bucket:shared", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	// Via role
	g.AddEdge(&Edge{ID: "e2", Source: "user:multi2", Target: "role:shared", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "role:shared", Target: "bucket:shared", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow})

	result := ReverseAccess(g, "bucket:shared", 3)
	// Should find: user:multi1 (direct), role:shared, user:multi2 (via role)
	// The role is also an identity that can access
	if result.TotalCount < 2 {
		t.Errorf("expected at least 2 accessors, got %d", result.TotalCount)
	}

	// Check we found user:multi1
	foundMulti1 := false
	foundMulti2 := false
	for _, acc := range result.AccessibleBy {
		if acc.Node.ID == "user:multi1" {
			foundMulti1 = true
		}
		if acc.Node.ID == "user:multi2" {
			foundMulti2 = true
		}
	}
	if !foundMulti1 {
		t.Error("expected to find user:multi1")
	}
	if !foundMulti2 {
		t.Error("expected to find user:multi2")
	}
}

func TestBlastRadius_CrossAccountTracking(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "user:source", Kind: NodeKindUser, Account: "111111111111"})
	g.AddNode(&Node{ID: "role:target", Kind: NodeKindRole, Account: "222222222222"})
	g.AddNode(&Node{ID: "bucket:target", Kind: NodeKindBucket, Account: "222222222222"})

	g.AddEdge(&Edge{
		ID: "e1", Source: "user:source", Target: "role:target",
		Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow,
		Properties: map[string]any{"cross_account": true, "target_account": "222222222222"},
	})
	g.AddEdge(&Edge{ID: "e2", Source: "role:target", Target: "bucket:target", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	result := BlastRadius(g, "user:source", 3)

	if !result.CrossAccountRisk {
		t.Error("expected cross-account risk to be detected")
	}
	if len(result.ForeignAccounts) != 1 || result.ForeignAccounts[0] != "222222222222" {
		t.Errorf("expected foreign account 222222222222, got %v", result.ForeignAccounts)
	}
}

func TestBlastRadius_ParallelMatchesSequentialWideFrontier(t *testing.T) {
	single := runBlastRadiusWithWorkers(setupWideBlastRadiusGraph(), 1)
	parallel := runBlastRadiusWithWorkers(setupWideBlastRadiusGraph(), 8)

	assertBlastRadiusResultsEqual(t, single, parallel)
}

func TestReverseAccess_ParallelMatchesSequentialWideFrontier(t *testing.T) {
	single := runReverseAccessWithWorkers(setupWideReverseAccessGraph(), 1)
	parallel := runReverseAccessWithWorkers(setupWideReverseAccessGraph(), 8)

	assertReverseAccessResultsEqual(t, single, parallel)
}

func TestEffectiveAccess_ParallelMatchesSequentialWideGraph(t *testing.T) {
	single := runEffectiveAccessWithWorkers(newEffectiveAccessBenchmarkGraph(5, 3), 1)
	parallel := runEffectiveAccessWithWorkers(newEffectiveAccessBenchmarkGraph(5, 3), 8)

	assertEffectiveAccessResultsEqual(t, single, parallel)
}

func runBlastRadiusWithWorkers(g *Graph, workers int) *BlastRadiusResult {
	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = workers
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()
	return BlastRadius(g, "user:wide", 4)
}

func runReverseAccessWithWorkers(g *Graph, workers int) *ReverseAccessResult {
	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = workers
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()
	return ReverseAccess(g, "bucket:wide-target", 4)
}

func runEffectiveAccessWithWorkers(g *Graph, workers int) *EffectiveAccessResult {
	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = workers
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()
	return EffectiveAccess(g, "user:start", "bucket:target", 8)
}

func setupWideBlastRadiusGraph() *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:wide", Kind: NodeKindUser, Account: "111111111111"})
	g.AddNode(&Node{ID: "role:shared-wide", Kind: NodeKindRole, Account: "222222222222"})
	g.AddNode(&Node{ID: "bucket:shared-wide", Kind: NodeKindBucket, Account: "222222222222", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "shared-wide-resource", Source: "role:shared-wide", Target: "bucket:shared-wide", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	for i := 0; i < 96; i++ {
		roleID := fmt.Sprintf("role:wide-%03d", i)
		bucketID := fmt.Sprintf("bucket:wide-%03d", i)
		accountID := "111111111111"
		risk := RiskLow
		edgeProps := map[string]any{}
		if i%12 == 0 {
			accountID = "222222222222"
			edgeProps["cross_account"] = true
			edgeProps["target_account"] = accountID
			risk = RiskHigh
		}
		if i%10 == 0 {
			risk = RiskCritical
		}

		g.AddNode(&Node{ID: roleID, Kind: NodeKindRole, Account: accountID})
		g.AddNode(&Node{ID: bucketID, Kind: NodeKindBucket, Account: accountID, Risk: risk})
		g.AddEdge(&Edge{ID: fmt.Sprintf("user-wide-%03d", i), Source: "user:wide", Target: roleID, Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow, Properties: edgeProps})
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("role-wide-bucket-%03d", i),
			Source:     roleID,
			Target:     bucketID,
			Kind:       EdgeKindCanRead,
			Effect:     EdgeEffectAllow,
			Properties: map[string]any{"actions": []string{"s3:GetObject"}},
		})
		if i%3 == 0 {
			g.AddEdge(&Edge{
				ID:         fmt.Sprintf("role-wide-shared-%03d", i),
				Source:     roleID,
				Target:     "role:shared-wide",
				Kind:       EdgeKindCanAssume,
				Effect:     EdgeEffectAllow,
				Properties: map[string]any{"cross_account": true, "target_account": "222222222222"},
			})
		}
	}

	return g
}

func setupWideReverseAccessGraph() *Graph {
	g := New()
	g.AddNode(&Node{ID: "bucket:wide-target", Kind: NodeKindBucket, Account: "111111111111", Risk: RiskHigh})

	for i := 0; i < 96; i++ {
		roleID := fmt.Sprintf("role:reverse-%03d", i)
		userID := fmt.Sprintf("user:reverse-%03d", i)
		g.AddNode(&Node{ID: roleID, Kind: NodeKindRole, Account: "111111111111"})
		g.AddNode(&Node{ID: userID, Kind: NodeKindUser, Account: "111111111111"})
		g.AddEdge(&Edge{ID: fmt.Sprintf("reverse-role-target-%03d", i), Source: roleID, Target: "bucket:wide-target", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
		g.AddEdge(&Edge{ID: fmt.Sprintf("reverse-user-role-%03d", i), Source: userID, Target: roleID, Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	}

	return g
}

func assertBlastRadiusResultsEqual(t *testing.T, want, got *BlastRadiusResult) {
	t.Helper()

	if want.PrincipalID != got.PrincipalID || want.PrincipalName != got.PrincipalName {
		t.Fatalf("principal mismatch: want %s/%s got %s/%s", want.PrincipalID, want.PrincipalName, got.PrincipalID, got.PrincipalName)
	}
	if want.TotalCount != got.TotalCount || want.MaxDepth != got.MaxDepth || want.CrossAccountRisk != got.CrossAccountRisk || want.AccountsReached != got.AccountsReached || want.RiskSummary != got.RiskSummary {
		t.Fatalf("blast radius summary mismatch: want %#v got %#v", want, got)
	}

	wantAccounts := append([]string(nil), want.ForeignAccounts...)
	gotAccounts := append([]string(nil), got.ForeignAccounts...)
	sort.Strings(wantAccounts)
	sort.Strings(gotAccounts)
	if len(wantAccounts) != len(gotAccounts) {
		t.Fatalf("foreign account count mismatch: want %v got %v", wantAccounts, gotAccounts)
	}
	for i := range wantAccounts {
		if wantAccounts[i] != gotAccounts[i] {
			t.Fatalf("foreign accounts mismatch: want %v got %v", wantAccounts, gotAccounts)
		}
	}

	if len(want.ReachableNodes) != len(got.ReachableNodes) {
		t.Fatalf("reachable node count mismatch: want %d got %d", len(want.ReachableNodes), len(got.ReachableNodes))
	}
	for i := range want.ReachableNodes {
		assertReachableNodeEqual(t, want.ReachableNodes[i], got.ReachableNodes[i], i)
	}
}

func assertReachableNodeEqual(t *testing.T, want, got *ReachableNode, index int) {
	t.Helper()

	if want.Node.ID != got.Node.ID || want.Depth != got.Depth || want.EdgeKind != got.EdgeKind {
		t.Fatalf("reachable node %d mismatch: want %#v got %#v", index, want, got)
	}
	if len(want.Path) != len(got.Path) || len(want.Actions) != len(got.Actions) {
		t.Fatalf("reachable node %d path/action length mismatch: want %#v got %#v", index, want, got)
	}
	for i := range want.Path {
		if want.Path[i] != got.Path[i] {
			t.Fatalf("reachable node %d path mismatch: want %v got %v", index, want.Path, got.Path)
		}
	}
	for i := range want.Actions {
		if want.Actions[i] != got.Actions[i] {
			t.Fatalf("reachable node %d actions mismatch: want %v got %v", index, want.Actions, got.Actions)
		}
	}
}

func assertEffectiveAccessResultsEqual(t *testing.T, want, got *EffectiveAccessResult) {
	t.Helper()

	if want.PrincipalID != got.PrincipalID || want.ResourceID != got.ResourceID || want.Allowed != got.Allowed {
		t.Fatalf("effective access summary mismatch: want %#v got %#v", want, got)
	}
	assertEdgeMultisetEqual(t, want.AllowedBy, got.AllowedBy, "allowed_by")
	assertEdgeMultisetEqual(t, want.DeniedBy, got.DeniedBy, "denied_by")
}

func assertEdgeMultisetEqual(t *testing.T, want, got []*Edge, label string) {
	t.Helper()

	if len(want) != len(got) {
		t.Fatalf("%s edge count mismatch: want %d got %d", label, len(want), len(got))
	}
	wantCounts := make(map[string]int, len(want))
	for _, edge := range want {
		wantCounts[edge.ID]++
	}
	gotCounts := make(map[string]int, len(got))
	for _, edge := range got {
		gotCounts[edge.ID]++
	}
	if !reflect.DeepEqual(wantCounts, gotCounts) {
		t.Fatalf("%s mismatch: want %v got %v", label, wantCounts, gotCounts)
	}
}

func assertReverseAccessResultsEqual(t *testing.T, want, got *ReverseAccessResult) {
	t.Helper()

	if want.ResourceID != got.ResourceID || want.ResourceName != got.ResourceName || want.TotalCount != got.TotalCount {
		t.Fatalf("reverse access summary mismatch: want %#v got %#v", want, got)
	}
	if len(want.AccessibleBy) != len(got.AccessibleBy) {
		t.Fatalf("accessible-by count mismatch: want %d got %d", len(want.AccessibleBy), len(got.AccessibleBy))
	}
	for i := range want.AccessibleBy {
		wantAccessor := want.AccessibleBy[i]
		gotAccessor := got.AccessibleBy[i]
		if wantAccessor.Node.ID != gotAccessor.Node.ID || wantAccessor.EdgeKind != gotAccessor.EdgeKind {
			t.Fatalf("accessible-by %d mismatch: want %#v got %#v", i, wantAccessor, gotAccessor)
		}
		if len(wantAccessor.Path) != len(gotAccessor.Path) || len(wantAccessor.Actions) != len(gotAccessor.Actions) {
			t.Fatalf("accessible-by %d path/action length mismatch: want %#v got %#v", i, wantAccessor, gotAccessor)
		}
		for j := range wantAccessor.Path {
			if wantAccessor.Path[j] != gotAccessor.Path[j] {
				t.Fatalf("accessible-by %d path mismatch: want %v got %v", i, wantAccessor.Path, gotAccessor.Path)
			}
		}
		for j := range wantAccessor.Actions {
			if wantAccessor.Actions[j] != gotAccessor.Actions[j] {
				t.Fatalf("accessible-by %d actions mismatch: want %v got %v", i, wantAccessor.Actions, gotAccessor.Actions)
			}
		}
	}
}

func TestCascadingBlastRadius(t *testing.T) {
	g := New()

	// Create a graph with sensitive data nodes
	g.AddNode(&Node{
		ID: "user:attacker", Kind: NodeKindUser, Name: "attacker", Account: "111111111111",
	})
	g.AddNode(&Node{
		ID: "role:admin", Kind: NodeKindRole, Name: "admin", Account: "111111111111",
	})
	g.AddNode(&Node{
		ID: "bucket:pii-data", Kind: NodeKindBucket, Name: "pii-data", Account: "111111111111",
		Risk:       RiskCritical,
		Properties: map[string]any{"contains_pii": true, "data_classification": "confidential"},
	})
	g.AddNode(&Node{
		ID: "bucket:pci-data", Kind: NodeKindBucket, Name: "pci-data", Account: "111111111111",
		Risk:       RiskCritical,
		Properties: map[string]any{"contains_pci": true},
	})
	g.AddNode(&Node{
		ID: "secret:db-credentials", Kind: NodeKindSecret, Name: "db-credentials", Account: "111111111111",
		Risk: RiskHigh,
	})
	g.AddNode(&Node{
		ID: "bucket:cross-account", Kind: NodeKindBucket, Name: "cross-account", Account: "222222222222",
		Risk: RiskMedium,
	})

	// Create edges
	g.AddEdge(&Edge{ID: "e1", Source: "user:attacker", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "role:admin", Target: "bucket:pii-data", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "role:admin", Target: "bucket:pci-data", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e4", Source: "role:admin", Target: "secret:db-credentials", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{
		ID: "e5", Source: "role:admin", Target: "bucket:cross-account", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow,
		Properties: map[string]any{"cross_account": true, "target_account": "222222222222"},
	})

	t.Run("cascading blast radius detects sensitive data", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:attacker", 4)

		if result.TotalImpact < 4 {
			t.Errorf("expected at least 4 impacted nodes, got %d", result.TotalImpact)
		}

		if len(result.SensitiveDataHits) < 2 {
			t.Errorf("expected at least 2 sensitive data hits (PII, PCI), got %d", len(result.SensitiveDataHits))
		}

		// Check for PII detection
		foundPII := false
		for _, hit := range result.SensitiveDataHits {
			for _, dt := range hit.DataTypes {
				if dt == "PII" {
					foundPII = true
					break
				}
			}
		}
		if !foundPII {
			t.Error("expected PII to be detected in sensitive data hits")
		}
	})

	t.Run("cascading blast radius tracks time to compromise", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:attacker", 4)

		// Depth 1 should have the admin role
		if len(result.TimeToCompromise[1]) == 0 {
			t.Error("expected nodes at depth 1 (admin role)")
		}

		// Depth 2 should have the resources
		if len(result.TimeToCompromise[2]) < 3 {
			t.Errorf("expected at least 3 nodes at depth 2, got %d", len(result.TimeToCompromise[2]))
		}

		// Check that time estimates are reasonable
		for _, node := range result.TimeToCompromise[2] {
			if node.EstimatedTimeMs <= 0 {
				t.Errorf("expected positive time estimate, got %d", node.EstimatedTimeMs)
			}
		}
	})

	t.Run("cascading blast radius detects account boundaries", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:attacker", 4)

		if len(result.AccountBoundaries) == 0 {
			t.Error("expected account boundary crossing to be detected")
		}

		found := false
		for _, cross := range result.AccountBoundaries {
			if cross.ToAccount == "222222222222" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected crossing to account 222222222222")
		}
	})

	t.Run("cascading blast radius handles cycles without duplicating impact", func(t *testing.T) {
		cycleGraph := New()
		cycleGraph.AddNode(&Node{ID: "user:start", Kind: NodeKindUser})
		cycleGraph.AddNode(&Node{ID: "role:a", Kind: NodeKindRole})
		cycleGraph.AddNode(&Node{ID: "role:b", Kind: NodeKindRole})
		cycleGraph.AddEdge(&Edge{ID: "start-a", Source: "user:start", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
		cycleGraph.AddEdge(&Edge{ID: "a-b", Source: "role:a", Target: "role:b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
		cycleGraph.AddEdge(&Edge{ID: "b-a", Source: "role:b", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

		result := CascadingBlastRadius(cycleGraph, "user:start", 6)

		if got := result.TotalImpact; got != 2 {
			t.Fatalf("TotalImpact = %d, want 2", got)
		}
		if got := len(result.TimeToCompromise[1]); got != 1 {
			t.Fatalf("depth 1 impacted count = %d, want 1", got)
		}
		if got := len(result.TimeToCompromise[2]); got != 1 {
			t.Fatalf("depth 2 impacted count = %d, want 1", got)
		}
	})

	t.Run("cascading blast radius calculates impact score", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:attacker", 4)

		if result.ImpactScore <= 0 {
			t.Error("expected positive impact score")
		}

		// With sensitive data and cross-account, score should be significant
		if result.ImpactScore < 20 {
			t.Errorf("expected impact score >= 20 with sensitive data, got %f", result.ImpactScore)
		}
	})

	t.Run("cascading blast radius provides remediation suggestions", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:attacker", 4)

		if len(result.RemediationPaths) == 0 {
			t.Error("expected remediation suggestions")
		}
	})

	t.Run("cascading blast radius handles non-existent source", func(t *testing.T) {
		result := CascadingBlastRadius(g, "user:nonexistent", 4)

		if result.TotalImpact != 0 {
			t.Errorf("expected 0 impact for non-existent source, got %d", result.TotalImpact)
		}
	})
}

func TestCascadingBlastRadius_BestTimeFallsBackForInvalidOrdinals(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Name: "start"})
	g.AddNode(&Node{ID: "role:a", Kind: NodeKindRole, Name: "role-a"})
	g.AddNode(&Node{ID: "role:b", Kind: NodeKindRole, Name: "role-b"})
	g.AddEdge(&Edge{ID: "start-a", Source: "user:start", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "start-b", Source: "user:start", Target: "role:b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	g.mu.Lock()
	g.nodes["user:start"].ordinal = InvalidNodeOrdinal
	g.edgeByID["start-a"].targetOrd = InvalidNodeOrdinal
	g.edgeByID["start-b"].targetOrd = InvalidNodeOrdinal
	g.mu.Unlock()

	result := CascadingBlastRadius(g, "user:start", 2)
	if got := result.TotalImpact; got != 2 {
		t.Fatalf("TotalImpact = %d, want 2", got)
	}
	if got := len(result.TimeToCompromise[1]); got != 2 {
		t.Fatalf("depth 1 impacted count = %d, want 2", got)
	}

	reached := make(map[string]struct{}, len(result.TimeToCompromise[1]))
	for _, node := range result.TimeToCompromise[1] {
		reached[node.Node.ID] = struct{}{}
	}
	if _, ok := reached["role:a"]; !ok {
		t.Fatal("expected role:a to remain reachable with invalid ordinals")
	}
	if _, ok := reached["role:b"]; !ok {
		t.Fatal("expected role:b to remain reachable with invalid ordinals")
	}
}

func TestDetectSensitiveData(t *testing.T) {
	t.Run("detects PII", func(t *testing.T) {
		node := &Node{
			ID:   "test",
			Name: "user-data",
			Properties: map[string]any{
				"contains_pii": true,
			},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "PII") {
			t.Error("expected PII in data types")
		}
		if !sliceContains(result.ComplianceImpact, "GDPR") {
			t.Error("expected GDPR in compliance impact")
		}
	})

	t.Run("detects PHI", func(t *testing.T) {
		node := &Node{
			ID:   "test",
			Name: "health-records",
			Properties: map[string]any{
				"contains_phi": true,
			},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "PHI") {
			t.Error("expected PHI in data types")
		}
		if !sliceContains(result.ComplianceImpact, "HIPAA") {
			t.Error("expected HIPAA in compliance impact")
		}
	})

	t.Run("detects PCI", func(t *testing.T) {
		node := &Node{
			ID:   "test",
			Name: "payment-data",
			Properties: map[string]any{
				"contains_pci": true,
			},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "PCI") {
			t.Error("expected PCI in data types")
		}
		if !sliceContains(result.ComplianceImpact, "PCI-DSS") {
			t.Error("expected PCI-DSS in compliance impact")
		}
	})

	t.Run("detects credentials by node kind", func(t *testing.T) {
		node := &Node{
			ID:         "test",
			Kind:       NodeKindSecret,
			Name:       "api-key",
			Properties: map[string]any{},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "credentials") {
			t.Error("expected credentials in data types")
		}
	})

	t.Run("detects secrets from DSPM properties", func(t *testing.T) {
		node := &Node{
			ID:   "test",
			Name: "archive-bucket",
			Properties: map[string]any{
				"contains_secrets": true,
			},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "secrets") {
			t.Error("expected secrets in data types")
		}
		if !sliceContains(result.ComplianceImpact, "SOC2") {
			t.Error("expected SOC2 in compliance impact")
		}
	})

	t.Run("deduplicates SOC2 for secrets with sensitive classification", func(t *testing.T) {
		node := &Node{
			ID:   "test",
			Name: "restricted-archive-bucket",
			Properties: map[string]any{
				"data_classification": "restricted",
				"contains_secrets":    true,
			},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}

		soc2Count := 0
		for _, framework := range result.ComplianceImpact {
			if framework == "SOC2" {
				soc2Count++
			}
		}
		if soc2Count != 1 {
			t.Errorf("expected SOC2 once in compliance impact, got %d entries: %v", soc2Count, result.ComplianceImpact)
		}
	})

	t.Run("detects sensitive by name pattern", func(t *testing.T) {
		node := &Node{
			ID:         "test",
			Name:       "backup-password-store",
			Properties: map[string]any{},
		}
		result := detectSensitiveData(node)
		if result == nil {
			t.Fatal("expected sensitive data detection")
		}
		if !sliceContains(result.DataTypes, "sensitive_by_name") {
			t.Error("expected sensitive_by_name in data types")
		}
	})

	t.Run("returns nil for non-sensitive nodes", func(t *testing.T) {
		node := &Node{
			ID:         "test",
			Name:       "public-assets",
			Properties: map[string]any{},
		}
		result := detectSensitiveData(node)
		if result != nil {
			t.Error("expected nil for non-sensitive node")
		}
	})
}

func TestEstimateCompromiseTime(t *testing.T) {
	target := &Node{ID: "target", Risk: RiskMedium}

	tests := []struct {
		name         string
		edgeKind     EdgeKind
		crossAccount bool
		criticalRisk bool
		minTime      int64
		maxTime      int64
	}{
		{"role assumption is fast", EdgeKindCanAssume, false, false, 4000, 6000},
		{"read permission", EdgeKindCanRead, false, false, 25000, 35000},
		{"write permission", EdgeKindCanWrite, false, false, 40000, 50000},
		{"cross-account doubles time", EdgeKindCanAssume, true, false, 8000, 12000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edge := &Edge{Kind: tt.edgeKind}
			if tt.crossAccount {
				edge.Properties = map[string]any{"cross_account": true}
			}
			testTarget := target
			if tt.criticalRisk {
				testTarget = &Node{ID: "critical", Risk: RiskCritical}
			}

			time := estimateCompromiseTime(edge, testTarget)
			if time < tt.minTime || time > tt.maxTime {
				t.Errorf("expected time between %d and %d, got %d", tt.minTime, tt.maxTime, time)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"secret-key", "secret", true},
		{"SECRET-KEY", "secret", true},
		{"my-Secret-data", "secret", true},
		{"public-data", "secret", false},
		{"", "secret", false},
		{"secret", "", true},
		{"password", "PASSWORD", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsIgnoreCase(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}
