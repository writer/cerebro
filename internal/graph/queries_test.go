package graph

import (
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
