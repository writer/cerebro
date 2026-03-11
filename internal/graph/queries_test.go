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
