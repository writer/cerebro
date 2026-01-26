package graph

import (
	"testing"
)

func setupIAMTestGraph() *Graph {
	g := New()

	// Add users
	g.AddNode(&Node{
		ID:       "user:alice",
		Kind:     NodeKindUser,
		Name:     "alice",
		Account:  "111111111111",
		Provider: "aws",
	})
	g.AddNode(&Node{
		ID:       "user:bob",
		Kind:     NodeKindUser,
		Name:     "bob",
		Account:  "111111111111",
		Provider: "aws",
	})
	g.AddNode(&Node{
		ID:       "user:charlie",
		Kind:     NodeKindUser,
		Name:     "charlie",
		Account:  "111111111111",
		Provider: "aws",
		Properties: map[string]any{
			"permission_boundary": "boundary:restricted",
		},
	})

	// Add groups
	g.AddNode(&Node{
		ID:       "group:developers",
		Kind:     NodeKindGroup,
		Name:     "developers",
		Account:  "111111111111",
		Provider: "aws",
	})
	g.AddNode(&Node{
		ID:       "group:admins",
		Kind:     NodeKindGroup,
		Name:     "admins",
		Account:  "111111111111",
		Provider: "aws",
	})

	// Add roles
	g.AddNode(&Node{
		ID:       "role:readonly",
		Kind:     NodeKindRole,
		Name:     "readonly",
		Account:  "111111111111",
		Provider: "aws",
	})
	g.AddNode(&Node{
		ID:       "role:admin",
		Kind:     NodeKindRole,
		Name:     "admin",
		Account:  "111111111111",
		Provider: "aws",
	})
	g.AddNode(&Node{
		ID:       "role:cross-account",
		Kind:     NodeKindRole,
		Name:     "cross-account",
		Account:  "222222222222",
		Provider: "aws",
	})

	// Add resources
	g.AddNode(&Node{
		ID:       "bucket:data",
		Kind:     NodeKindBucket,
		Name:     "data-bucket",
		Account:  "111111111111",
		Provider: "aws",
		Risk:     RiskHigh,
	})
	g.AddNode(&Node{
		ID:       "bucket:logs",
		Kind:     NodeKindBucket,
		Name:     "logs-bucket",
		Account:  "111111111111",
		Provider: "aws",
		Risk:     RiskMedium,
	})
	g.AddNode(&Node{
		ID:       "db:production",
		Kind:     NodeKindDatabase,
		Name:     "production-db",
		Account:  "111111111111",
		Provider: "aws",
		Risk:     RiskCritical,
	})
	g.AddNode(&Node{
		ID:       "secret:api-key",
		Kind:     NodeKindSecret,
		Name:     "api-key",
		Account:  "111111111111",
		Provider: "aws",
		Risk:     RiskCritical,
	})
	g.AddNode(&Node{
		ID:       "bucket:external",
		Kind:     NodeKindBucket,
		Name:     "external-bucket",
		Account:  "222222222222",
		Provider: "aws",
		Risk:     RiskMedium,
	})

	// Add permission boundary
	g.AddNode(&Node{
		ID:       "boundary:restricted",
		Kind:     NodeKindPermissionBoundary,
		Name:     "restricted-boundary",
		Account:  "111111111111",
		Provider: "aws",
	})

	// Add SCP
	g.AddNode(&Node{
		ID:       "scp:deny-delete",
		Kind:     NodeKindSCP,
		Name:     "deny-delete-scp",
		Provider: "aws",
		Properties: map[string]any{
			"target_accounts": []string{"111111111111"},
		},
	})

	// --- Edges ---

	// alice is member of developers group
	g.AddEdge(&Edge{
		ID:     "e1",
		Source: "user:alice",
		Target: "group:developers",
		Kind:   EdgeKindMemberOf,
		Effect: EdgeEffectAllow,
	})

	// bob is member of admins group
	g.AddEdge(&Edge{
		ID:     "e2",
		Source: "user:bob",
		Target: "group:admins",
		Kind:   EdgeKindMemberOf,
		Effect: EdgeEffectAllow,
	})

	// developers group can read data bucket
	g.AddEdge(&Edge{
		ID:     "e3",
		Source: "group:developers",
		Target: "bucket:data",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	// alice can directly assume readonly role
	g.AddEdge(&Edge{
		ID:     "e4",
		Source: "user:alice",
		Target: "role:readonly",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	})

	// bob can directly assume admin role
	g.AddEdge(&Edge{
		ID:     "e5",
		Source: "user:bob",
		Target: "role:admin",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	})

	// readonly role can read logs bucket
	g.AddEdge(&Edge{
		ID:     "e6",
		Source: "role:readonly",
		Target: "bucket:logs",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	// admin role has full admin access to everything
	g.AddEdge(&Edge{
		ID:     "e7",
		Source: "role:admin",
		Target: "bucket:data",
		Kind:   EdgeKindCanAdmin,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:     "e8",
		Source: "role:admin",
		Target: "db:production",
		Kind:   EdgeKindCanAdmin,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:     "e9",
		Source: "role:admin",
		Target: "secret:api-key",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	// admin role can assume cross-account role
	g.AddEdge(&Edge{
		ID:     "e10",
		Source: "role:admin",
		Target: "role:cross-account",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	})

	// cross-account role can read external bucket
	g.AddEdge(&Edge{
		ID:     "e11",
		Source: "role:cross-account",
		Target: "bucket:external",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	// alice has direct deny on production db
	g.AddEdge(&Edge{
		ID:       "e12",
		Source:   "user:alice",
		Target:   "db:production",
		Kind:     EdgeKindCanWrite,
		Effect:   EdgeEffectDeny,
		Priority: 100,
	})

	// charlie can read data bucket directly
	g.AddEdge(&Edge{
		ID:     "e13",
		Source: "user:charlie",
		Target: "bucket:data",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:     "e14",
		Source: "user:charlie",
		Target: "bucket:logs",
		Kind:   EdgeKindCanWrite,
		Effect: EdgeEffectAllow,
	})

	// permission boundary only allows read access
	g.AddEdge(&Edge{
		ID:     "e15",
		Source: "boundary:restricted",
		Target: "*",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	// SCP denies delete on critical resources
	g.AddEdge(&Edge{
		ID:       "e16",
		Source:   "scp:deny-delete",
		Target:   "db:production",
		Kind:     EdgeKindCanDelete,
		Effect:   EdgeEffectDeny,
		Priority: 200,
	})

	return g
}

func TestEffectivePermissionsCalculator_Calculate(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("direct and group permissions", func(t *testing.T) {
		ep := calc.Calculate("user:alice")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		if ep.PrincipalID != "user:alice" {
			t.Errorf("expected principal ID user:alice, got %s", ep.PrincipalID)
		}

		// alice should have access to data bucket (via group)
		if _, ok := ep.Resources["bucket:data"]; !ok {
			t.Error("expected alice to have access to bucket:data via developers group")
		}
	})

	t.Run("role assumption permissions", func(t *testing.T) {
		ep := calc.Calculate("user:alice")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		// alice should have access to logs bucket (via developers -> readonly role)
		if _, ok := ep.Resources["bucket:logs"]; !ok {
			t.Error("expected alice to have access to bucket:logs via readonly role")
		}
	})

	t.Run("admin permissions", func(t *testing.T) {
		ep := calc.Calculate("user:bob")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		// bob should have admin access via admin role
		if access, ok := ep.Resources["bucket:data"]; !ok {
			t.Error("expected bob to have access to bucket:data via admin role")
		} else {
			// Should have wildcard admin access
			hasWildcard := false
			for _, a := range access.Actions {
				if a == "*" {
					hasWildcard = true
					break
				}
			}
			if !hasWildcard {
				t.Error("expected bob to have wildcard admin access")
			}
		}

		// bob should have access to secrets
		if _, ok := ep.Resources["secret:api-key"]; !ok {
			t.Error("expected bob to have access to secret:api-key via admin role")
		}
	})

	t.Run("cross-account access", func(t *testing.T) {
		ep := calc.Calculate("user:bob")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		// bob should have cross-account access to external bucket
		if _, ok := ep.Resources["bucket:external"]; !ok {
			t.Error("expected bob to have cross-account access to bucket:external")
		}

		if ep.Summary.CrossAccountAccess == 0 {
			t.Error("expected cross-account access count > 0")
		}
	})

	t.Run("nonexistent principal", func(t *testing.T) {
		ep := calc.Calculate("user:nonexistent")
		if ep != nil {
			t.Error("expected nil for nonexistent principal")
		}
	})
}

func TestEffectivePermissionsCalculator_DenyRules(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("direct deny edge", func(t *testing.T) {
		ep := calc.Calculate("user:alice")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		// alice should NOT have write access to production db due to explicit deny
		if access, ok := ep.Resources["db:production"]; ok {
			for _, a := range access.Actions {
				if a == "write" || a == "put" || a == "create" || a == "update" {
					t.Errorf("expected alice to NOT have write access to db:production, but has action: %s", a)
				}
			}
		}
	})
}

func TestEffectivePermissionsCalculator_PermissionBoundary(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("permission boundary limits actions", func(t *testing.T) {
		ep := calc.Calculate("user:charlie")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		// charlie has a permission boundary that only allows reads
		// so write access to logs bucket should be denied
		if access, ok := ep.Resources["bucket:logs"]; ok {
			for _, a := range access.Actions {
				if a == "write" || a == "put" || a == "create" || a == "update" {
					t.Errorf("expected charlie's write access to be limited by permission boundary, but has action: %s", a)
				}
			}
		}

		// charlie should still have read access to data bucket
		if _, ok := ep.Resources["bucket:data"]; !ok {
			t.Error("expected charlie to have read access to bucket:data (allowed by boundary)")
		}
	})
}

func TestEffectivePermissionsCalculator_Summary(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("summary statistics", func(t *testing.T) {
		ep := calc.Calculate("user:bob")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		if ep.Summary == nil {
			t.Fatal("expected summary, got nil")
		}

		if ep.Summary.TotalResources == 0 {
			t.Error("expected total resources > 0")
		}

		if ep.Summary.AdminAccess == 0 {
			t.Error("expected admin access count > 0 for bob")
		}

		if ep.Summary.ResourcesByType == nil {
			t.Error("expected resources by type map")
		}
	})
}

func TestEffectivePermissionsCalculator_RiskAssessment(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("high risk for admin user", func(t *testing.T) {
		ep := calc.Calculate("user:bob")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		if ep.RiskAssessment == nil {
			t.Fatal("expected risk assessment, got nil")
		}

		// bob has admin access, should have high risk
		if ep.RiskAssessment.RiskScore < 25 {
			t.Errorf("expected higher risk score for admin user, got %f", ep.RiskAssessment.RiskScore)
		}

		if len(ep.RiskAssessment.Findings) == 0 {
			t.Error("expected risk findings for admin user")
		}

		// Should have findings about secrets access
		foundSecretsAccess := false
		for _, f := range ep.RiskAssessment.Findings {
			if f.Type == "secrets_access" {
				foundSecretsAccess = true
				break
			}
		}
		if !foundSecretsAccess {
			t.Error("expected secrets_access finding for bob")
		}
	})

	t.Run("lower risk for limited user", func(t *testing.T) {
		ep := calc.Calculate("user:alice")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		if ep.RiskAssessment == nil {
			t.Fatal("expected risk assessment, got nil")
		}

		// alice has limited access, should have lower risk than bob
		epBob := calc.Calculate("user:bob")
		if ep.RiskAssessment.RiskScore >= epBob.RiskAssessment.RiskScore {
			t.Errorf("expected alice (%f) to have lower risk than bob (%f)",
				ep.RiskAssessment.RiskScore, epBob.RiskAssessment.RiskScore)
		}
	})
}

func TestEffectivePermissionsCalculator_InheritanceChain(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("tracks inheritance chain", func(t *testing.T) {
		ep := calc.Calculate("user:alice")
		if ep == nil {
			t.Fatal("expected effective permissions, got nil")
		}

		if len(ep.InheritanceChain) == 0 {
			t.Error("expected inheritance chain to be populated")
		}

		// Should have group and role sources
		hasGroupSource := false
		hasRoleSource := false
		for _, source := range ep.InheritanceChain {
			if source.Type == "group" {
				hasGroupSource = true
			}
			if source.Type == "role" {
				hasRoleSource = true
			}
		}

		if !hasGroupSource {
			t.Error("expected group source in inheritance chain")
		}
		if !hasRoleSource {
			t.Error("expected role source in inheritance chain")
		}
	})
}

func TestEffectivePermissionsCalculator_ComparePermissions(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("compare alice and bob", func(t *testing.T) {
		comparison := calc.ComparePermissions("user:alice", "user:bob")
		if comparison == nil {
			t.Fatal("expected comparison, got nil")
		}

		// bob should have more resources than alice
		if comparison.OnlyBCount == 0 {
			t.Error("expected bob to have resources alice doesn't")
		}

		// Should have common resources (bucket:data)
		if comparison.CommonCount == 0 {
			t.Error("expected common resources between alice and bob")
		}
	})

	t.Run("compare same principal", func(t *testing.T) {
		comparison := calc.ComparePermissions("user:alice", "user:alice")
		if comparison == nil {
			t.Fatal("expected comparison, got nil")
		}

		// Same principal should have no differences
		if comparison.OnlyACount != 0 || comparison.OnlyBCount != 0 {
			t.Error("expected no differences for same principal")
		}
	})
}

func TestEffectivePermissionsCalculator_GenerateLeastPrivilegePolicy(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("generates least privilege recommendations", func(t *testing.T) {
		// Simulate usage - alice only used read on data bucket
		usedActions := map[string][]string{
			"bucket:data": {"read"},
		}

		policy := calc.GenerateLeastPrivilegePolicy("user:alice", usedActions)
		if policy == nil {
			t.Fatal("expected policy, got nil")
		}

		// Should recommend removing access to unused resources
		if policy.TotalRemoved == 0 {
			t.Error("expected some actions to be removed")
		}

		// Should keep used actions
		if policy.TotalKept == 0 {
			t.Error("expected some actions to be kept")
		}

		// Reduction should be positive
		if policy.ReductionPercent <= 0 {
			t.Error("expected positive reduction percentage")
		}
	})

	t.Run("no usage data removes everything", func(t *testing.T) {
		usedActions := map[string][]string{}

		policy := calc.GenerateLeastPrivilegePolicy("user:alice", usedActions)
		if policy == nil {
			t.Fatal("expected policy, got nil")
		}

		// Should recommend removing all
		if policy.TotalKept != 0 {
			t.Errorf("expected zero kept actions with no usage, got %d", policy.TotalKept)
		}
	})
}

func TestEffectivePermissionsCalculator_Cache(t *testing.T) {
	g := setupIAMTestGraph()
	calc := NewEffectivePermissionsCalculator(g)

	t.Run("caches results", func(t *testing.T) {
		ep1 := calc.Calculate("user:alice")
		ep2 := calc.Calculate("user:alice")

		if ep1 != ep2 {
			t.Error("expected cached result to be returned")
		}
	})

	t.Run("clear cache works", func(t *testing.T) {
		ep1 := calc.Calculate("user:alice")
		calc.ClearCache()
		ep2 := calc.Calculate("user:alice")

		// After clearing cache, should get new object
		if ep1 == ep2 {
			t.Error("expected new object after cache clear")
		}
	})

	t.Run("invalidate cache by version", func(t *testing.T) {
		ep1 := calc.Calculate("user:alice")
		calc.InvalidateCache()
		ep2 := calc.Calculate("user:alice")

		// After version invalidation, should get new object
		if ep1 == ep2 {
			t.Error("expected new object after cache invalidation")
		}
	})

	t.Run("invalidate specific principal", func(t *testing.T) {
		ep1 := calc.Calculate("user:alice")
		epBob1 := calc.Calculate("user:bob")

		calc.InvalidatePrincipal("user:alice")

		ep2 := calc.Calculate("user:alice")
		epBob2 := calc.Calculate("user:bob")

		// Alice should be recalculated
		if ep1 == ep2 {
			t.Error("expected alice to be recalculated")
		}
		// Bob should still be cached
		if epBob1 != epBob2 {
			t.Error("expected bob to still be cached")
		}
	})
}

func TestEdgeKindToActions(t *testing.T) {
	testCases := []struct {
		kind     EdgeKind
		expected []string
	}{
		{EdgeKindCanRead, []string{"read", "get", "list", "describe"}},
		{EdgeKindCanWrite, []string{"write", "put", "create", "update"}},
		{EdgeKindCanDelete, []string{"delete", "remove"}},
		{EdgeKindCanAdmin, []string{"*"}},
	}

	for _, tc := range testCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			actions := edgeKindToActions(tc.kind)
			if len(actions) != len(tc.expected) {
				t.Errorf("expected %d actions, got %d", len(tc.expected), len(actions))
			}
		})
	}
}

func TestMergeActions(t *testing.T) {
	a := []string{"read", "write"}
	b := []string{"write", "delete"}
	result := mergeActions(a, b)

	expected := map[string]bool{"read": true, "write": true, "delete": true}
	if len(result) != len(expected) {
		t.Errorf("expected %d actions, got %d", len(expected), len(result))
	}

	for _, action := range result {
		if !expected[action] {
			t.Errorf("unexpected action: %s", action)
		}
	}
}

func TestRemoveActions(t *testing.T) {
	actions := []string{"read", "write", "delete", "admin"}
	toRemove := []string{"write", "admin"}
	result := removeActions(actions, toRemove)

	expected := map[string]bool{"read": true, "delete": true}
	if len(result) != len(expected) {
		t.Errorf("expected %d actions, got %d", len(expected), len(result))
	}

	for _, action := range result {
		if !expected[action] {
			t.Errorf("unexpected action: %s", action)
		}
	}
}

func TestSubtractActions(t *testing.T) {
	a := []string{"read", "write", "delete"}
	b := []string{"write"}
	result := subtractActions(a, b)

	expected := map[string]bool{"read": true, "delete": true}
	if len(result) != len(expected) {
		t.Errorf("expected %d actions, got %d", len(expected), len(result))
	}

	for _, action := range result {
		if !expected[action] {
			t.Errorf("unexpected action: %s", action)
		}
	}
}
