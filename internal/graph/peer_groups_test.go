package graph

import (
	"fmt"
	"testing"
)

func TestMinHashIndex_Basic(t *testing.T) {
	idx := NewMinHashIndex()

	// Create fingerprints with overlapping resources
	fp1 := &AccessFingerprint{
		PrincipalID: "user1",
		Resources:   map[string]bool{"r1": true, "r2": true, "r3": true},
		Account:     "account1",
	}
	fp2 := &AccessFingerprint{
		PrincipalID: "user2",
		Resources:   map[string]bool{"r1": true, "r2": true, "r3": true, "r4": true},
		Account:     "account1",
	}
	fp3 := &AccessFingerprint{
		PrincipalID: "user3",
		Resources:   map[string]bool{"r10": true, "r11": true, "r12": true},
		Account:     "account1",
	}

	idx.Add(fp1)
	idx.Add(fp2)
	idx.Add(fp3)

	// user1 and user2 should be candidates for each other
	candidates := idx.FindCandidates("user1")
	found := false
	for _, c := range candidates {
		if c == "user2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected user2 to be a candidate for user1")
	}

	// Verify similarity estimation
	sim := EstimateSimilarity(fp1.MinHashSig, fp2.MinHashSig)
	exactSim := jaccardSimilarity(fp1.Resources, fp2.Resources)

	// MinHash should be within ~10% of exact for these sizes
	if sim < exactSim-0.15 || sim > exactSim+0.15 {
		t.Errorf("MinHash similarity %.3f too far from exact %.3f", sim, exactSim)
	}
}

func TestAnalyzePeerGroups_Clustering(t *testing.T) {
	g := New()

	// Create 3 groups of users with similar access patterns
	// Group 1: Admin users
	for i := 0; i < 5; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("admin-%d", i),
			Kind:    NodeKindUser,
			Name:    fmt.Sprintf("Admin User %d", i),
			Account: "123456789012",
		})
	}

	// Group 2: Developer users
	for i := 0; i < 5; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("dev-%d", i),
			Kind:    NodeKindUser,
			Name:    fmt.Sprintf("Developer %d", i),
			Account: "123456789012",
		})
	}

	// Group 3: Readonly users
	for i := 0; i < 5; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("readonly-%d", i),
			Kind:    NodeKindUser,
			Name:    fmt.Sprintf("Readonly User %d", i),
			Account: "123456789012",
		})
	}

	// Add resources
	adminResources := []string{"admin-db", "admin-config", "admin-logs", "prod-db", "prod-config"}
	devResources := []string{"dev-db", "dev-config", "staging-env", "ci-pipeline", "code-repo"}
	readonlyResources := []string{"docs", "wiki", "public-api", "metrics-dashboard"}

	for _, r := range adminResources {
		g.AddNode(&Node{ID: r, Kind: NodeKindDatabase, Name: r, Account: "123456789012"})
	}
	for _, r := range devResources {
		g.AddNode(&Node{ID: r, Kind: NodeKindBucket, Name: r, Account: "123456789012"})
	}
	for _, r := range readonlyResources {
		g.AddNode(&Node{ID: r, Kind: NodeKindBucket, Name: r, Account: "123456789012"})
	}

	// Add edges - admins get admin resources
	for i := 0; i < 5; i++ {
		for _, r := range adminResources {
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("admin-%d->%s", i, r),
				Source: fmt.Sprintf("admin-%d", i),
				Target: r,
				Kind:   EdgeKindCanAdmin,
				Effect: EdgeEffectAllow,
			})
		}
	}

	// Devs get dev resources
	for i := 0; i < 5; i++ {
		for _, r := range devResources {
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("dev-%d->%s", i, r),
				Source: fmt.Sprintf("dev-%d", i),
				Target: r,
				Kind:   EdgeKindCanWrite,
				Effect: EdgeEffectAllow,
			})
		}
	}

	// Readonly users get readonly resources
	for i := 0; i < 5; i++ {
		for _, r := range readonlyResources {
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("readonly-%d->%s", i, r),
				Source: fmt.Sprintf("readonly-%d", i),
				Target: r,
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
			})
		}
	}

	analysis := AnalyzePeerGroups(g, 0.7, 2)

	if len(analysis.Groups) < 3 {
		t.Errorf("Expected at least 3 peer groups, got %d", len(analysis.Groups))
	}

	// Verify each group has members from the same category
	for _, group := range analysis.Groups {
		if group.MemberCount < 2 {
			t.Errorf("Group %s has only %d members", group.ID, group.MemberCount)
		}
	}

	t.Logf("Found %d groups with %d ungrouped principals",
		len(analysis.Groups), analysis.Ungrouped)
}

func TestFindPrivilegeCreep(t *testing.T) {
	g := New()

	// Create a group of users
	for i := 0; i < 5; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("user-%d", i),
			Kind:    NodeKindUser,
			Name:    fmt.Sprintf("User %d", i),
			Account: "123456789012",
		})
	}

	// Add resources
	resources := []string{"r1", "r2", "r3", "r4", "r5"}
	for _, r := range resources {
		g.AddNode(&Node{ID: r, Kind: NodeKindBucket, Name: r, Account: "123456789012"})
	}

	// Most users get access to 3 resources
	for i := 0; i < 4; i++ {
		for j := 0; j < 3; j++ {
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("user-%d->%s", i, resources[j]),
				Source: fmt.Sprintf("user-%d", i),
				Target: resources[j],
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
			})
		}
	}

	// One user (user-4) gets access to ALL 5 resources (privilege creep)
	for _, r := range resources {
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("user-4->%s", r),
			Source: "user-4",
			Target: r,
			Kind:   EdgeKindCanRead,
			Effect: EdgeEffectAllow,
		})
	}

	creepCases := FindPrivilegeCreep(g, 1.3) // 30% more than average

	found := false
	for _, c := range creepCases {
		if c.PrincipalID == "user-4" {
			found = true
			t.Logf("Found privilege creep for user-4 with score %.2f", c.OutlierScore)
		}
	}

	if !found {
		t.Error("Expected user-4 to be flagged for privilege creep")
	}
}

func TestCompareAccess(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "bob", Kind: NodeKindUser, Name: "Bob"})
	g.AddNode(&Node{ID: "shared-bucket", Kind: NodeKindBucket, Name: "Shared"})
	g.AddNode(&Node{ID: "alice-only", Kind: NodeKindBucket, Name: "Alice Only"})
	g.AddNode(&Node{ID: "bob-only", Kind: NodeKindBucket, Name: "Bob Only"})

	g.AddEdge(&Edge{ID: "e1", Source: "alice", Target: "shared-bucket", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "alice", Target: "alice-only", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "bob", Target: "shared-bucket", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e4", Source: "bob", Target: "bob-only", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	comparison := CompareAccess(g, "alice", "bob")

	if comparison.SharedCount != 1 {
		t.Errorf("Expected 1 shared resource, got %d", comparison.SharedCount)
	}

	if len(comparison.OnlyA) != 1 || comparison.OnlyA[0] != "alice-only" {
		t.Errorf("Expected OnlyA=[alice-only], got %v", comparison.OnlyA)
	}

	if len(comparison.OnlyB) != 1 || comparison.OnlyB[0] != "bob-only" {
		t.Errorf("Expected OnlyB=[bob-only], got %v", comparison.OnlyB)
	}

	// Jaccard similarity: 1 shared / 3 total = 0.33
	if comparison.Similarity < 0.3 || comparison.Similarity > 0.4 {
		t.Errorf("Expected similarity ~0.33, got %.2f", comparison.Similarity)
	}
}

func BenchmarkAnalyzePeerGroups(b *testing.B) {
	// Create a large graph
	g := New()

	numUsers := 1000
	numResources := 500
	resourcesPerUser := 50

	for i := 0; i < numUsers; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("user-%d", i),
			Kind:    NodeKindUser,
			Name:    fmt.Sprintf("User %d", i),
			Account: "123456789012",
		})
	}

	for i := 0; i < numResources; i++ {
		g.AddNode(&Node{
			ID:      fmt.Sprintf("resource-%d", i),
			Kind:    NodeKindBucket,
			Name:    fmt.Sprintf("Resource %d", i),
			Account: "123456789012",
		})
	}

	// Create groups by assigning similar resources to users
	for i := 0; i < numUsers; i++ {
		groupBase := (i / 100) * 50 // 10 groups of 100 users each
		for j := 0; j < resourcesPerUser; j++ {
			resourceIdx := (groupBase + j) % numResources
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("user-%d->resource-%d", i, resourceIdx),
				Source: fmt.Sprintf("user-%d", i),
				Target: fmt.Sprintf("resource-%d", resourceIdx),
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
			})
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzePeerGroups(g, 0.7, 2)
	}
}
