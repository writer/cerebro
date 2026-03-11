package graph

import "testing"

func TestCreateAccessReview_ReusesBlastRadiusCache(t *testing.T) {
	g := setupTestGraph()

	var blastRadiusCalls int
	blastRadiusComputeHook = func(_ string, _ int) {
		blastRadiusCalls++
	}
	t.Cleanup(func() {
		blastRadiusComputeHook = nil
	})

	identityCount := 0
	for _, node := range g.GetAllNodes() {
		if node.IsIdentity() {
			identityCount++
		}
	}

	scope := ReviewScope{Type: ScopeTypeAll}

	first := CreateAccessReview(g, "all-1", scope, "tester")
	if len(first.Items) == 0 {
		t.Fatal("expected access review items")
	}
	if blastRadiusCalls != identityCount {
		t.Fatalf("expected %d blast radius computations, got %d", identityCount, blastRadiusCalls)
	}

	second := CreateAccessReview(g, "all-2", scope, "tester")
	if len(second.Items) != len(first.Items) {
		t.Fatalf("expected stable item count across cached run, got %d and %d", len(first.Items), len(second.Items))
	}
	if blastRadiusCalls != identityCount {
		t.Fatalf("expected cached review generation to avoid recomputation, got %d calls", blastRadiusCalls)
	}

	// Any graph mutation should invalidate the traversal cache.
	g.AddNode(&Node{
		ID:      "bucket:post-mutation",
		Kind:    NodeKindBucket,
		Name:    "post-mutation",
		Account: "111111111111",
		Risk:    RiskMedium,
	})
	g.AddEdge(&Edge{
		ID:     "edge:post-mutation",
		Source: "role:admin",
		Target: "bucket:post-mutation",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	third := CreateAccessReview(g, "all-3", scope, "tester")
	if len(third.Items) <= len(second.Items) {
		t.Fatalf("expected new resource to increase item count, got %d then %d", len(second.Items), len(third.Items))
	}
	if blastRadiusCalls != identityCount*2 {
		t.Fatalf("expected cache invalidation to trigger recomputation, got %d calls", blastRadiusCalls)
	}
}

func TestGeneratePrincipalAccessItems_DeduplicatesPrincipalInput(t *testing.T) {
	g := setupTestGraph()

	var blastRadiusCalls int
	blastRadiusComputeHook = func(_ string, _ int) {
		blastRadiusCalls++
	}
	t.Cleanup(func() {
		blastRadiusComputeHook = nil
	})

	items := generatePrincipalAccessItems(g, []string{
		"user:alice",
		"user:alice",
		"user:alice",
		"user:bob",
		"user:bob",
	})
	if len(items) == 0 {
		t.Fatal("expected principal access review items")
	}
	if blastRadiusCalls != 2 {
		t.Fatalf("expected deduplicated principal computation count 2, got %d", blastRadiusCalls)
	}
}
