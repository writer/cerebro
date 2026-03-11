package graph

import "testing"

func buildPatternTestGraph() *Graph {
	g := New()
	g.AddNode(&Node{ID: "user-a", Kind: NodeKindUser, Account: "111", Provider: "aws", Properties: map[string]any{"mfa_enabled": false}})
	g.AddNode(&Node{ID: "user-b", Kind: NodeKindUser, Account: "111", Provider: "aws", Properties: map[string]any{"mfa_enabled": true}})
	g.AddNode(&Node{ID: "role-admin-111", Kind: NodeKindRole, Account: "111", Provider: "aws", Properties: map[string]any{"is_admin": true}})
	g.AddNode(&Node{ID: "role-admin-222", Kind: NodeKindRole, Account: "222", Provider: "aws", Properties: map[string]any{"is_admin": true}})
	g.AddNode(&Node{ID: "bucket-public", Kind: NodeKindBucket, Account: "222", Provider: "aws", Properties: map[string]any{"public": true}})

	g.AddEdge(&Edge{ID: "e1", Source: "user-a", Target: "role-admin-111", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e2", Source: "user-a", Target: "role-admin-222", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e3", Source: "user-b", Target: "role-admin-111", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e4", Source: "role-admin-111", Target: "role-admin-222", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "e5", Source: "role-admin-222", Target: "bucket-public", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	return g
}

func TestFindPatternSimpleAdminAssume(t *testing.T) {
	g := buildPatternTestGraph()

	pattern := &GraphPattern{
		ID: "simple-assume",
		Nodes: []PatternNode{
			{Alias: "A", Kind: NodeKindUser, Properties: map[string]any{"mfa_enabled": false}},
			{Alias: "B", Kind: NodeKindRole, Properties: map[string]any{"is_admin": true}},
		},
		Edges: []PatternEdge{{Source: "A", Target: "B", Kind: EdgeKindCanAssume}},
	}

	matches := g.FindPattern(pattern)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestFindPatternDynamicDifferentFromAlias(t *testing.T) {
	g := buildPatternTestGraph()

	pattern := &GraphPattern{
		ID: "cross-account-chain",
		Nodes: []PatternNode{
			{Alias: "A", Kind: NodeKindRole},
			{Alias: "B", Kind: NodeKindRole, Properties: map[string]any{"account": "different_from_A"}},
		},
		Edges: []PatternEdge{{Source: "A", Target: "B", Kind: EdgeKindCanAssume}},
	}

	matches := g.FindPattern(pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 cross-account match, got %d", len(matches))
	}
	if matches[0].Bindings["A"].ID != "role-admin-111" || matches[0].Bindings["B"].ID != "role-admin-222" {
		t.Fatalf("unexpected bindings: A=%s B=%s", matches[0].Bindings["A"].ID, matches[0].Bindings["B"].ID)
	}
}

func TestFindPatternConditionExpression(t *testing.T) {
	g := buildPatternTestGraph()

	pattern := &GraphPattern{
		ID: "cross-account-admin",
		Nodes: []PatternNode{
			{Alias: "A", Kind: NodeKindUser, Properties: map[string]any{"mfa_enabled": false}},
			{Alias: "B", Kind: NodeKindRole, Properties: map[string]any{"is_admin": true}},
		},
		Edges: []PatternEdge{{Source: "A", Target: "B", Kind: EdgeKindCanAssume}},
		Conditions: []PatternCondition{
			{Expression: "A.account != B.account AND B.provider == 'aws'"},
		},
	}

	matches := g.FindPattern(pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match after condition filter, got %d", len(matches))
	}
	if got := matches[0].Bindings["B"].ID; got != "role-admin-222" {
		t.Fatalf("expected cross-account admin role, got %s", got)
	}
}

func TestFindPatternAnyKindNode(t *testing.T) {
	g := buildPatternTestGraph()

	pattern := &GraphPattern{
		ID: "public-any",
		Nodes: []PatternNode{
			{Alias: "X", Kind: NodeKindAny, Properties: map[string]any{"public": true}},
		},
	}

	matches := g.FindPattern(pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 any-kind public match, got %d", len(matches))
	}
	if got := matches[0].Bindings["X"].ID; got != "bucket-public" {
		t.Fatalf("unexpected match %s", got)
	}
}

func TestFindPatternInvalidAliasReference(t *testing.T) {
	g := buildPatternTestGraph()

	pattern := &GraphPattern{
		ID:    "invalid",
		Nodes: []PatternNode{{Alias: "A", Kind: NodeKindUser}},
		Edges: []PatternEdge{{Source: "A", Target: "B", Kind: EdgeKindCanAssume}},
	}

	matches := g.FindPattern(pattern)
	if matches != nil {
		t.Fatalf("expected nil for invalid pattern, got %d matches", len(matches))
	}
}

func TestFindPatternAliasesMustBindDistinctNodes(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "role-1", Kind: NodeKindRole, Account: "111", Provider: "aws"})
	g.AddEdge(&Edge{ID: "self", Source: "role-1", Target: "role-1", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	pattern := &GraphPattern{
		ID: "distinct-aliases",
		Nodes: []PatternNode{
			{Alias: "A", Kind: NodeKindRole},
			{Alias: "B", Kind: NodeKindRole},
		},
		Edges: []PatternEdge{{Source: "A", Target: "B", Kind: EdgeKindCanAssume}},
	}

	matches := g.FindPattern(pattern)
	if len(matches) != 0 {
		t.Fatalf("expected no matches because aliases must bind different nodes, got %d", len(matches))
	}
}
