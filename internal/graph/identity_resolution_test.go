package graph

import "testing"

func TestResolveIdentityAlias_EmailMatchAutoApplies(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "person:alice@example.com",
		Kind: NodeKindPerson,
		Name: "Alice Doe",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	result, err := ResolveIdentityAlias(g, IdentityAliasAssertion{
		SourceSystem:  "github",
		SourceEventID: "evt-1",
		ExternalID:    "alice-handle",
		Email:         "Alice@Example.com",
		Name:          "Alice Doe",
	}, IdentityResolutionOptions{})
	if err != nil {
		t.Fatalf("resolve identity alias failed: %v", err)
	}
	if !result.Applied {
		t.Fatalf("expected alias resolution to auto-apply, got %#v", result)
	}
	if result.AppliedTargetID != "person:alice@example.com" {
		t.Fatalf("expected alias to resolve to person:alice@example.com, got %q", result.AppliedTargetID)
	}

	aliasNode, ok := g.GetNode(result.AliasNodeID)
	if !ok || aliasNode == nil {
		t.Fatalf("expected alias node %q to exist", result.AliasNodeID)
	}
	if aliasNode.Kind != NodeKindIdentityAlias {
		t.Fatalf("expected alias node kind identity_alias, got %q", aliasNode.Kind)
	}

	aliasEdges := g.GetOutEdges(result.AliasNodeID)
	foundAliasOf := false
	for _, edge := range aliasEdges {
		if edge == nil {
			continue
		}
		if edge.Kind == EdgeKindAliasOf && edge.Target == "person:alice@example.com" {
			foundAliasOf = true
			break
		}
	}
	if !foundAliasOf {
		t.Fatalf("expected alias_of edge from %s to person:alice@example.com, got %#v", result.AliasNodeID, aliasEdges)
	}
}

func TestResolveIdentityAlias_NameSimilaritySuggestsOnly(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "person:robert.smith@example.com",
		Kind: NodeKindPerson,
		Name: "Robert Smith",
	})

	result, err := ResolveIdentityAlias(g, IdentityAliasAssertion{
		SourceSystem: "slack",
		ExternalID:   "U12345",
		Name:         "Robert J Smith",
	}, IdentityResolutionOptions{
		AutoLinkThreshold: 0.95,
		SuggestThreshold:  0.20,
	})
	if err != nil {
		t.Fatalf("resolve identity alias failed: %v", err)
	}
	if result.Applied {
		t.Fatalf("expected no auto-link for name-only weak match, got %#v", result)
	}
	if len(result.Candidates) == 0 {
		t.Fatalf("expected candidate suggestions, got %#v", result)
	}
	if result.Candidates[0].CanonicalNodeID != "person:robert.smith@example.com" {
		t.Fatalf("unexpected top candidate: %#v", result.Candidates[0])
	}
}

func TestSplitIdentityAlias_RemovesAliasLink(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{
		ID:   "alias:github:alice-handle",
		Kind: NodeKindIdentityAlias,
		Name: "alice-handle",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice-handle",
			"observed_at":   "2026-03-08T00:00:00Z",
			"valid_from":    "2026-03-08T00:00:00Z",
		},
	})

	if err := ConfirmIdentityAlias(g, "alias:github:alice-handle", "person:alice@example.com", "manual", "evt-confirm", temporalNowUTC(), 1); err != nil {
		t.Fatalf("confirm alias failed: %v", err)
	}

	removed, err := SplitIdentityAlias(g, "alias:github:alice-handle", "person:alice@example.com", "bad merge", "manual", "evt-split", temporalNowUTC())
	if err != nil {
		t.Fatalf("split alias failed: %v", err)
	}
	if !removed {
		t.Fatal("expected alias link to be removed")
	}

	for _, edge := range g.GetOutEdges("alias:github:alice-handle") {
		if edge == nil {
			continue
		}
		if edge.Kind == EdgeKindAliasOf && edge.Target == "person:alice@example.com" {
			t.Fatalf("expected alias_of edge to be removed, found %#v", edge)
		}
	}
}

func TestConfirmIdentityAlias_IsIdempotent(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{
		ID:   "alias:github:alice-handle",
		Kind: NodeKindIdentityAlias,
		Name: "alice-handle",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice-handle",
			"observed_at":   "2026-03-08T00:00:00Z",
			"valid_from":    "2026-03-08T00:00:00Z",
		},
	})

	for i := 0; i < 2; i++ {
		if err := ConfirmIdentityAlias(g, "alias:github:alice-handle", "person:alice@example.com", "manual", "evt-confirm", temporalNowUTC(), 1); err != nil {
			t.Fatalf("confirm alias failed: %v", err)
		}
	}

	count := 0
	for _, edge := range g.GetOutEdges("alias:github:alice-handle") {
		if edge == nil {
			continue
		}
		if edge.Kind == EdgeKindAliasOf && edge.Target == "person:alice@example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one active alias_of edge, got %d", count)
	}
}

func TestConfirmIdentityAlias_RemovesStaleCanonicalLinks(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{
		ID:   "alias:github:shared-handle",
		Kind: NodeKindIdentityAlias,
		Name: "shared-handle",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "shared-handle",
			"observed_at":   "2026-03-08T00:00:00Z",
			"valid_from":    "2026-03-08T00:00:00Z",
		},
	})

	g.AddEdge(&Edge{
		ID:     "alias_of:shared->alice",
		Source: "alias:github:shared-handle",
		Target: "person:alice@example.com",
		Kind:   EdgeKindAliasOf,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:     "alias_of:shared->bob",
		Source: "alias:github:shared-handle",
		Target: "person:bob@example.com",
		Kind:   EdgeKindAliasOf,
		Effect: EdgeEffectAllow,
	})

	if err := ConfirmIdentityAlias(g, "alias:github:shared-handle", "person:alice@example.com", "manual", "evt-confirm", temporalNowUTC(), 1); err != nil {
		t.Fatalf("confirm alias failed: %v", err)
	}

	links := make([]string, 0)
	for _, edge := range g.GetOutEdges("alias:github:shared-handle") {
		if edge == nil || edge.Kind != EdgeKindAliasOf {
			continue
		}
		links = append(links, edge.Target)
	}
	if len(links) != 1 || links[0] != "person:alice@example.com" {
		t.Fatalf("expected one canonical link to alice, got %+v", links)
	}
}
