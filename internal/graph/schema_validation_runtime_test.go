package graph

import "testing"

func TestGraphSchemaValidationWarnAndEnforce(t *testing.T) {
	requiredKind := NodeKind("test_runtime_required_kind_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:               requiredKind,
		Categories:         []NodeKindCategory{NodeCategoryBusiness},
		RequiredProperties: []string{"owner"},
	}); err != nil {
		t.Fatalf("register required kind: %v", err)
	}

	g := New()
	if g.SchemaValidationMode() != SchemaValidationWarn {
		t.Fatalf("expected default schema validation mode warn, got %q", g.SchemaValidationMode())
	}

	g.AddNode(&Node{ID: "node:warn", Kind: requiredKind, Name: "Warn Mode"})
	if g.NodeCount() != 1 {
		t.Fatalf("expected warn mode to ingest node, got node count %d", g.NodeCount())
	}
	stats := g.SchemaValidationStats()
	if stats.NodeWarnings == 0 || stats.NodeRejected != 0 {
		t.Fatalf("expected node warning counters only in warn mode, got %#v", stats)
	}

	g.SetSchemaValidationMode(SchemaValidationEnforce)
	g.AddNode(&Node{ID: "node:reject", Kind: requiredKind, Name: "Reject Mode"})
	if g.NodeCount() != 1 {
		t.Fatalf("expected enforce mode to reject invalid node, got node count %d", g.NodeCount())
	}
	stats = g.SchemaValidationStats()
	if stats.NodeRejected == 0 {
		t.Fatalf("expected rejected-node counters in enforce mode, got %#v", stats)
	}

	sourceKind := NodeKind("test_runtime_source_kind_v1")
	targetKind := NodeKind("test_runtime_target_kind_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          sourceKind,
		Categories:    []NodeKindCategory{NodeCategoryBusiness},
		Relationships: []EdgeKind{EdgeKindReportsTo},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	g.AddNode(&Node{ID: "node:source", Kind: sourceKind, Properties: map[string]any{"owner": "team-a"}})
	g.AddNode(&Node{ID: "node:target", Kind: targetKind})
	g.AddEdge(&Edge{
		ID:     "edge:reject",
		Source: "node:source",
		Target: "node:target",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})
	if g.EdgeCount() != 0 {
		t.Fatalf("expected enforce mode to reject invalid edge, got edge count %d", g.EdgeCount())
	}
	stats = g.SchemaValidationStats()
	if stats.EdgeRejected == 0 {
		t.Fatalf("expected rejected-edge counters in enforce mode, got %#v", stats)
	}
}

func TestGraphCapabilityDrivenInternetAndCrownJewel(t *testing.T) {
	internetCapKind := NodeKind("test_cap_internet_enabled_v1")
	internetNoCapKind := NodeKind("test_cap_internet_disabled_v1")
	sensitiveCapKind := NodeKind("test_cap_sensitive_enabled_v1")
	sensitiveNoCapKind := NodeKind("test_cap_sensitive_disabled_v1")

	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:         internetCapKind,
		Categories:   []NodeKindCategory{NodeCategoryResource},
		Capabilities: []NodeKindCapability{NodeCapabilityInternetExposable},
	}); err != nil {
		t.Fatalf("register internet-cap kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       internetNoCapKind,
		Categories: []NodeKindCategory{NodeCategoryResource},
	}); err != nil {
		t.Fatalf("register internet-no-cap kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:         sensitiveCapKind,
		Categories:   []NodeKindCategory{NodeCategoryResource},
		Capabilities: []NodeKindCapability{NodeCapabilitySensitiveData},
	}); err != nil {
		t.Fatalf("register sensitive-cap kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       sensitiveNoCapKind,
		Categories: []NodeKindCategory{NodeCategoryResource},
	}); err != nil {
		t.Fatalf("register sensitive-no-cap kind: %v", err)
	}

	g := New()
	g.SetSchemaValidationMode(SchemaValidationOff)
	g.AddNode(&Node{
		ID:         "node:internet-cap",
		Kind:       internetCapKind,
		Properties: map[string]any{"function_url": "https://example.test/fn"},
		Risk:       RiskNone,
	})
	g.AddNode(&Node{
		ID:         "node:internet-no-cap",
		Kind:       internetNoCapKind,
		Properties: map[string]any{"function_url": "https://example.test/fn"},
		Risk:       RiskNone,
	})
	g.AddNode(&Node{
		ID:         "node:sensitive-cap",
		Kind:       sensitiveCapKind,
		Properties: map[string]any{"contains_pii": true},
		Risk:       RiskNone,
	})
	g.AddNode(&Node{
		ID:         "node:sensitive-no-cap",
		Kind:       sensitiveNoCapKind,
		Properties: map[string]any{"contains_pii": true},
		Risk:       RiskNone,
	})
	g.BuildIndex()

	internetFacing := g.GetInternetFacingNodes()
	if !containsNodeIDRuntime(internetFacing, "node:internet-cap") {
		t.Fatalf("expected internet-cap node to be internet-facing, got %#v", internetFacing)
	}
	if containsNodeIDRuntime(internetFacing, "node:internet-no-cap") {
		t.Fatalf("did not expect internet-no-cap node to be internet-facing, got %#v", internetFacing)
	}

	crownJewels := g.GetCrownJewels()
	if !containsNodeIDRuntime(crownJewels, "node:sensitive-cap") {
		t.Fatalf("expected sensitive-cap node to be crown jewel, got %#v", crownJewels)
	}
	if containsNodeIDRuntime(crownJewels, "node:sensitive-no-cap") {
		t.Fatalf("did not expect sensitive-no-cap node to be crown jewel, got %#v", crownJewels)
	}
}

func containsNodeIDRuntime(nodes []*Node, targetID string) bool {
	for _, node := range nodes {
		if node != nil && node.ID == targetID {
			return true
		}
	}
	return false
}
