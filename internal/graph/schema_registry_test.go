package graph

import "testing"

func TestSchemaRegistry_BuiltinsAvailable(t *testing.T) {
	reg := GlobalSchemaRegistry()

	if !reg.IsNodeKindRegistered(NodeKindUser) {
		t.Fatal("expected builtin node kind user to be registered")
	}
	if !reg.IsEdgeKindRegistered(EdgeKindCanRead) {
		t.Fatal("expected builtin edge kind can_read to be registered")
	}

	if !(&Node{Kind: NodeKindUser}).IsIdentity() {
		t.Fatal("expected user to be identity")
	}
	if !(&Node{Kind: NodeKindCustomer}).IsBusinessEntity() {
		t.Fatal("expected customer to be business entity")
	}
	if !(&Node{Kind: NodeKindPod}).IsKubernetes() {
		t.Fatal("expected pod to be kubernetes")
	}
	if !(&Node{Kind: NodeKindPod}).IsResource() {
		t.Fatal("expected pod to be resource")
	}
	if (&Node{Kind: NodeKindNamespace}).IsResource() {
		t.Fatal("expected namespace to not be resource by default")
	}
}

func TestSchemaRegistry_RegisterDynamicNodeKind(t *testing.T) {
	kind := NodeKind("test_dynamic_employee_v1")
	def, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       kind,
		Categories: []NodeKindCategory{NodeCategoryIdentity, NodeCategoryBusiness},
		Properties: map[string]string{
			"title": "string",
		},
		Relationships: []EdgeKind{EdgeKindReportsTo},
		Description:   "Dynamic employee entity",
	})
	if err != nil {
		t.Fatalf("register node kind: %v", err)
	}
	if def.Kind != kind {
		t.Fatalf("unexpected kind: %s", def.Kind)
	}

	node := &Node{Kind: kind}
	if !node.IsIdentity() {
		t.Fatal("expected dynamic kind to be identity")
	}
	if !node.IsBusinessEntity() {
		t.Fatal("expected dynamic kind to be business entity")
	}
}

func TestSchemaRegistry_RegisterNodeKindMergesDefinitions(t *testing.T) {
	kind := NodeKind("test_dynamic_merge_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       kind,
		Categories: []NodeKindCategory{NodeCategoryIdentity},
		Properties: map[string]string{"title": "string"},
	}); err != nil {
		t.Fatalf("initial register failed: %v", err)
	}

	merged, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          kind,
		Categories:    []NodeKindCategory{NodeCategoryResource},
		Properties:    map[string]string{"department": "string"},
		Relationships: []EdgeKind{EdgeKindManagedBy},
	})
	if err != nil {
		t.Fatalf("merge register failed: %v", err)
	}

	if len(merged.Categories) != 2 {
		t.Fatalf("expected merged categories, got %#v", merged.Categories)
	}
	if merged.Properties["title"] != "string" || merged.Properties["department"] != "string" {
		t.Fatalf("expected merged properties, got %#v", merged.Properties)
	}
	if len(merged.Relationships) != 1 || merged.Relationships[0] != EdgeKindManagedBy {
		t.Fatalf("expected merged relationships, got %#v", merged.Relationships)
	}

	node := &Node{Kind: kind}
	if !node.IsIdentity() || !node.IsResource() {
		t.Fatalf("expected merged dynamic kind to satisfy both categories")
	}
}

func TestSchemaRegistry_RegisterDynamicEdgeKind(t *testing.T) {
	kind := EdgeKind("test_dynamic_relationship_v1")
	def, err := RegisterEdgeKindDefinition(EdgeKindDefinition{
		Kind:        kind,
		Description: "Dynamic relationship kind",
	})
	if err != nil {
		t.Fatalf("register edge kind failed: %v", err)
	}
	if def.Kind != kind {
		t.Fatalf("unexpected edge kind: %s", def.Kind)
	}
	if !GlobalSchemaRegistry().IsEdgeKindRegistered(kind) {
		t.Fatalf("expected dynamic edge kind to be registered")
	}
}

func TestSchemaRegistry_InvalidCategory(t *testing.T) {
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       NodeKind("test_invalid_category_kind_v1"),
		Categories: []NodeKindCategory{"not_a_category"},
	}); err == nil {
		t.Fatal("expected invalid category error")
	}
}
