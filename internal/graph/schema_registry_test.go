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

func TestSchemaRegistry_IntelligenceSpineBuiltins(t *testing.T) {
	reg := GlobalSchemaRegistry()

	requiredNodeKinds := []NodeKind{
		NodeKindIdentityAlias,
		NodeKindService,
		NodeKindWorkload,
		NodeKindPullRequest,
		NodeKindDeploymentRun,
		NodeKindMeeting,
		NodeKindDocument,
		NodeKindThread,
		NodeKindIncident,
		NodeKindDecision,
		NodeKindOutcome,
		NodeKindEvidence,
		NodeKindAction,
	}
	for _, kind := range requiredNodeKinds {
		if !reg.IsNodeKindRegistered(kind) {
			t.Fatalf("expected builtin node kind %q to be registered", kind)
		}
	}

	requiredEdgeKinds := []EdgeKind{
		EdgeKindAliasOf,
		EdgeKindRuns,
		EdgeKindDependsOn,
		EdgeKindTargets,
		EdgeKindBasedOn,
		EdgeKindExecutedBy,
		EdgeKindEvaluates,
	}
	for _, kind := range requiredEdgeKinds {
		if !reg.IsEdgeKindRegistered(kind) {
			t.Fatalf("expected builtin edge kind %q to be registered", kind)
		}
	}

	nodeDefs := reg.ListNodeKinds()
	defByKind := make(map[NodeKind]NodeKindDefinition, len(nodeDefs))
	for _, def := range nodeDefs {
		defByKind[def.Kind] = def
	}

	decisionDef, ok := defByKind[NodeKindDecision]
	if !ok {
		t.Fatal("expected decision definition")
	}
	for _, property := range []string{"decision_type", "status", "made_at", "observed_at", "valid_from"} {
		if !containsRequiredProperty(decisionDef.RequiredProperties, property) {
			t.Fatalf("expected decision required property %q, got %#v", property, decisionDef.RequiredProperties)
		}
	}
	for _, relationship := range []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindExecutedBy} {
		if !containsEdgeKind(decisionDef.Relationships, relationship) {
			t.Fatalf("expected decision relationship %q, got %#v", relationship, decisionDef.Relationships)
		}
	}

	aliasDef, ok := defByKind[NodeKindIdentityAlias]
	if !ok {
		t.Fatal("expected identity_alias definition")
	}
	if !containsEdgeKind(aliasDef.Relationships, EdgeKindAliasOf) {
		t.Fatalf("expected identity_alias relationship %q, got %#v", EdgeKindAliasOf, aliasDef.Relationships)
	}

	incidentDef, ok := defByKind[NodeKindIncident]
	if !ok {
		t.Fatal("expected incident definition")
	}
	for _, property := range []string{"incident_id", "status", "observed_at", "valid_from"} {
		if !containsRequiredProperty(incidentDef.RequiredProperties, property) {
			t.Fatalf("expected incident required property %q, got %#v", property, incidentDef.RequiredProperties)
		}
	}
	for _, relationship := range []EdgeKind{EdgeKindTargets, EdgeKindBasedOn} {
		if !containsEdgeKind(incidentDef.Relationships, relationship) {
			t.Fatalf("expected incident relationship %q, got %#v", relationship, incidentDef.Relationships)
		}
	}

	evidenceDef, ok := defByKind[NodeKindEvidence]
	if !ok {
		t.Fatal("expected evidence definition")
	}
	for _, relationship := range []EdgeKind{EdgeKindTargets, EdgeKindBasedOn} {
		if !containsEdgeKind(evidenceDef.Relationships, relationship) {
			t.Fatalf("expected evidence relationship %q, got %#v", relationship, evidenceDef.Relationships)
		}
	}

	actionDef, ok := defByKind[NodeKindAction]
	if !ok {
		t.Fatal("expected action definition")
	}
	for _, relationship := range []EdgeKind{EdgeKindTargets, EdgeKindEvaluates, EdgeKindBasedOn, EdgeKindInteractedWith} {
		if !containsEdgeKind(actionDef.Relationships, relationship) {
			t.Fatalf("expected action relationship %q, got %#v", relationship, actionDef.Relationships)
		}
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

func TestSchemaRegistry_Capabilities(t *testing.T) {
	reg := NewSchemaRegistry()

	if !reg.NodeKindHasCapability(NodeKindDatabase, NodeCapabilitySensitiveData) {
		t.Fatal("expected database kind to be sensitive-data capable")
	}
	if !reg.NodeKindHasCapability(NodeKindRole, NodeCapabilityPrivilegedIdentity) {
		t.Fatal("expected role kind to be privileged-identity capable")
	}
	if reg.NodeKindHasCapability(NodeKindPerson, NodeCapabilityCredentialStore) {
		t.Fatal("did not expect person kind to be credential-store capable")
	}
}

func TestSchemaRegistry_VersionHistoryAndDrift(t *testing.T) {
	reg := NewSchemaRegistry()
	start := reg.Version()
	if start != 1 {
		t.Fatalf("expected initial schema version 1, got %d", start)
	}

	kind := NodeKind("test_versioned_entity_v1")
	if _, err := reg.RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       kind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register versioned kind: %v", err)
	}

	if reg.Version() <= start {
		t.Fatalf("expected schema version to advance, start=%d now=%d", start, reg.Version())
	}

	drift := reg.DriftSince(start)
	if len(drift.AddedNodeKinds) == 0 || drift.AddedNodeKinds[0] != kind {
		t.Fatalf("expected drift to include added node kind %q, got %#v", kind, drift.AddedNodeKinds)
	}
	history := reg.History(10)
	if len(history) < 2 {
		t.Fatalf("expected builtins + update history entries, got %d", len(history))
	}
}

func TestSchemaRegistry_ValidateNodeAndEdge(t *testing.T) {
	reg := NewSchemaRegistry()

	sourceKind := NodeKind("test_validation_source_v1")
	targetKind := NodeKind("test_validation_target_v1")
	if _, err := reg.RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:               sourceKind,
		Categories:         []NodeKindCategory{NodeCategoryBusiness},
		Properties:         map[string]string{"title": "string", "manager_level": "integer"},
		RequiredProperties: []string{"title"},
		Relationships:      []EdgeKind{EdgeKindReportsTo},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := reg.RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	node := &Node{ID: "node:1", Kind: sourceKind, Properties: map[string]any{"manager_level": "not-an-int"}}
	issues := reg.ValidateNode(node)
	if !hasIssueCode(issues, SchemaIssueMissingRequiredProperty) {
		t.Fatalf("expected missing required property issue, got %#v", issues)
	}
	if !hasIssueCode(issues, SchemaIssueInvalidPropertyType) {
		t.Fatalf("expected invalid property type issue, got %#v", issues)
	}

	source := &Node{ID: "node:source", Kind: sourceKind, Properties: map[string]any{"title": "owner"}}
	target := &Node{ID: "node:target", Kind: targetKind}
	edge := &Edge{ID: "edge:1", Source: source.ID, Target: target.ID, Kind: EdgeKindCanRead}
	edgeIssues := reg.ValidateEdge(edge, source, target)
	if !hasIssueCode(edgeIssues, SchemaIssueRelationshipNotAllowed) {
		t.Fatalf("expected relationship-not-allowed issue, got %#v", edgeIssues)
	}

	unknownEdge := &Edge{ID: "edge:2", Source: source.ID, Target: target.ID, Kind: EdgeKind("unknown_kind_v1")}
	unknownIssues := reg.ValidateEdge(unknownEdge, source, target)
	if !hasIssueCode(unknownIssues, SchemaIssueUnknownEdgeKind) {
		t.Fatalf("expected unknown edge kind issue, got %#v", unknownIssues)
	}
}

func hasIssueCode(issues []SchemaValidationIssue, code SchemaValidationIssueCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func containsEdgeKind(values []EdgeKind, target EdgeKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsRequiredProperty(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
