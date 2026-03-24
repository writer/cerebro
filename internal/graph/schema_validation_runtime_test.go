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

func TestGraphSchemaValidationEnforceRejectsCardinalityViolations(t *testing.T) {
	sourceKind := NodeKind("test_runtime_cardinality_source_v1")
	targetKind := NodeKind("test_runtime_cardinality_target_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          sourceKind,
		Categories:    []NodeKindCategory{NodeCategoryBusiness},
		Relationships: []EdgeKind{EdgeKindMemberOf},
		RelationshipCardinality: map[EdgeKind]RelationshipCardinality{
			EdgeKindMemberOf: {MaxOutgoing: 1},
		},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)
	g.AddNode(&Node{ID: "person:alice", Kind: sourceKind})
	g.AddNode(&Node{ID: "department:eng", Kind: targetKind})
	g.AddNode(&Node{ID: "department:ops", Kind: targetKind})
	g.AddEdge(&Edge{ID: "edge:eng", Source: "person:alice", Target: "department:eng", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:ops", Source: "person:alice", Target: "department:ops", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	if got := g.EdgeCount(); got != 1 {
		t.Fatalf("EdgeCount() = %d, want 1", got)
	}
	stats := g.SchemaValidationStats()
	if stats.EdgeRejected == 0 {
		t.Fatalf("expected rejected-edge counters in enforce mode, got %#v", stats)
	}
	if stats.EdgeRejectByCode[string(SchemaIssueCardinalityExceeded)] == 0 {
		t.Fatalf("expected cardinality reject counters, got %#v", stats)
	}
}

func TestGraphSchemaValidationEnforceAcceptsEvaluationEdgeContracts(t *testing.T) {
	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)

	g.AddNode(&Node{
		ID:   "thread:evaluation:run-1:conv-1",
		Kind: NodeKindThread,
		Properties: map[string]any{
			"thread_id":     "conv-1",
			"channel_id":    "run-1",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:00:00Z",
			"valid_from":    "2026-03-22T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "decision:evaluation:run-1:conv-1:turn-1",
		Kind: NodeKindDecision,
		Properties: map[string]any{
			"decision_type": "tool_call_context",
			"status":        "completed",
			"made_at":       "2026-03-22T10:00:00Z",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:00:00Z",
			"valid_from":    "2026-03-22T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "action:evaluation:run-1:conv-1:call-1",
		Kind: NodeKindAction,
		Properties: map[string]any{
			"action_type":   "tool_call",
			"status":        "completed",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:01:00Z",
			"valid_from":    "2026-03-22T10:01:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-1:conv-1",
		Kind: NodeKindOutcome,
		Properties: map[string]any{
			"outcome_type":  "evaluation_conversation",
			"verdict":       "positive",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:02:00Z",
			"valid_from":    "2026-03-22T10:02:00Z",
		},
	})

	for _, edge := range []*Edge{
		{ID: "decision-target", Source: "decision:evaluation:run-1:conv-1:turn-1", Target: "thread:evaluation:run-1:conv-1", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "action-based-on", Source: "action:evaluation:run-1:conv-1:call-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "action-target", Source: "action:evaluation:run-1:conv-1:call-1", Target: "thread:evaluation:run-1:conv-1", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "outcome-evaluates", Source: "outcome:evaluation:run-1:conv-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow},
	} {
		g.AddEdge(edge)
	}

	if got := g.EdgeCount(); got != 4 {
		t.Fatalf("EdgeCount() = %d, want 4", got)
	}
	stats := g.SchemaValidationStats()
	if stats.EdgeRejected != 0 {
		t.Fatalf("expected no rejected evaluation edges, got %#v", stats)
	}
}

func TestGraphSchemaValidationEnforceRejectsInvalidEvaluationEdgeContracts(t *testing.T) {
	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)

	g.AddNode(&Node{
		ID:   "thread:evaluation:run-1:conv-1",
		Kind: NodeKindThread,
		Properties: map[string]any{
			"thread_id":     "conv-1",
			"channel_id":    "run-1",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:00:00Z",
			"valid_from":    "2026-03-22T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "decision:evaluation:run-1:conv-1:turn-1",
		Kind: NodeKindDecision,
		Properties: map[string]any{
			"decision_type": "tool_call_context",
			"status":        "completed",
			"made_at":       "2026-03-22T10:00:00Z",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:00:00Z",
			"valid_from":    "2026-03-22T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "action:evaluation:run-1:conv-1:call-1",
		Kind: NodeKindAction,
		Properties: map[string]any{
			"action_type":   "tool_call",
			"status":        "completed",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:01:00Z",
			"valid_from":    "2026-03-22T10:01:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-1:conv-1",
		Kind: NodeKindOutcome,
		Properties: map[string]any{
			"outcome_type":  "evaluation_conversation",
			"verdict":       "positive",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-22T10:02:00Z",
			"valid_from":    "2026-03-22T10:02:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "claim:evaluation:run-1:conv-1:stage-1",
		Kind: NodeKindClaim,
		Properties: map[string]any{
			"claim_type":       "classification",
			"subject_id":       "thread:evaluation:run-1:conv-1",
			"predicate":        "evaluation_stage_result",
			"status":           "asserted",
			"source_system":    "platform_eval",
			"observed_at":      "2026-03-22T10:00:00Z",
			"valid_from":       "2026-03-22T10:00:00Z",
			"recorded_at":      "2026-03-22T10:00:00Z",
			"transaction_from": "2026-03-22T10:00:00Z",
		},
	})

	for _, edge := range []*Edge{
		{ID: "outcome-based-on", Source: "outcome:evaluation:run-1:conv-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "action-based-on-claim", Source: "action:evaluation:run-1:conv-1:call-1", Target: "claim:evaluation:run-1:conv-1:stage-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "outcome-based-on-claim", Source: "outcome:evaluation:run-1:conv-1", Target: "claim:evaluation:run-1:conv-1:stage-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "decision-evaluates", Source: "decision:evaluation:run-1:conv-1:turn-1", Target: "action:evaluation:run-1:conv-1:call-1", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow},
		{ID: "thread-evaluates", Source: "thread:evaluation:run-1:conv-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow},
	} {
		g.AddEdge(edge)
	}

	if got := g.EdgeCount(); got != 2 {
		t.Fatalf("EdgeCount() = %d, want 2", got)
	}
	stats := g.SchemaValidationStats()
	if stats.EdgeRejected != 3 {
		t.Fatalf("expected 3 rejected evaluation edges, got %#v", stats)
	}
	if stats.EdgeRejectByCode[string(SchemaIssueRelationshipNotAllowed)] != 3 {
		t.Fatalf("expected relationship-not-allowed rejects, got %#v", stats.EdgeRejectByCode)
	}
}

func TestGraphSchemaValidationEnforceAcceptsPlaybookWorkflowEdges(t *testing.T) {
	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)

	g.AddNode(&Node{
		ID:   "thread:playbook:run-1",
		Kind: NodeKindThread,
		Properties: map[string]any{
			"thread_id":     "run-1",
			"channel_id":    "playbook-1",
			"source_system": "platform_playbook",
			"observed_at":   "2026-03-23T10:00:00Z",
			"valid_from":    "2026-03-23T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "decision:playbook:run-1:stage-1",
		Kind: NodeKindDecision,
		Properties: map[string]any{
			"decision_type": "playbook_stage",
			"status":        "completed",
			"made_at":       "2026-03-23T10:01:00Z",
			"source_system": "platform_playbook",
			"observed_at":   "2026-03-23T10:01:00Z",
			"valid_from":    "2026-03-23T10:01:00Z",
		},
	})
	g.AddNode(validDecisionNode("decision:playbook:run-1:stage-2"))
	g.AddNode(&Node{
		ID:   "action:playbook:run-1:action-1",
		Kind: NodeKindAction,
		Properties: map[string]any{
			"action_type":   "approval_request",
			"status":        "completed",
			"source_system": "platform_playbook",
			"observed_at":   "2026-03-23T10:02:00Z",
			"valid_from":    "2026-03-23T10:02:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:playbook:run-1",
		Kind: NodeKindOutcome,
		Properties: map[string]any{
			"outcome_type":  "playbook_run",
			"verdict":       "positive",
			"source_system": "platform_playbook",
			"observed_at":   "2026-03-23T10:03:00Z",
			"valid_from":    "2026-03-23T10:03:00Z",
		},
	})

	for _, edge := range []*Edge{
		{ID: "playbook-stage-target-1", Source: "decision:playbook:run-1:stage-1", Target: "thread:playbook:run-1", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "playbook-stage-sequence", Source: "decision:playbook:run-1:stage-2", Target: "decision:playbook:run-1:stage-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "playbook-action-based-on", Source: "action:playbook:run-1:action-1", Target: "decision:playbook:run-1:stage-2", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow},
		{ID: "playbook-outcome-evaluates", Source: "outcome:playbook:run-1", Target: "decision:playbook:run-1:stage-2", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow},
	} {
		g.AddEdge(edge)
	}

	if got := g.EdgeCount(); got != 4 {
		t.Fatalf("EdgeCount() = %d, want 4", got)
	}
	stats := g.SchemaValidationStats()
	if stats.EdgeRejected != 0 {
		t.Fatalf("expected no rejected playbook edges, got %#v", stats)
	}
}

func TestGraphSchemaValidationEnforceRejectsTargetKindCompatibilityViolations(t *testing.T) {
	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)

	g.AddNode(validEvaluationThreadNode("thread:evaluation:run-1:conv-1"))
	g.AddNode(validDecisionNode("decision:evaluation:run-1:conv-1:turn-1"))
	g.AddNode(validActionNode("action:evaluation:run-1:conv-1:tool-1"))
	g.AddNode(validOutcomeNode("outcome:evaluation:run-1:conv-1"))
	g.AddNode(validPackageNode("package:payments@1.0.0"))
	g.AddNode(validVulnerabilityNode("vuln:CVE-2026-0001"))

	g.AddEdge(&Edge{ID: "edge:action-valid", Source: "action:evaluation:run-1:conv-1:tool-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:action-invalid", Source: "action:evaluation:run-1:conv-1:tool-1", Target: "thread:evaluation:run-1:conv-1", Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:outcome-valid", Source: "outcome:evaluation:run-1:conv-1", Target: "decision:evaluation:run-1:conv-1:turn-1", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:outcome-invalid", Source: "outcome:evaluation:run-1:conv-1", Target: "thread:evaluation:run-1:conv-1", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:package-valid", Source: "package:payments@1.0.0", Target: "vuln:CVE-2026-0001", Kind: EdgeKindAffectedBy, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge:package-invalid", Source: "package:payments@1.0.0", Target: "thread:evaluation:run-1:conv-1", Kind: EdgeKindAffectedBy, Effect: EdgeEffectAllow})

	if got := g.EdgeCount(); got != 3 {
		t.Fatalf("EdgeCount() = %d, want 3 accepted edges", got)
	}

	stats := g.SchemaValidationStats()
	if stats.EdgeRejected < 3 {
		t.Fatalf("expected at least three rejected edges, got %#v", stats)
	}
	if stats.EdgeRejectByCode[string(SchemaIssueRelationshipNotAllowed)] < 3 {
		t.Fatalf("expected relationship-not-allowed rejects, got %#v", stats)
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

func validEvaluationThreadNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindThread,
		Properties: map[string]any{
			"thread_id":     "conv-1",
			"channel_id":    "run-1",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-23T00:00:00Z",
			"valid_from":    "2026-03-23T00:00:00Z",
		},
	}
}

func validDecisionNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindDecision,
		Properties: map[string]any{
			"decision_type": "tool_selection",
			"status":        "completed",
			"made_at":       "2026-03-23T00:01:00Z",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-23T00:01:00Z",
			"valid_from":    "2026-03-23T00:01:00Z",
		},
	}
}

func validActionNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindAction,
		Properties: map[string]any{
			"action_type":   "tool_call",
			"status":        "completed",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-23T00:02:00Z",
			"valid_from":    "2026-03-23T00:02:00Z",
		},
	}
}

func validOutcomeNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindOutcome,
		Properties: map[string]any{
			"outcome_type":  "evaluation_conversation",
			"verdict":       "positive",
			"source_system": "platform_eval",
			"observed_at":   "2026-03-23T00:03:00Z",
			"valid_from":    "2026-03-23T00:03:00Z",
		},
	}
}

func validPackageNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindPackage,
		Properties: map[string]any{
			"package_name":     "payments",
			"version":          "1.0.0",
			"ecosystem":        "go",
			"source_system":    "scanner",
			"observed_at":      "2026-03-23T00:04:00Z",
			"valid_from":       "2026-03-23T00:04:00Z",
			"recorded_at":      "2026-03-23T00:04:00Z",
			"transaction_from": "2026-03-23T00:04:00Z",
		},
	}
}

func validVulnerabilityNode(id string) *Node {
	return &Node{
		ID:   id,
		Kind: NodeKindVulnerability,
		Properties: map[string]any{
			"vulnerability_id": "CVE-2026-0001",
			"severity":         "high",
			"source_system":    "scanner",
			"observed_at":      "2026-03-23T00:05:00Z",
			"valid_from":       "2026-03-23T00:05:00Z",
			"recorded_at":      "2026-03-23T00:05:00Z",
			"transaction_from": "2026-03-23T00:05:00Z",
		},
	}
}
