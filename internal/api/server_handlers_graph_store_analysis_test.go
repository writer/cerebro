package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreRiskAnalysisTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
	g.AddNode(&graph.Node{
		ID:      "web-server",
		Kind:    graph.NodeKindInstance,
		Name:    "Web Server",
		Account: "123456789012",
		Risk:    graph.RiskHigh,
		Properties: map[string]any{
			"vulnerabilities": []any{"CVE-2021-44228"},
		},
	})
	g.AddNode(&graph.Node{
		ID:      "web-role",
		Kind:    graph.NodeKindRole,
		Name:    "WebServerRole",
		Account: "123456789012",
	})
	g.AddNode(&graph.Node{
		ID:      "prod-db",
		Kind:    graph.NodeKindDatabase,
		Name:    "Production Database",
		Account: "123456789012",
		Risk:    graph.RiskCritical,
		Tags:    map[string]string{"contains_pii": "true"},
	})
	g.AddNode(&graph.Node{
		ID:      "user:alice",
		Kind:    graph.NodeKindUser,
		Name:    "Alice",
		Account: "123456789012",
	})
	g.AddNode(&graph.Node{
		ID:      "user:bob",
		Kind:    graph.NodeKindUser,
		Name:    "Bob",
		Account: "123456789012",
	})

	g.AddEdge(&graph.Edge{ID: "internet-to-web", Source: "internet", Target: "web-server", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "web-server-assumes", Source: "web-server", Target: "web-role", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-to-db", Source: "web-role", Target: "prod-db", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "alice-assumes", Source: "user:alice", Target: "web-role", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})

	return g
}

func TestGraphRiskAnalysisHandlersUseGraphStoreSnapshotWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreRiskAnalysisTestGraph())

	toxic := do(t, s, http.MethodGet, "/api/v1/graph/toxic-combinations", nil)
	if toxic.Code != http.StatusOK {
		t.Fatalf("expected toxic combinations 200, got %d: %s", toxic.Code, toxic.Body.String())
	}
	toxicBody := decodeJSON(t, toxic)
	if got := int(toxicBody["total_count"].(float64)); got < 1 {
		t.Fatalf("expected toxic combinations from store-backed handler, got %#v", toxicBody)
	}

	attack := do(t, s, http.MethodGet, "/api/v1/graph/attack-paths?limit=5", nil)
	if attack.Code != http.StatusOK {
		t.Fatalf("expected attack paths 200, got %d: %s", attack.Code, attack.Body.String())
	}
	attackBody := decodeJSON(t, attack)
	if got := int(attackBody["total_paths"].(float64)); got < 1 {
		t.Fatalf("expected attack paths from store-backed handler, got %#v", attackBody)
	}

	simFix := do(t, s, http.MethodGet, "/api/v1/graph/attack-paths/web-role/simulate-fix", nil)
	if simFix.Code != http.StatusOK {
		t.Fatalf("expected simulate-fix 200, got %d: %s", simFix.Code, simFix.Body.String())
	}
	if body := simFix.Body.String(); !strings.Contains(body, "blocked_paths") {
		t.Fatalf("expected simulation output, got %q", body)
	}

	choke := do(t, s, http.MethodGet, "/api/v1/graph/chokepoints", nil)
	if choke.Code != http.StatusOK {
		t.Fatalf("expected chokepoints 200, got %d: %s", choke.Code, choke.Body.String())
	}
	chokeBody := decodeJSON(t, choke)
	if got := int(chokeBody["total"].(float64)); got < 1 {
		t.Fatalf("expected chokepoints from store-backed handler, got %#v", chokeBody)
	}

	perm := do(t, s, http.MethodGet, "/api/v1/graph/effective-permissions/user:alice", nil)
	if perm.Code != http.StatusOK {
		t.Fatalf("expected effective permissions 200, got %d: %s", perm.Code, perm.Body.String())
	}
	permBody := decodeJSON(t, perm)
	if got := permBody["principal_id"]; got != "user:alice" {
		t.Fatalf("expected effective permissions principal, got %#v", got)
	}

	compare := do(t, s, http.MethodGet, "/api/v1/graph/compare-permissions?principal1=user:alice&principal2=user:bob", nil)
	if compare.Code != http.StatusOK {
		t.Fatalf("expected compare permissions 200, got %d: %s", compare.Code, compare.Body.String())
	}

	peer := do(t, s, http.MethodGet, "/api/v1/graph/peer-groups", nil)
	if peer.Code != http.StatusOK {
		t.Fatalf("expected peer groups 200, got %d: %s", peer.Code, peer.Body.String())
	}

	escalation := do(t, s, http.MethodGet, "/api/v1/graph/privilege-escalation/user:alice", nil)
	if escalation.Code != http.StatusOK {
		t.Fatalf("expected privilege escalation 200, got %d: %s", escalation.Code, escalation.Body.String())
	}
}

func buildGraphStorePropagationTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "svc-1", Kind: graph.NodeKindApplication, Name: "svc-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 1500000.0}})
	g.AddEdge(&graph.Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()
	return g
}

func buildGraphStoreSchemaHealthTestGraph(t *testing.T) *graph.Graph {
	t.Helper()
	const (
		requiredKind  = "api_health_required_employee_v1"
		sourceKind    = "api_health_source_v1"
		targetKind    = "api_health_target_v1"
		unknownNode   = "api_health_unknown_kind_v1"
		unknownEdge   = "api_health_unknown_edge_v1"
		requiredNode  = "node:required-missing"
		sourceNodeID  = "node:source"
		targetNodeID  = "node:target"
		unknownNodeID = "node:unknown"
	)

	if _, err := graph.RegisterNodeKindDefinition(graph.NodeKindDefinition{
		Kind:               graph.NodeKind(requiredKind),
		Categories:         []graph.NodeKindCategory{graph.NodeCategoryBusiness},
		Properties:         map[string]string{"title": "string"},
		RequiredProperties: []string{"title"},
	}); err != nil {
		t.Fatalf("register required kind: %v", err)
	}
	if _, err := graph.RegisterNodeKindDefinition(graph.NodeKindDefinition{
		Kind:          graph.NodeKind(sourceKind),
		Categories:    []graph.NodeKindCategory{graph.NodeCategoryBusiness},
		Relationships: []graph.EdgeKind{graph.EdgeKindReportsTo},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := graph.RegisterNodeKindDefinition(graph.NodeKindDefinition{
		Kind:       graph.NodeKind(targetKind),
		Categories: []graph.NodeKindCategory{graph.NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{ID: requiredNode, Kind: graph.NodeKind(requiredKind), Name: "Missing Required"})
	g.AddNode(&graph.Node{ID: sourceNodeID, Kind: graph.NodeKind(sourceKind), Name: "Source"})
	g.AddNode(&graph.Node{ID: targetNodeID, Kind: graph.NodeKind(targetKind), Name: "Target"})
	g.AddNode(&graph.Node{ID: unknownNodeID, Kind: graph.NodeKind(unknownNode), Name: "Unknown"})
	g.AddEdge(&graph.Edge{
		ID:     "edge:invalid-relationship",
		Source: sourceNodeID,
		Target: targetNodeID,
		Kind:   graph.EdgeKindCanRead,
		Effect: graph.EdgeEffectAllow,
	})
	g.AddEdge(&graph.Edge{
		ID:     "edge:unknown-kind",
		Source: sourceNodeID,
		Target: targetNodeID,
		Kind:   graph.EdgeKind(unknownEdge),
		Effect: graph.EdgeEffectAllow,
	})
	return g
}

func TestGraphAnalysisHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStorePropagationTestGraph())

	eval := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{
		"id":                     "proposal-1",
		"source":                 "api-test",
		"reason":                 "quarterly review",
		"approval_arr_threshold": 100000.0,
		"mutations":              []map[string]any{{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": false}}},
	})
	if eval.Code != http.StatusOK {
		t.Fatalf("expected evaluate-change 200, got %d: %s", eval.Code, eval.Body.String())
	}
	evalBody := decodeJSON(t, eval)
	if evalBody["decision"] != string(graph.DecisionNeedsApproval) {
		t.Fatalf("expected decision %q from store-backed propagation handler, got %#v", graph.DecisionNeedsApproval, evalBody["decision"])
	}

	schema := newStoreBackedGraphServer(t, buildGraphStoreSchemaHealthTestGraph(t))
	health := do(t, schema, http.MethodGet, "/api/v1/graph/schema/health", nil)
	if health.Code != http.StatusOK {
		t.Fatalf("expected schema health 200, got %d: %s", health.Code, health.Body.String())
	}
	body := decodeJSON(t, health)
	if !jsonArrayHasIssueCode(body["missing_required_properties"], string(graph.SchemaIssueMissingRequiredProperty)) {
		t.Fatalf("expected missing_required_property issue from store-backed schema handler, got %#v", body["missing_required_properties"])
	}
	if !jsonArrayHasIssueCode(body["invalid_relationships"], string(graph.SchemaIssueRelationshipNotAllowed)) {
		t.Fatalf("expected relationship_not_allowed issue from store-backed schema handler, got %#v", body["invalid_relationships"])
	}
}
