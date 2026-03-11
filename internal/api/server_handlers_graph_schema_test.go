package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestGraphSchemaRegisterAndListEndpoints(t *testing.T) {
	s := newTestServer(t)
	nodeKind := "api_dynamic_employee_v1"
	edgeKind := "api_dynamic_reports_to_v1"

	w := do(t, s, http.MethodPost, "/api/v1/graph/schema/register", map[string]any{
		"node_kinds": []map[string]any{
			{
				"kind":          nodeKind,
				"categories":    []string{"identity", "business"},
				"properties":    map[string]any{"title": "string"},
				"relationships": []string{"reports_to"},
				"description":   "Dynamic employee entity from integration metadata",
			},
		},
		"edge_kinds": []map[string]any{
			{
				"kind":        edgeKind,
				"description": "Dynamic reporting relationship",
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["schema_version"].(float64); !ok {
		t.Fatalf("expected schema_version in response, got %#v", body["schema_version"])
	}
	if !jsonArrayHasKind(body["registered_node_kinds"], nodeKind) {
		t.Fatalf("expected registered_node_kinds to contain %q, got %#v", nodeKind, body["registered_node_kinds"])
	}
	if !jsonArrayHasKind(body["registered_edge_kinds"], edgeKind) {
		t.Fatalf("expected registered_edge_kinds to contain %q, got %#v", edgeKind, body["registered_edge_kinds"])
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/schema", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 from schema list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if !jsonArrayHasKind(listBody["node_kinds"], nodeKind) {
		t.Fatalf("expected node_kinds list to contain %q", nodeKind)
	}
	if !jsonArrayHasKind(listBody["edge_kinds"], edgeKind) {
		t.Fatalf("expected edge_kinds list to contain %q", edgeKind)
	}

	node := &graph.Node{Kind: graph.NodeKind(nodeKind)}
	if !node.IsIdentity() || !node.IsBusinessEntity() {
		t.Fatalf("expected dynamic node kind %q to be categorized identity+business", nodeKind)
	}
}

func TestGraphSchemaHealthEndpoint(t *testing.T) {
	s := newTestServer(t)

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

	g := s.app.SecurityGraph
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

	w := do(t, s, http.MethodGet, "/api/v1/graph/schema/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	nodes, ok := body["nodes"].(map[string]any)
	if !ok {
		t.Fatalf("expected nodes object, got %#v", body["nodes"])
	}
	if got, _ := nodes["total"].(float64); got < 4 {
		t.Fatalf("expected at least 4 nodes in health report, got %#v", nodes["total"])
	}

	if !jsonArrayHasKindCount(body["unknown_node_kinds"], unknownNode) {
		t.Fatalf("expected unknown node kind %q in report, got %#v", unknownNode, body["unknown_node_kinds"])
	}
	if !jsonArrayHasKindCount(body["unknown_edge_kinds"], unknownEdge) {
		t.Fatalf("expected unknown edge kind %q in report, got %#v", unknownEdge, body["unknown_edge_kinds"])
	}

	if !jsonArrayHasIssueCode(body["missing_required_properties"], string(graph.SchemaIssueMissingRequiredProperty)) {
		t.Fatalf("expected missing_required_property issue, got %#v", body["missing_required_properties"])
	}
	if !jsonArrayHasIssueCode(body["invalid_relationships"], string(graph.SchemaIssueRelationshipNotAllowed)) {
		t.Fatalf("expected relationship_not_allowed issue, got %#v", body["invalid_relationships"])
	}
}

func TestGraphSchemaRegisterEndpoint_InvalidPayload(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/graph/schema/register", map[string]any{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty payload, got %d", w.Code)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/schema/register", map[string]any{
		"node_kinds": []map[string]any{
			{
				"kind":       "api_invalid_category_v1",
				"categories": []string{"unknown"},
			},
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid node category, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/schema/health?history_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid history_limit, got %d", w.Code)
	}
}

func jsonArrayHasKind(raw any, kind string) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := obj["kind"].(string); got == kind {
			return true
		}
	}
	return false
}

func jsonArrayHasKindCount(raw any, kind string) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := obj["kind"].(string); got == kind {
			return true
		}
	}
	return false
}

func jsonArrayHasIssueCode(raw any, code string) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := obj["code"].(string); got == code {
			return true
		}
	}
	return false
}
