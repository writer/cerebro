package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
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
