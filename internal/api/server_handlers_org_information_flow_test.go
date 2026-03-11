package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestOrgInformationFlowEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgInformationFlowGraph(s.app.SecurityGraph, time.Now().UTC())

	w := do(t, s, http.MethodGet, "/api/v1/org/information-flow?from=team/support&to=team/engineering", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["source"] != "team/support" {
		t.Fatalf("expected source team/support, got %v", body["source"])
	}
	if body["destination"] != "team/engineering" {
		t.Fatalf("expected destination team/engineering, got %v", body["destination"])
	}
	path, ok := body["path"].([]any)
	if !ok || len(path) < 3 {
		t.Fatalf("expected path with at least 3 nodes, got %T %#v", body["path"], body["path"])
	}
}

func TestOrgInformationFlowEndpoint_ValidationAndNotFound(t *testing.T) {
	s := newTestServer(t)
	seedOrgInformationFlowGraph(s.app.SecurityGraph, time.Now().UTC())

	w := do(t, s, http.MethodGet, "/api/v1/org/information-flow?from=team/support", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing to param, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/org/information-flow?from=team/unknown&to=team/engineering", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing path, got %d", w.Code)
	}
}

func TestOrgClockSpeedEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgInformationFlowGraph(s.app.SecurityGraph, time.Now().UTC())

	w := do(t, s, http.MethodGet, "/api/v1/org/clock-speed", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["customer_issue_to_resolver"].(map[string]any); !ok {
		t.Fatalf("expected customer_issue_to_resolver metrics in response")
	}
	if _, ok := body["average_hops"].(float64); !ok {
		t.Fatalf("expected average_hops in response")
	}
}

func TestOrgRecommendedConnectionsEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgInformationFlowGraph(s.app.SecurityGraph, time.Now().UTC())

	w := do(t, s, http.MethodGet, "/api/v1/org/recommended-connections?limit=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) != 1 {
		t.Fatalf("expected count=1, got %v", body["count"])
	}
	recs, ok := body["recommendations"].([]any)
	if !ok || len(recs) != 1 {
		t.Fatalf("expected exactly one recommendation, got %T %#v", body["recommendations"], body["recommendations"])
	}
}

func seedOrgInformationFlowGraph(g *graph.Graph, now time.Time) {
	g.AddNode(&graph.Node{ID: "department:support", Kind: graph.NodeKindDepartment, Name: "Support"})
	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&graph.Node{ID: "department:product", Kind: graph.NodeKindDepartment, Name: "Product"})

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support", "title": "Support Lead"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"title": "Support Engineer"}})
	g.AddNode(&graph.Node{ID: "person:carol@example.com", Kind: graph.NodeKindPerson, Name: "Carol", Properties: map[string]any{"department": "engineering", "title": "Senior Engineer"}})
	g.AddNode(&graph.Node{ID: "person:dave@example.com", Kind: graph.NodeKindPerson, Name: "Dave", Properties: map[string]any{"department": "product", "title": "Product Manager"}})
	g.AddNode(&graph.Node{ID: "person:erin@example.com", Kind: graph.NodeKindPerson, Name: "Erin", Properties: map[string]any{"title": "VP Engineering"}})

	g.AddNode(&graph.Node{ID: "system:payment-service", Kind: graph.NodeKindApplication, Name: "payment-service", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "customer:northwind", Kind: graph.NodeKindCustomer, Name: "Northwind"})
	g.AddNode(&graph.Node{ID: "ticket:incident-1", Kind: graph.NodeKindTicket, Name: "Incident P1", Properties: map[string]any{"severity": "high"}})
	g.AddNode(&graph.Node{ID: "lead:expansion-1", Kind: graph.NodeKindLead, Name: "Northwind Expansion"})

	g.AddEdge(&graph.Edge{ID: "m1", Source: "person:alice@example.com", Target: "department:support", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m2", Source: "person:carol@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m3", Source: "person:dave@example.com", Target: "department:product", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})

	g.AddEdge(&graph.Edge{ID: "ia", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 18, "last_seen": now.Add(-2 * time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "ib", Source: "person:bob@example.com", Target: "person:carol@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 12, "last_seen": now.Add(-4 * time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "ic", Source: "person:carol@example.com", Target: "person:dave@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 8, "last_seen": now.Add(-6 * time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "id", Source: "person:dave@example.com", Target: "person:erin@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 6, "last_seen": now.Add(-8 * time.Hour)}})

	g.AddEdge(&graph.Edge{ID: "resolver-a", Source: "person:alice@example.com", Target: "system:payment-service", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "resolver-c", Source: "person:carol@example.com", Target: "system:payment-service", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "cust-a", Source: "person:alice@example.com", Target: "customer:northwind", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "cust-c", Source: "person:carol@example.com", Target: "customer:northwind", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})

	g.AddEdge(&graph.Edge{ID: "ticket-escalate", Source: "ticket:incident-1", Target: "person:alice@example.com", Kind: graph.EdgeKindEscalatedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "customer-ticket", Source: "customer:northwind", Target: "ticket:incident-1", Kind: graph.EdgeKindRefers, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "lead-customer", Source: "lead:expansion-1", Target: "customer:northwind", Kind: graph.EdgeKindRefers, Effect: graph.EdgeEffectAllow})
}
