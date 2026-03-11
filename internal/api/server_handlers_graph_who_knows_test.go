package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestGraphWhoKnowsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "system:auth-svc", Kind: graph.NodeKindApplication, Name: "auth-svc"})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"status": "active"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"status": "active"}})
	g.AddNode(&graph.Node{ID: "person:carol@example.com", Kind: graph.NodeKindPerson, Name: "Carol", Properties: map[string]any{"status": "active"}})

	now := time.Now().UTC()
	g.AddEdge(&graph.Edge{
		ID:     "alice-auth",
		Source: "person:alice@example.com",
		Target: "system:auth-svc",
		Kind:   graph.EdgeKindManagedBy,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"commit_count": 220,
			"last_seen":    now.Add(-1 * time.Hour),
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "bob-auth",
		Source: "person:bob@example.com",
		Target: "system:auth-svc",
		Kind:   graph.EdgeKindAssignedTo,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"review_count": 80,
			"last_seen":    now.Add(-8 * time.Hour),
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "alice-carol",
		Source: "person:alice@example.com",
		Target: "person:carol@example.com",
		Kind:   graph.EdgeKindInteractedWith,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"frequency": 24,
			"strength":  1.5,
			"last_seen": now.Add(-2 * time.Hour),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=auth-svc&limit=2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) != 2 {
		t.Fatalf("expected count=2, got %v", body["count"])
	}

	targets, ok := body["targets"].([]any)
	if !ok || len(targets) == 0 {
		t.Fatalf("expected at least one target, got %T %#v", body["targets"], body["targets"])
	}

	candidates, ok := body["candidates"].([]any)
	if !ok || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %T %#v", body["candidates"], body["candidates"])
	}

	topCandidate, ok := candidates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map candidate, got %T", candidates[0])
	}
	person, ok := topCandidate["person"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested person object, got %T", topCandidate["person"])
	}
	if person["id"] != "person:alice@example.com" {
		t.Fatalf("expected alice as top expert, got %v", person["id"])
	}
}

func TestGraphWhoKnowsEndpoint_RequiresQuery(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGraphWhoKnowsEndpoint_AvailableFilter(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "system:payment-service", Kind: graph.NodeKindApplication, Name: "payment-service"})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"status": "on_leave"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"status": "active"}})

	now := time.Now().UTC()
	g.AddEdge(&graph.Edge{
		ID:     "alice-payment",
		Source: "person:alice@example.com",
		Target: "system:payment-service",
		Kind:   graph.EdgeKindManagedBy,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"commit_count": 400,
			"last_seen":    now,
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "bob-payment",
		Source: "person:bob@example.com",
		Target: "system:payment-service",
		Kind:   graph.EdgeKindAssignedTo,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"review_count": 45,
			"last_seen":    now.Add(-6 * time.Hour),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=payment-service&available=true&limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	candidates, ok := body["candidates"].([]any)
	if !ok || len(candidates) != 1 {
		t.Fatalf("expected one available candidate, got %T %#v", body["candidates"], body["candidates"])
	}
	only, ok := candidates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map candidate, got %T", candidates[0])
	}
	person, ok := only["person"].(map[string]any)
	if !ok {
		t.Fatalf("expected person map, got %T", only["person"])
	}
	if person["id"] != "person:bob@example.com" {
		t.Fatalf("expected bob as available candidate, got %v", person["id"])
	}
}
