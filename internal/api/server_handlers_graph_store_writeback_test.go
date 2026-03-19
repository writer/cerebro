package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphIdentityCalibrationUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreIdentityCalibrationTestGraph(t))

	resp := do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration?include_queue=true&queue_limit=10&suggest_threshold=0.2", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected calibration 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got := int(body["alias_nodes"].(float64)); got != 2 {
		t.Fatalf("expected alias_nodes=2 from store-backed calibration, got %#v", body)
	}
	queue, ok := body["queue"].([]any)
	if !ok || len(queue) == 0 {
		t.Fatalf("expected non-empty review queue from store-backed calibration, got %#v", body)
	}
}

func TestGraphIdentityCalibrationPrefersLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: buildGraphStoreIdentityCalibrationTestGraph(t),
			store: failingSnapshotGraphStore{GraphStore: buildGraphStoreIdentityCalibrationTestGraph(t)},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration?include_queue=true&queue_limit=10&suggest_threshold=0.2", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected calibration 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestGraphIdentityCalibrationReturnsServiceUnavailableWithoutGraphSources(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration", nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected calibration 503 without graph sources, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestGraphIdentityCalibrationReturnsServiceUnavailableWhenStoreSnapshotFails(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			store: errorSnapshotGraphStore{
				GraphStore: graph.New(),
				err:        errors.New("transient snapshot read failure"),
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration", nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected calibration 503 when store snapshot fails, got %d: %s", resp.Code, resp.Body.String())
	}
}

type errorSnapshotGraphStore struct {
	graph.GraphStore
	err error
}

func (s errorSnapshotGraphStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	return nil, s.err
}

func buildGraphStoreIdentityCalibrationTestGraph(t *testing.T) *graph.Graph {
	t.Helper()

	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"email": "alice@example.com"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"email": "bob@example.com"}})

	g.AddNode(&graph.Node{ID: "alias:github:alice", Kind: graph.NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"name":          "Alice",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "alias:slack:alice", Kind: graph.NodeKindIdentityAlias, Name: "alice.s", Properties: map[string]any{
		"source_system": "slack",
		"external_id":   "U123",
		"name":          "Alice Smith",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})

	if _, err := graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:alice@example.com",
		Verdict:         graph.IdentityReviewVerdictAccepted,
		ObservedAt:      now,
		Reviewer:        "reviewer-1",
		Reason:          "email exact match",
	}); err != nil {
		t.Fatalf("accepted review: %v", err)
	}
	if _, err := graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:bob@example.com",
		Verdict:         graph.IdentityReviewVerdictRejected,
		ObservedAt:      now.Add(time.Minute),
		Reviewer:        "reviewer-1",
		Reason:          "false candidate",
	}); err != nil {
		t.Fatalf("rejected review: %v", err)
	}

	return g
}
