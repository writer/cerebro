package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type failAfterFirstSnapshotStore struct {
	graph.GraphStore
	snapshotCalls int
}

func (s *failAfterFirstSnapshotStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	s.snapshotCalls++
	if s.snapshotCalls > 1 {
		return nil, graph.ErrStoreUnavailable
	}
	return s.GraphStore.Snapshot(ctx)
}

type failingSnapshotStore struct {
	graph.GraphStore
	err error
}

func (s failingSnapshotStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	return nil, s.err
}

func TestGraphAccessReviewHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreAccessReviewTestGraph())

	create := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Store-backed graph review",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"type":       "resource",
			"resources":  []string{"bucket:prod-data"},
			"principals": []string{"user:alice"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	if created["generation_source"] != "graph" {
		t.Fatalf("expected graph generation source, got %#v", created)
	}
	items, ok := created["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one generated item from store-backed graph, got %#v", created["items"])
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/access-reviews", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", list.Code, list.Body.String())
	}
	body := decodeJSON(t, list)
	if got := int(body["count"].(float64)); got != 1 {
		t.Fatalf("expected one persisted graph access review, got %#v", body)
	}
}

func TestGraphAccessReviewCreateReusesResolvedStoreGraph(t *testing.T) {
	store := &failAfterFirstSnapshotStore{GraphStore: buildGraphStoreAccessReviewTestGraph()}
	s := newStoreBackedGraphServer(t, store)

	create := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Store-backed graph review",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"type":       "resource",
			"resources":  []string{"bucket:prod-data"},
			"principals": []string{"user:alice"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	items, ok := created["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one generated item from the reused resolved graph, got %#v", created["items"])
	}
	if store.snapshotCalls != 1 {
		t.Fatalf("expected exactly one snapshot lookup, got %d", store.snapshotCalls)
	}
}

func TestGraphAccessReviewCreatePropagatesGraphViewErrors(t *testing.T) {
	s := newStoreBackedGraphServer(t, failingSnapshotStore{
		GraphStore: buildGraphStoreAccessReviewTestGraph(),
		err:        errors.New("snapshot boom"),
	})

	create := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Store-backed graph review",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"type":       "resource",
			"resources":  []string{"bucket:prod-data"},
			"principals": []string{"user:alice"},
		},
	})
	if create.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for snapshot errors, got %d body=%s", create.Code, create.Body.String())
	}
}

func buildGraphStoreAccessReviewTestGraph() *graph.Graph {
	lastLogin := time.Now().Add(-120 * 24 * time.Hour).UTC().Format(time.RFC3339)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: time.Now().Add(-400 * 24 * time.Hour).UTC(),
		Properties: map[string]any{
			"email":      "alice@example.com",
			"last_login": lastLogin,
		},
	})
	g.AddNode(&graph.Node{
		ID:        "person:bob",
		Kind:      graph.NodeKindPerson,
		Name:      "Bob Reviewer",
		Provider:  "internal",
		Account:   "corp",
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:prod-data",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-data",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "bucket:prod-data", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "bob-owner", Source: "person:bob", Target: "bucket:prod-data", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	return g
}
