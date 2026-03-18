package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type failingSnapshotGraphStore struct {
	graph.GraphStore
}

func (f failingSnapshotGraphStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	return nil, errors.New("snapshot should not be called when live graph is available")
}

func buildGraphStoreOrgExpertiseTestGraph() *graph.Graph {
	g := graph.New()
	seedRecommendTeamGraph(g)
	return g
}

func TestGraphWhoKnowsUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreOrgExpertiseTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=payment-service&limit=2", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected expertise query 200, got %d: %s", resp.Code, resp.Body.String())
	}

	body := decodeJSON(t, resp)
	candidates, ok := body["candidates"].([]any)
	if !ok || len(candidates) == 0 {
		t.Fatalf("expected expertise candidates from store-backed handler, got %#v", body)
	}
}

func TestRecommendTeamUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreOrgExpertiseTestGraph())

	resp := do(t, s, http.MethodPost, "/api/v1/org/team-recommendations", map[string]any{
		"target_systems": []string{"payment-service", "billing-api"},
		"domains":        []string{"payments", "customer-facing"},
		"team_size":      2,
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected team recommendation 200, got %d: %s", resp.Code, resp.Body.String())
	}

	body := decodeJSON(t, resp)
	recommended, ok := body["recommended_team"].([]any)
	if !ok || len(recommended) == 0 {
		t.Fatalf("expected recommended_team from store-backed handler, got %#v", body)
	}
}

func TestGraphWhoKnowsPrefersLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	g := buildGraphStoreOrgExpertiseTestGraph()
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: g,
			store: failingSnapshotGraphStore{GraphStore: g},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=payment-service&limit=2", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected expertise query 200, got %d: %s", resp.Code, resp.Body.String())
	}
}
