package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreStatsTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "service:api", Kind: graph.NodeKindService, Name: "API"})
	g.AddEdge(&graph.Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	meta := g.Metadata()
	meta.BuiltAt = time.Date(2026, 3, 18, 16, 0, 0, 0, time.UTC)
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	meta.Providers = []string{"aws", "gcp"}
	meta.Accounts = []string{"123456789012", "projects/demo"}
	meta.BuildDuration = 1500 * time.Millisecond
	g.SetMetadata(meta)
	return g
}

func TestGraphStatsUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreStatsTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/graph/stats", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected graph stats 200, got %d: %s", resp.Code, resp.Body.String())
	}

	body := decodeJSON(t, resp)
	if got := int(body["node_count"].(float64)); got != 2 {
		t.Fatalf("expected node_count=2 from store-backed graph stats, got %#v", body)
	}
	if got := int(body["edge_count"].(float64)); got != 1 {
		t.Fatalf("expected edge_count=1 from store-backed graph stats, got %#v", body)
	}
	if body["build_duration"] != "1.5s" {
		t.Fatalf("expected build_duration=1.5s, got %#v", body["build_duration"])
	}
}

func TestGraphStatsPrefersLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	g := buildGraphStoreStatsTestGraph()
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: g,
			store: failingSnapshotGraphStore{GraphStore: g},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/graph/stats", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected graph stats 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestGraphRebuildUsesGraphRuntimeStoreWhenLiveGraphUnavailable(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			store: buildGraphStoreStatsTestGraph(),
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodPost, "/api/v1/graph/rebuild", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected graph rebuild 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got := int(body["node_count"].(float64)); got != 2 {
		t.Fatalf("expected node_count=2 from store-backed rebuild, got %#v", body)
	}
	if got := int(body["edge_count"].(float64)); got != 1 {
		t.Fatalf("expected edge_count=1 from store-backed rebuild, got %#v", body)
	}
}

func TestGraphRebuildPrefersRuntimeGraphOverSnapshotWhenAvailable(t *testing.T) {
	g := buildGraphStoreStatsTestGraph()
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: g,
			store: failingSnapshotGraphStore{GraphStore: g},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodPost, "/api/v1/graph/rebuild", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected graph rebuild 200, got %d: %s", resp.Code, resp.Body.String())
	}
}
