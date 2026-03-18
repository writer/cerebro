package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

func newStoreBackedGraphServer(t *testing.T, store graph.GraphStore) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		graphRuntime: stubGraphRuntime{store: store},
	})
	t.Cleanup(func() { s.Close() })
	return s
}

func buildGraphStoreTraversalTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "service:api", Kind: graph.NodeKindService, Name: "API"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskHigh})
	g.AddEdge(&graph.Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "api-db", Source: "service:api", Target: "db:prod", Kind: graph.EdgeKindDependsOn, Effect: graph.EdgeEffectAllow})
	return g
}

func TestGraphTraversalHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreTraversalTestGraph())

	blast := do(t, s, http.MethodGet, "/api/v1/graph/blast-radius/user:alice?max_depth=3", nil)
	if blast.Code != http.StatusOK {
		t.Fatalf("expected blast radius 200, got %d: %s", blast.Code, blast.Body.String())
	}
	blastBody := decodeJSON(t, blast)
	if got := int(blastBody["total_count"].(float64)); got < 1 {
		t.Fatalf("expected blast radius results from store-backed handler, got %#v", blastBody)
	}

	cascade := do(t, s, http.MethodGet, "/api/v1/graph/cascading-blast-radius/service:api?max_depth=3", nil)
	if cascade.Code != http.StatusOK {
		t.Fatalf("expected cascading blast radius 200, got %d: %s", cascade.Code, cascade.Body.String())
	}

	reverse := do(t, s, http.MethodGet, "/api/v1/graph/reverse-access/db:prod?max_depth=3", nil)
	if reverse.Code != http.StatusOK {
		t.Fatalf("expected reverse access 200, got %d: %s", reverse.Code, reverse.Body.String())
	}
	reverseBody := decodeJSON(t, reverse)
	if got := int(reverseBody["total_count"].(float64)); got != 1 {
		t.Fatalf("expected one reverse-access principal, got %#v", reverseBody)
	}
}

func TestVisualizeBlastRadiusUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreTraversalTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/graph/visualize/blast-radius/user:alice?max_depth=3", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected blast-radius visualization 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Content-Type"); !strings.Contains(got, "text/markdown") {
		t.Fatalf("expected markdown content type, got %q", got)
	}
	body := resp.Body.String()
	if !strings.Contains(body, "```mermaid") || !strings.Contains(body, "Alice") {
		t.Fatalf("expected mermaid blast radius output, got %q", body)
	}
}
