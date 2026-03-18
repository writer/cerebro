package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type nilSnapshotGraphStore struct {
	graph.GraphStore
}

func (n nilSnapshotGraphStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	return nil, nil
}

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

func buildGraphStoreVisualizationTestGraph() *graph.Graph {
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
	g.AddEdge(&graph.Edge{ID: "internet-to-web", Source: "internet", Target: "web-server", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "web-server-assumes", Source: "web-server", Target: "web-role", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-to-db", Source: "web-role", Target: "prod-db", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
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

func TestVisualizeAttackPathUsesGraphStoreSnapshotWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreVisualizationTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/graph/visualize/attack-path/0", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected attack-path visualization 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "```mermaid") || !strings.Contains(body, "Production Database") {
		t.Fatalf("expected mermaid attack path output, got %q", body)
	}
}

func TestVisualizeToxicCombinationUsesGraphStoreSnapshotWhenRawGraphUnavailable(t *testing.T) {
	g := buildGraphStoreVisualizationTestGraph()
	results := graph.NewToxicCombinationEngine().Analyze(g)
	if len(results) == 0 {
		t.Fatal("expected at least one toxic combination in test graph")
	}

	s := newStoreBackedGraphServer(t, g)
	resp := do(t, s, http.MethodGet, "/api/v1/graph/visualize/toxic-combination/"+results[0].ID, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected toxic-combination visualization 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "```mermaid") || !strings.Contains(body, results[0].Name) {
		t.Fatalf("expected mermaid toxic combination output, got %q", body)
	}
}

func TestVisualizeReportUsesGraphStoreSnapshotWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreVisualizationTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/graph/visualize/report", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected report visualization 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "# Security Report") || !strings.Contains(body, "Risk Score") {
		t.Fatalf("expected report visualization output, got %q", body)
	}
}

func TestVisualizeReportReturnsServiceUnavailableWhenStoreSnapshotMissing(t *testing.T) {
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: buildGraphStoreVisualizationTestGraph()})

	resp := do(t, s, http.MethodGet, "/api/v1/graph/visualize/report", nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected report visualization 503, got %d: %s", resp.Code, resp.Body.String())
	}
}
