package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

func buildGraphStoreRiskAnalysisTestGraph() *graph.Graph {
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
	g.AddNode(&graph.Node{
		ID:      "user:alice",
		Kind:    graph.NodeKindUser,
		Name:    "Alice",
		Account: "123456789012",
	})
	g.AddNode(&graph.Node{
		ID:      "user:bob",
		Kind:    graph.NodeKindUser,
		Name:    "Bob",
		Account: "123456789012",
	})

	g.AddEdge(&graph.Edge{ID: "internet-to-web", Source: "internet", Target: "web-server", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "web-server-assumes", Source: "web-server", Target: "web-role", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-to-db", Source: "web-role", Target: "prod-db", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "alice-assumes", Source: "user:alice", Target: "web-role", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})

	return g
}

func TestGraphRiskAnalysisHandlersUseGraphStoreSnapshotWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreRiskAnalysisTestGraph())

	toxic := do(t, s, http.MethodGet, "/api/v1/graph/toxic-combinations", nil)
	if toxic.Code != http.StatusOK {
		t.Fatalf("expected toxic combinations 200, got %d: %s", toxic.Code, toxic.Body.String())
	}
	toxicBody := decodeJSON(t, toxic)
	if got := int(toxicBody["total_count"].(float64)); got < 1 {
		t.Fatalf("expected toxic combinations from store-backed handler, got %#v", toxicBody)
	}

	attack := do(t, s, http.MethodGet, "/api/v1/graph/attack-paths?limit=5", nil)
	if attack.Code != http.StatusOK {
		t.Fatalf("expected attack paths 200, got %d: %s", attack.Code, attack.Body.String())
	}
	attackBody := decodeJSON(t, attack)
	if got := int(attackBody["total_paths"].(float64)); got < 1 {
		t.Fatalf("expected attack paths from store-backed handler, got %#v", attackBody)
	}

	simFix := do(t, s, http.MethodGet, "/api/v1/graph/attack-paths/web-role/simulate-fix", nil)
	if simFix.Code != http.StatusOK {
		t.Fatalf("expected simulate-fix 200, got %d: %s", simFix.Code, simFix.Body.String())
	}
	if body := simFix.Body.String(); !strings.Contains(body, "blocked_paths") {
		t.Fatalf("expected simulation output, got %q", body)
	}

	choke := do(t, s, http.MethodGet, "/api/v1/graph/chokepoints", nil)
	if choke.Code != http.StatusOK {
		t.Fatalf("expected chokepoints 200, got %d: %s", choke.Code, choke.Body.String())
	}
	chokeBody := decodeJSON(t, choke)
	if got := int(chokeBody["total"].(float64)); got < 1 {
		t.Fatalf("expected chokepoints from store-backed handler, got %#v", chokeBody)
	}

	perm := do(t, s, http.MethodGet, "/api/v1/graph/effective-permissions/user:alice", nil)
	if perm.Code != http.StatusOK {
		t.Fatalf("expected effective permissions 200, got %d: %s", perm.Code, perm.Body.String())
	}
	permBody := decodeJSON(t, perm)
	if got := permBody["principal_id"]; got != "user:alice" {
		t.Fatalf("expected effective permissions principal, got %#v", got)
	}

	compare := do(t, s, http.MethodGet, "/api/v1/graph/compare-permissions?principal1=user:alice&principal2=user:bob", nil)
	if compare.Code != http.StatusOK {
		t.Fatalf("expected compare permissions 200, got %d: %s", compare.Code, compare.Body.String())
	}

	peer := do(t, s, http.MethodGet, "/api/v1/graph/peer-groups", nil)
	if peer.Code != http.StatusOK {
		t.Fatalf("expected peer groups 200, got %d: %s", peer.Code, peer.Body.String())
	}

	escalation := do(t, s, http.MethodGet, "/api/v1/graph/privilege-escalation/user:alice", nil)
	if escalation.Code != http.StatusOK {
		t.Fatalf("expected privilege escalation 200, got %d: %s", escalation.Code, escalation.Body.String())
	}
}
