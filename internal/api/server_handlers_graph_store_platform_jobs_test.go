package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStorePlatformJobsTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin Role", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "internet-role", Source: "internet", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	meta := g.Metadata()
	meta.BuiltAt = time.Date(2026, 3, 18, 17, 30, 0, 0, time.UTC)
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	meta.Providers = []string{"aws"}
	meta.Accounts = []string{"123456789012"}
	g.SetMetadata(meta)
	return g
}

func TestCurrentPlatformGraphSnapshotUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStorePlatformJobsTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/current", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected current snapshot 200, got %d: %s", resp.Code, resp.Body.String())
	}

	body := decodeJSON(t, resp)
	if got := int(body["node_count"].(float64)); got != 3 {
		t.Fatalf("expected node_count=3 from store-backed current snapshot, got %#v", body)
	}
	if got := int(body["edge_count"].(float64)); got != 2 {
		t.Fatalf("expected edge_count=2 from store-backed current snapshot, got %#v", body)
	}
	if got, _ := body["current"].(bool); !got {
		t.Fatalf("expected current snapshot flag, got %#v", body["current"])
	}
}

func TestCurrentPlatformGraphSnapshotReturnsServiceUnavailableWhenStoreSnapshotMissing(t *testing.T) {
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: buildGraphStorePlatformJobsTestGraph()})

	resp := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/current", nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected current snapshot 503, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestSecurityAttackPathJobUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStorePlatformJobsTestGraph())

	create := do(t, s, http.MethodPost, "/api/v1/security/analyses/attack-paths/jobs", map[string]any{
		"max_depth": 6,
		"limit":     10,
	})
	if create.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for attack-path job creation, got %d: %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	jobID, _ := created["id"].(string)
	if jobID == "" {
		t.Fatalf("expected job id, got %#v", created)
	}

	var latest map[string]any
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := do(t, s, http.MethodGet, "/api/v1/platform/jobs/"+jobID, nil)
		if status.Code != http.StatusOK {
			t.Fatalf("expected 200 for platform job status, got %d: %s", status.Code, status.Body.String())
		}
		latest = decodeJSON(t, status)
		if latest["status"] == "succeeded" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if latest == nil || latest["status"] != "succeeded" {
		t.Fatalf("expected succeeded job, got %#v", latest)
	}
	result, ok := latest["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result payload, got %#v", latest["result"])
	}
	if count, ok := result["total_paths"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one attack path from store-backed job, got %#v", result["total_paths"])
	}
}
