package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestSecurityAttackPathJobAndPlatformJobStatus(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin Role", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "internet-role", Source: "internet", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

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
		t.Fatalf("expected at least one attack path, got %#v", result["total_paths"])
	}
}
