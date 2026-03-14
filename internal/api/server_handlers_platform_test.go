package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
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

func TestPlatformWorkloadScanTargetsPrioritizeGraphSignals(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet", Provider: "external"})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-public",
		Kind:     graph.NodeKindInstance,
		Name:     "i-public",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id":      "i-public",
			"public_ip":        "54.1.2.3",
			"criticality":      "high",
			"compliance_scope": "pci",
		},
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-fresh",
		Kind:     graph.NodeKindInstance,
		Name:     "i-fresh",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id": "i-fresh",
		},
	})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin Role", Provider: "aws", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Provider: "aws", Risk: graph.RiskCritical, Properties: map[string]any{"data_classification": "restricted"}})
	g.AddEdge(&graph.Edge{ID: "internet->public", Source: "internet", Target: "arn:aws:ec2:us-east-1:123456789012:instance/i-public", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "public->role", Source: "arn:aws:ec2:us-east-1:123456789012:instance/i-public", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role->db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	lastCompletedAt := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Minute)
	workloadRun := workloadscan.RunRecord{
		ID:          "workload_scan:fresh",
		Provider:    workloadscan.ProviderAWS,
		Status:      workloadscan.RunStatusSucceeded,
		Stage:       workloadscan.RunStageCompleted,
		Target:      workloadscan.VMTarget{Provider: workloadscan.ProviderAWS, Region: "us-east-1", InstanceID: "i-fresh"},
		SubmittedAt: lastCompletedAt.Add(-30 * time.Minute),
		UpdatedAt:   lastCompletedAt,
		CompletedAt: &lastCompletedAt,
	}
	store, err := workloadscan.NewSQLiteRunStore(s.app.Config.WorkloadScanStateFile)
	if err != nil {
		t.Fatalf("NewSQLiteRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.SaveRun(t.Context(), &workloadRun); err != nil {
		t.Fatalf("SaveRun workload: %v", err)
	}

	resp := do(t, s, http.MethodGet, "/api/v1/platform/workload-scan/targets?include_deferred=true", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	targets, ok := body["targets"].([]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected two targets, got %#v", body["targets"])
	}
	first := targets[0].(map[string]any)
	if first["provider"] != "aws" {
		t.Fatalf("expected aws target, got %#v", first)
	}
	firstTarget := first["target"].(map[string]any)
	if firstTarget["instance_id"] != "i-public" {
		t.Fatalf("expected public target first, got %#v", firstTarget)
	}
	firstAssessment := first["assessment"].(map[string]any)
	if firstAssessment["priority"] != "critical" {
		t.Fatalf("expected critical first target, got %#v", firstAssessment)
	}

	secondAssessment := targets[1].(map[string]any)["assessment"].(map[string]any)
	if eligible, ok := secondAssessment["eligible"].(bool); !ok || eligible {
		t.Fatalf("expected fresh target to be deferred, got %#v", secondAssessment)
	}

	filtered := do(t, s, http.MethodGet, "/api/v1/platform/workload-scan/targets", nil)
	if filtered.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", filtered.Code, filtered.Body.String())
	}
	filteredBody := decodeJSON(t, filtered)
	filteredTargets, ok := filteredBody["targets"].([]any)
	if !ok || len(filteredTargets) != 1 {
		t.Fatalf("expected only actionable target, got %#v", filteredBody["targets"])
	}
}

func TestPlatformWorkloadScanTargetsRejectInvalidProvider(t *testing.T) {
	s := newTestServer(t)

	resp := do(t, s, http.MethodGet, "/api/v1/platform/workload-scan/targets?provider=digitalocean", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if body["error"] != "provider must be one of aws, gcp, azure" {
		t.Fatalf("unexpected error body: %#v", body)
	}
}
