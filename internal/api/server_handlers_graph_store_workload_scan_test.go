package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

func newStoreBackedGraphServerWithExecutionStore(t *testing.T, store graph.GraphStore) *Server {
	t.Helper()

	application := newTestApp(t)
	deps := newServerDependenciesFromApp(application)
	deps.SecurityGraph = nil
	deps.SecurityGraphBuilder = nil
	deps.graphRuntime = stubGraphRuntime{store: store}

	s := NewServerWithDependencies(deps)
	t.Cleanup(func() { s.Close() })
	return s
}

func buildGraphStorePlatformWorkloadScanTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
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
	return g
}

func seedGraphStorePlatformWorkloadScanRun(t *testing.T, s *Server) {
	t.Helper()

	if s.app == nil || s.app.ExecutionStore == nil {
		t.Fatal("expected shared execution store")
	}

	lastCompletedAt := time.Now().UTC().Add(-12 * time.Hour)
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
	workloadPayload, err := json.Marshal(workloadRun)
	if err != nil {
		t.Fatalf("marshal workload run: %v", err)
	}
	if err := s.app.ExecutionStore.UpsertRun(t.Context(), executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceWorkloadScan,
		RunID:       workloadRun.ID,
		Kind:        string(workloadRun.Provider),
		Status:      string(workloadRun.Status),
		Stage:       string(workloadRun.Stage),
		SubmittedAt: workloadRun.SubmittedAt,
		UpdatedAt:   workloadRun.UpdatedAt,
		CompletedAt: workloadRun.CompletedAt,
		Payload:     workloadPayload,
	}); err != nil {
		t.Fatalf("UpsertRun workload: %v", err)
	}
}

func TestPlatformWorkloadScanTargetsUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServerWithExecutionStore(t, buildGraphStorePlatformWorkloadScanTestGraph())
	seedGraphStorePlatformWorkloadScanRun(t, s)

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

func TestPlatformWorkloadScanTargetsReturnServiceUnavailableWhenStoreSnapshotMissing(t *testing.T) {
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: buildGraphStorePlatformWorkloadScanTestGraph()})

	resp := do(t, s, http.MethodGet, "/api/v1/platform/workload-scan/targets", nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", resp.Code, resp.Body.String())
	}
}
