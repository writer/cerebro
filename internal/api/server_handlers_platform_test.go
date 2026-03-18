package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
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

func TestPlatformExecutionsListsSharedExecutionStoreRuns(t *testing.T) {
	s := newTestServer(t)

	reportRun := &reports.ReportRun{
		ID:            "report_run:test-execution-list",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusSucceeded,
		ExecutionMode: reports.ReportExecutionModeSync,
		SubmittedAt:   time.Date(2026, 3, 12, 9, 0, 0, 0, time.UTC),
		RequestedBy:   "alice",
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:test-execution-list",
	}
	reportStartedAt := time.Date(2026, 3, 12, 9, 0, 5, 0, time.UTC)
	reportCompletedAt := time.Date(2026, 3, 12, 9, 0, 10, 0, time.UTC)
	reportRun.StartedAt = &reportStartedAt
	reportRun.CompletedAt = &reportCompletedAt
	if err := s.storePlatformReportRun(reportRun); err != nil {
		t.Fatalf("storePlatformReportRun: %v", err)
	}

	sharedStore := s.app.ExecutionStore
	if sharedStore == nil {
		t.Fatal("expected shared execution store")
	}

	workloadRun := workloadscan.RunRecord{
		ID:          "workload_scan:test-execution-list",
		Provider:    workloadscan.ProviderAWS,
		Status:      workloadscan.RunStatusRunning,
		Stage:       workloadscan.RunStageAnalyze,
		Target:      workloadscan.VMTarget{Provider: workloadscan.ProviderAWS, Region: "us-east-1", InstanceID: "i-123"},
		RequestedBy: "bob",
		SubmittedAt: time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 12, 10, 0, 30, 0, time.UTC),
	}
	workloadPayload, err := json.Marshal(workloadRun)
	if err != nil {
		t.Fatalf("marshal workload run: %v", err)
	}
	if err := sharedStore.UpsertRun(t.Context(), executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceWorkloadScan,
		RunID:       workloadRun.ID,
		Kind:        string(workloadRun.Provider),
		Status:      string(workloadRun.Status),
		Stage:       string(workloadRun.Stage),
		SubmittedAt: workloadRun.SubmittedAt,
		UpdatedAt:   workloadRun.UpdatedAt,
		Payload:     workloadPayload,
	}); err != nil {
		t.Fatalf("UpsertRun workload: %v", err)
	}

	resp := do(t, s, http.MethodGet, "/api/v1/platform/executions?namespace=report_run,workload_scan&order=submitted", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got := int(body["count"].(float64)); got != 2 {
		t.Fatalf("expected 2 executions, got %#v", body)
	}
	executions, ok := body["executions"].([]any)
	if !ok || len(executions) != 2 {
		t.Fatalf("expected executions array, got %#v", body["executions"])
	}
	first := executions[0].(map[string]any)
	if first["namespace"] != executionstore.NamespaceWorkloadScan {
		t.Fatalf("expected workload scan first when ordered by submitted time, got %#v", first)
	}
	second := executions[1].(map[string]any)
	if second["namespace"] != executionstore.NamespacePlatformReportRun {
		t.Fatalf("expected report run second, got %#v", second)
	}

	filtered := do(t, s, http.MethodGet, "/api/v1/platform/executions?namespace=report_run&report_id=quality", nil)
	if filtered.Code != http.StatusOK {
		t.Fatalf("expected 200 for report-only listing, got %d: %s", filtered.Code, filtered.Body.String())
	}
	filteredBody := decodeJSON(t, filtered)
	if got := int(filteredBody["count"].(float64)); got != 1 {
		t.Fatalf("expected one filtered execution, got %#v", filteredBody)
	}
}

func TestPlatformGraphSnapshotRecordsIncludePersistedReportRuns(t *testing.T) {
	s := newTestServer(t)
	builtAt := time.Date(2026, 3, 12, 11, 0, 0, 0, time.UTC)
	s.app.SecurityGraph.SetMetadata(graph.Metadata{
		BuiltAt:   builtAt,
		NodeCount: 1,
		EdgeCount: 0,
	})

	run := &reports.ReportRun{
		ID:            "report_run:graph-snapshot-persisted",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusSucceeded,
		ExecutionMode: reports.ReportExecutionModeSync,
		SubmittedAt:   builtAt.Add(5 * time.Minute),
		RequestedBy:   "alice",
		Lineage: reports.ReportLineage{
			GraphSnapshotID:         "graph_snapshot:historic",
			GraphSchemaVersion:      3,
			OntologyContractVersion: "2026-03-12",
			GraphBuiltAt:            &builtAt,
		},
	}
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun: %v", err)
	}

	s.platformReportRunMu.Lock()
	s.platformReportRuns = map[string]*reports.ReportRun{}
	s.platformReportRunMu.Unlock()

	records := s.platformGraphSnapshotRecords()
	record, ok := records["graph_snapshot:historic"]
	if !ok || record == nil {
		t.Fatalf("expected persisted report-run lineage snapshot to be present, got %#v", records)
	}
	if got := record.ObservedRunCount; got < 1 {
		t.Fatalf("expected observed run count from persisted report run, got %#v", got)
	}
	if len(record.ObservedReportIDs) == 0 || record.ObservedReportIDs[0] != "quality" {
		t.Fatalf("expected observed report id to include quality, got %#v", record.ObservedReportIDs)
	}
}
