package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

type countOnlyPlatformReportMetadataStore struct {
	graph.GraphStore
	nodeCount int
	edgeCount int
}

func (s countOnlyPlatformReportMetadataStore) CountNodes(context.Context) (int, error) {
	return s.nodeCount, nil
}

func (s countOnlyPlatformReportMetadataStore) CountEdges(context.Context) (int, error) {
	return s.edgeCount, nil
}

func buildGraphStorePlatformReportTestGraph() *graph.Graph {
	g := graph.New()
	now := time.Date(2026, 3, 18, 10, 30, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "claim:payments-owner",
		Kind: graph.NodeKindClaim,
		Name: "Payments owner",
		Properties: map[string]any{
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:       now.Add(10 * time.Minute),
		NodeCount:     2,
		EdgeCount:     0,
		Providers:     []string{"test"},
		BuildDuration: 2 * time.Second,
	})
	g.BuildIndex()
	return g
}

func TestPlatformIntelligenceReportRunSyncUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServerWithExecutionStore(t, buildGraphStorePlatformReportTestGraph())

	resp := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	lineage, ok := body["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("expected lineage payload, got %#v", body["lineage"])
	}
	if got := lineage["graph_snapshot_id"]; got == "" {
		t.Fatalf("expected graph_snapshot_id from graph store lineage, got %#v", got)
	}
}

func TestCurrentPlatformReportLineageUsesStoreMetadataWhenSnapshotMaterializationUnavailable(t *testing.T) {
	store := &snapshotFailingMetadataStore{GraphStore: buildGraphStorePlatformReportTestGraph()}
	s := newStoreBackedGraphServerWithExecutionStore(t, store)

	lineage := s.currentPlatformReportLineage(context.Background(), reports.ReportDefinition{ID: "quality", Version: "2.1.0"})
	if lineage.GraphSnapshotID == "" {
		t.Fatalf("expected graph_snapshot_id from store metadata lineage, got %#v", lineage)
	}
	if lineage.GraphBuiltAt == nil || lineage.GraphBuiltAt.IsZero() {
		t.Fatalf("expected graph built_at from store metadata lineage, got %#v", lineage.GraphBuiltAt)
	}
	if store.snapshotCalls != 0 {
		t.Fatalf("expected currentPlatformReportLineage to avoid snapshot fallback, got %d snapshot calls", store.snapshotCalls)
	}
	if store.metadataCalls == 0 {
		t.Fatal("expected currentPlatformReportLineage to use store metadata")
	}
}

func TestCurrentPlatformReportLineageSkipsSnapshotIDForCountOnlyMetadata(t *testing.T) {
	store := countOnlyPlatformReportMetadataStore{
		GraphStore: buildGraphStorePlatformReportTestGraph(),
		nodeCount:  2,
		edgeCount:  0,
	}
	s := newStoreBackedGraphServerWithExecutionStore(t, store)

	lineage := s.currentPlatformReportLineage(context.Background(), reports.ReportDefinition{ID: "quality", Version: "2.1.0"})
	if lineage.GraphSnapshotID != "" {
		t.Fatalf("expected no graph_snapshot_id for count-only metadata, got %#v", lineage)
	}
	if lineage.GraphBuiltAt != nil {
		t.Fatalf("expected no graph_built_at for count-only metadata, got %#v", lineage.GraphBuiltAt)
	}
}

func TestPlatformIntelligenceReportRunRetrySyncUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServerWithExecutionStore(t, buildGraphStorePlatformReportTestGraph())

	original := s.platformReportHandlers["quality"]
	var calls atomic.Int64
	s.platformReportHandlers["quality"] = func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			s.error(w, http.StatusServiceUnavailable, "temporary upstream failure")
			return
		}
		original(w, r)
	}

	create := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if create.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for failed first run, got %d: %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	statusURL, _ := created["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", created["status_url"])
	}

	retry := do(t, s, http.MethodPost, statusURL+":retry", map[string]any{
		"reason": "retry after transient failure",
	})
	if retry.Code != http.StatusOK {
		t.Fatalf("expected 200 for sync retry, got %d: %s", retry.Code, retry.Body.String())
	}
	retried := decodeJSON(t, retry)
	if got := retried["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected retry to succeed, got %#v", got)
	}
	lineage, ok := retried["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("expected lineage payload, got %#v", retried["lineage"])
	}
	if got := lineage["graph_snapshot_id"]; got == "" {
		t.Fatalf("expected graph_snapshot_id on retried run, got %#v", got)
	}
}

func TestBuildPlatformReportArtifactsUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServerWithExecutionStore(t, buildGraphStorePlatformReportTestGraph())

	run := &reports.ReportRun{
		ID:          "report_run:test",
		ReportID:    "quality",
		CacheStatus: reports.ReportCacheStatusMiss,
	}
	definition := reports.ReportDefinition{
		ID:    "test",
		Title: "Test",
		Sections: []reports.ReportSection{
			{Key: "claims", Title: "Claims", Kind: "list"},
		},
	}

	sections, _, _, err := s.buildPlatformReportArtifacts(context.Background(), run, run.ID, definition, map[string]any{
		"claims": []any{"claim:payments-owner"},
	}, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("buildPlatformReportArtifacts() failed: %v", err)
	}
	if len(sections) != 1 {
		t.Fatalf("expected one section, got %d", len(sections))
	}
	lineage := sections[0].Lineage
	if lineage == nil {
		t.Fatal("expected section lineage from graph store-backed graph view")
		return
	}
	if lineage.ClaimCount != 1 || lineage.ReferencedNodeCount != 1 {
		t.Fatalf("expected one referenced claim from store-backed graph view, got %#v", lineage)
	}
}
