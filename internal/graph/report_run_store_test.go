package graph

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReportRunStoreRoundTrip(t *testing.T) {
	now := time.Date(2026, 3, 10, 0, 15, 0, 0, time.UTC)
	definition := ReportDefinition{
		ID:           "quality",
		ResultSchema: "graph.GraphQualityReport",
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"maturity_score"}},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
	}
	result := map[string]any{
		"summary": map[string]any{
			"maturity_score": 93.5,
			"nodes":          7,
		},
		"recommendations": []any{
			"normalize metadata",
			"close claim conflicts",
		},
	}
	snapshot, err := BuildReportSnapshot("report_run:test", definition, result, true, now)
	if err != nil {
		t.Fatalf("build report snapshot: %v", err)
	}
	run := &ReportRun{
		ID:            "report_run:test",
		ReportID:      definition.ID,
		Status:        ReportRunStatusSucceeded,
		ExecutionMode: ReportExecutionModeSync,
		SubmittedAt:   now.Add(-2 * time.Minute),
		StartedAt:     timePtr(now.Add(-90 * time.Second)),
		CompletedAt:   timePtr(now),
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:test",
		CacheKey:      "cache-key",
		Sections:      BuildReportSectionResults(definition, result),
		Snapshot:      snapshot,
		Result:        result,
	}

	stateDir := t.TempDir()
	store := NewReportRunStore(filepath.Join(stateDir, "state.json"), filepath.Join(stateDir, "snapshots"))
	if err := store.SaveAll(map[string]*ReportRun{run.ID: run}); err != nil {
		t.Fatalf("save report runs: %v", err)
	}

	loadedRuns, err := store.Load()
	if err != nil {
		t.Fatalf("load report runs: %v", err)
	}
	loaded, ok := loadedRuns[run.ID]
	if !ok {
		t.Fatalf("expected restored run %q", run.ID)
	}
	if loaded.Snapshot == nil {
		t.Fatal("expected restored snapshot metadata")
	}
	if loaded.Snapshot.StoragePath == "" {
		t.Fatal("expected restored snapshot storage path")
	}
	if loaded.Result == nil {
		t.Fatal("expected restored materialized result")
	}
	summary, ok := loaded.Result["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", loaded.Result["summary"])
	}
	if got, ok := summary["maturity_score"].(float64); !ok || got != 93.5 {
		t.Fatalf("expected restored maturity_score=93.5, got %#v", summary["maturity_score"])
	}
	if loaded.Sections[0].EnvelopeKind != "summary" {
		t.Fatalf("expected summary envelope kind, got %+v", loaded.Sections[0])
	}
	if len(loaded.Sections[0].FieldKeys) != 2 {
		t.Fatalf("expected field key capture, got %+v", loaded.Sections[0])
	}
}

func timePtr(value time.Time) *time.Time {
	return &value
}
