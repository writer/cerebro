package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

func TestReportRunStoreRoundTrip(t *testing.T) {
	now := time.Date(2026, 3, 10, 0, 15, 0, 0, time.UTC)
	definition := ReportDefinition{
		ID:           "quality",
		ResultSchema: "reports.GraphQualityReport",
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
		Sections:      BuildReportSectionResults(definition, result, nil),
		Snapshot:      snapshot,
		Result:        result,
		Lineage: ReportLineage{
			GraphSnapshotID:         "graph_snapshot:test",
			GraphBuiltAt:            timePtr(now.Add(-1 * time.Hour)),
			GraphSchemaVersion:      SchemaVersion(),
			OntologyContractVersion: GraphOntologyContractVersion,
			ReportDefinitionVersion: "1.0.0",
		},
		Storage: BuildReportStoragePolicy(true, false),
	}
	run.Attempts = []ReportRunAttempt{
		NewReportRunAttempt(run.ID, 1, ReportRunStatusSucceeded, "api.request", "platform.inline", "host-a", "alice", "", run.SubmittedAt),
	}
	run.LatestAttemptID = run.Attempts[0].ID
	run.AttemptCount = 1
	AppendReportRunEvent(run, "platform.report_run.queued", ReportRunStatusQueued, "api.request", "alice", run.SubmittedAt, map[string]any{"report_id": run.ReportID})
	AppendReportRunEvent(run, "platform.report_run.completed", ReportRunStatusSucceeded, "api.request", "alice", now, map[string]any{"report_id": run.ReportID})
	run.EventCount = len(run.Events)
	run.Snapshot.Lineage = CloneReportLineage(run.Lineage)
	run.Snapshot.Storage = CloneReportStoragePolicy(run.Storage)

	stateDir := t.TempDir()
	store, err := NewReportRunStore(filepath.Join(stateDir, "executions.db"), filepath.Join(stateDir, "snapshots"), filepath.Join(stateDir, "legacy-state.json"))
	if err != nil {
		t.Fatalf("NewReportRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()
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
	if loaded.Lineage.GraphSnapshotID != "graph_snapshot:test" {
		t.Fatalf("expected restored lineage graph snapshot id, got %+v", loaded.Lineage)
	}
	if loaded.Storage.StorageClass != "local_durable" {
		t.Fatalf("expected restored storage class local_durable, got %+v", loaded.Storage)
	}
	if len(loaded.Attempts) != 1 || loaded.Attempts[0].ExecutionSurface != "platform.inline" {
		t.Fatalf("expected restored attempts, got %+v", loaded.Attempts)
	}
	if len(loaded.Events) != 2 || loaded.Events[1].Type != "platform.report_run.completed" {
		t.Fatalf("expected restored events, got %+v", loaded.Events)
	}
	if loaded.Snapshot.Lineage.GraphSnapshotID != "graph_snapshot:test" {
		t.Fatalf("expected restored snapshot lineage, got %+v", loaded.Snapshot.Lineage)
	}
	if loaded.Snapshot.Storage.StorageClass != "local_durable" {
		t.Fatalf("expected restored snapshot storage, got %+v", loaded.Snapshot.Storage)
	}

	executionStore, err := executionstore.NewSQLiteStore(store.StateFile())
	if err != nil {
		t.Fatalf("open shared execution store: %v", err)
	}
	defer func() { _ = executionStore.Close() }()
	envs, err := executionStore.ListRuns(t.Context(), executionstore.NamespacePlatformReportRun, executionstore.RunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns report namespace: %v", err)
	}
	if len(envs) != 1 || envs[0].RunID != run.ID {
		t.Fatalf("expected persisted report run in shared execution store, got %#v", envs)
	}
}

func TestReportRunStoreSaveRunReplacesPersistedEvents(t *testing.T) {
	now := time.Date(2026, 3, 10, 1, 0, 0, 0, time.UTC)
	run := &ReportRun{
		ID:            "report_run:replace-events",
		ReportID:      "quality",
		Status:        ReportRunStatusQueued,
		ExecutionMode: ReportExecutionModeAsync,
		SubmittedAt:   now,
	}
	AppendReportRunEvent(run, "platform.report_run.queued", ReportRunStatusQueued, "api.request", "alice", now, nil)
	run.EventCount = len(run.Events)

	stateDir := t.TempDir()
	store, err := NewReportRunStore(filepath.Join(stateDir, "executions.db"), filepath.Join(stateDir, "snapshots"), filepath.Join(stateDir, "legacy-state.json"))
	if err != nil {
		t.Fatalf("NewReportRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveRun(run); err != nil {
		t.Fatalf("SaveRun initial: %v", err)
	}

	run.Status = ReportRunStatusSucceeded
	run.CompletedAt = timePtr(now.Add(2 * time.Minute))
	AppendReportRunEvent(run, "platform.report_run.completed", ReportRunStatusSucceeded, "api.request", "alice", now.Add(2*time.Minute), nil)
	run.EventCount = len(run.Events)

	if err := store.SaveRun(run); err != nil {
		t.Fatalf("SaveRun updated: %v", err)
	}

	loaded, err := store.LoadRun(run.ID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected saved run")
	}
	if loaded.Status != ReportRunStatusSucceeded {
		t.Fatalf("expected updated status, got %+v", loaded)
	}
	if len(loaded.Events) != 2 {
		t.Fatalf("expected replaced persisted events, got %+v", loaded.Events)
	}
	if loaded.Events[0].Type != "platform.report_run.queued" || loaded.Events[1].Type != "platform.report_run.completed" {
		t.Fatalf("unexpected persisted event ordering: %+v", loaded.Events)
	}
}

func TestReportRunStoreWithSharedExecutionStoreDoesNotOwnClose(t *testing.T) {
	stateDir := t.TempDir()
	executionStore, err := executionstore.NewSQLiteStore(filepath.Join(stateDir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = executionStore.Close() }()

	store := NewReportRunStoreWithExecutionStore(executionStore, filepath.Join(stateDir, "executions.db"), filepath.Join(stateDir, "snapshots"), filepath.Join(stateDir, "legacy-state.json"))
	if err := store.Close(); err != nil {
		t.Fatalf("ReportRunStore.Close(): %v", err)
	}

	if err := executionStore.UpsertRun(t.Context(), executionstore.RunEnvelope{
		Namespace:   executionstore.NamespacePlatformReportRun,
		RunID:       "report_run:shared-close",
		Kind:        "quality",
		Status:      string(ReportRunStatusQueued),
		Stage:       string(ReportRunStatusQueued),
		SubmittedAt: time.Date(2026, 3, 12, 9, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 12, 9, 0, 0, 0, time.UTC),
		Payload:     []byte(`{"run":{"id":"report_run:shared-close","report_id":"quality","status":"queued","submitted_at":"2026-03-12T09:00:00Z"}}`),
	}); err != nil {
		t.Fatalf("UpsertRun after borrowed store close: %v", err)
	}
}

func TestReportRunStoreLoadImportsMissingLegacyRunsIntoPartiallyMigratedStore(t *testing.T) {
	stateDir := t.TempDir()
	store, err := NewReportRunStore(filepath.Join(stateDir, "executions.db"), filepath.Join(stateDir, "snapshots"), filepath.Join(stateDir, "legacy-state.json"))
	if err != nil {
		t.Fatalf("NewReportRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	existing := &ReportRun{
		ID:            "report_run:migrated",
		ReportID:      "quality",
		Status:        ReportRunStatusSucceeded,
		ExecutionMode: ReportExecutionModeSync,
		SubmittedAt:   time.Date(2026, 3, 12, 8, 0, 0, 0, time.UTC),
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:migrated",
	}
	if err := store.SaveRun(existing); err != nil {
		t.Fatalf("SaveRun existing: %v", err)
	}

	legacyOnly := &ReportRun{
		ID:            "report_run:legacy-only",
		ReportID:      "drift",
		Status:        ReportRunStatusQueued,
		ExecutionMode: ReportExecutionModeAsync,
		SubmittedAt:   time.Date(2026, 3, 12, 7, 0, 0, 0, time.UTC),
		StatusURL:     "/api/v1/platform/intelligence/reports/drift/runs/report_run:legacy-only",
	}
	legacyDuplicate := &ReportRun{
		ID:            existing.ID,
		ReportID:      existing.ReportID,
		Status:        ReportRunStatusQueued,
		ExecutionMode: ReportExecutionModeAsync,
		SubmittedAt:   existing.SubmittedAt.Add(-1 * time.Hour),
		StatusURL:     existing.StatusURL,
	}
	legacyState := persistedReportRunStore{
		Version: reportRunStoreVersion,
		SavedAt: time.Now().UTC(),
		Runs: []persistedReportRunRecord{
			{Run: legacyDuplicate},
			{Run: legacyOnly},
		},
	}
	payload, err := json.Marshal(legacyState)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := os.WriteFile(store.LegacyStateFile(), payload, 0o600); err != nil {
		t.Fatalf("WriteFile legacy state: %v", err)
	}

	loadedRuns, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loadedRuns) != 2 {
		t.Fatalf("expected merged run set of size 2, got %#v", loadedRuns)
	}
	if loadedRuns[existing.ID].Status != ReportRunStatusSucceeded {
		t.Fatalf("expected migrated run to keep v2 status, got %+v", loadedRuns[existing.ID])
	}
	if _, ok := loadedRuns[legacyOnly.ID]; !ok {
		t.Fatalf("expected legacy-only run to be imported, got %#v", loadedRuns)
	}

	executionStore, err := executionstore.NewSQLiteStore(store.StateFile())
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	defer func() { _ = executionStore.Close() }()
	envs, err := executionStore.ListRuns(t.Context(), executionstore.NamespacePlatformReportRun, executionstore.RunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 persisted report runs after legacy import, got %#v", envs)
	}
}

func timePtr(value time.Time) *time.Time {
	return &value
}
