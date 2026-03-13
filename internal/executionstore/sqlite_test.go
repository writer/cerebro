package executionstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreIsolatesNamespaces(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	if err := store.UpsertRun(context.Background(), RunEnvelope{
		Namespace:   "image_scan",
		RunID:       "run-1",
		Kind:        "ecr",
		Status:      "queued",
		Stage:       "queued",
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     []byte(`{"id":"run-1","kind":"image"}`),
	}); err != nil {
		t.Fatalf("UpsertRun image: %v", err)
	}
	if err := store.UpsertRun(context.Background(), RunEnvelope{
		Namespace:   "function_scan",
		RunID:       "run-1",
		Kind:        "aws",
		Status:      "running",
		Stage:       "analyze",
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     []byte(`{"id":"run-1","kind":"function"}`),
	}); err != nil {
		t.Fatalf("UpsertRun function: %v", err)
	}
	imageRuns, err := store.ListRuns(context.Background(), "image_scan", RunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns image: %v", err)
	}
	if len(imageRuns) != 1 || string(imageRuns[0].Payload) != `{"id":"run-1","kind":"image"}` {
		t.Fatalf("unexpected image runs: %#v", imageRuns)
	}
	functionRuns, err := store.ListRuns(context.Background(), "function_scan", RunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns function: %v", err)
	}
	if len(functionRuns) != 1 || string(functionRuns[0].Payload) != `{"id":"run-1","kind":"function"}` {
		t.Fatalf("unexpected function runs: %#v", functionRuns)
	}
}

func TestSQLiteStoreHandlesNullRunTimestamps(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC().Truncate(time.Second)
	if err := store.UpsertRun(context.Background(), RunEnvelope{
		Namespace:   "workload_scan",
		RunID:       "queued-run",
		Kind:        "aws",
		Status:      "queued",
		Stage:       "queued",
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     []byte(`{"id":"queued-run"}`),
	}); err != nil {
		t.Fatalf("UpsertRun queued: %v", err)
	}

	run, err := store.LoadRun(context.Background(), "workload_scan", "queued-run")
	if err != nil {
		t.Fatalf("LoadRun queued: %v", err)
	}
	if run == nil {
		t.Fatal("expected queued run")
	}
	if run.StartedAt != nil || run.CompletedAt != nil {
		t.Fatalf("expected nil queued timestamps, got %#v", run)
	}

	runs, err := store.ListRuns(context.Background(), "workload_scan", RunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns queued: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected one run, got %#v", runs)
	}
	if runs[0].StartedAt != nil || runs[0].CompletedAt != nil {
		t.Fatalf("expected nil queued timestamps in list, got %#v", runs[0])
	}
}

func TestSQLiteStoreAllocatesEventSequencesPerRun(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	first, err := store.SaveEvent(context.Background(), EventEnvelope{Namespace: "workload_scan", RunID: "run-a", Payload: []byte(`{"message":"first"}`)})
	if err != nil {
		t.Fatalf("SaveEvent first: %v", err)
	}
	second, err := store.SaveEvent(context.Background(), EventEnvelope{Namespace: "workload_scan", RunID: "run-a", Payload: []byte(`{"message":"second"}`)})
	if err != nil {
		t.Fatalf("SaveEvent second: %v", err)
	}
	other, err := store.SaveEvent(context.Background(), EventEnvelope{Namespace: "workload_scan", RunID: "run-b", Payload: []byte(`{"message":"other"}`)})
	if err != nil {
		t.Fatalf("SaveEvent other: %v", err)
	}
	if first.Sequence != 1 || second.Sequence != 2 || other.Sequence != 1 {
		t.Fatalf("unexpected sequences: first=%d second=%d other=%d", first.Sequence, second.Sequence, other.Sequence)
	}
}

func TestSQLiteStoreListsAcrossNamespaces(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	for _, env := range []RunEnvelope{
		{Namespace: NamespacePlatformReportRun, RunID: "report-1", Kind: "quality", Status: "succeeded", Stage: "succeeded", SubmittedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute), Payload: []byte(`{"kind":"report"}`)},
		{Namespace: NamespaceWorkloadScan, RunID: "scan-1", Kind: "aws", Status: "running", Stage: "analyze", SubmittedAt: now, UpdatedAt: now, Payload: []byte(`{"kind":"workload"}`)},
	} {
		if err := store.UpsertRun(context.Background(), env); err != nil {
			t.Fatalf("UpsertRun %s: %v", env.RunID, err)
		}
	}

	runs, err := store.ListAllRuns(context.Background(), RunListOptions{
		Namespaces:         []string{NamespacePlatformReportRun, NamespaceWorkloadScan},
		OrderBySubmittedAt: true,
	})
	if err != nil {
		t.Fatalf("ListAllRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %#v", runs)
	}
	if runs[0].RunID != "scan-1" || runs[1].RunID != "report-1" {
		t.Fatalf("unexpected ordering across namespaces: %#v", runs)
	}
}

func TestSQLiteStoreDeleteRunAndEvents(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	if err := store.UpsertRun(context.Background(), RunEnvelope{
		Namespace:   NamespacePlatformReportRun,
		RunID:       "run-delete",
		Kind:        "quality",
		Status:      "queued",
		Stage:       "queued",
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     []byte(`{"id":"run-delete"}`),
	}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}
	if _, err := store.SaveEvent(context.Background(), EventEnvelope{
		Namespace:  NamespacePlatformReportRun,
		RunID:      "run-delete",
		RecordedAt: now,
		Payload:    []byte(`{"message":"queued"}`),
	}); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}
	if err := store.DeleteEvents(context.Background(), NamespacePlatformReportRun, "run-delete"); err != nil {
		t.Fatalf("DeleteEvents: %v", err)
	}
	if err := store.DeleteRun(context.Background(), NamespacePlatformReportRun, "run-delete"); err != nil {
		t.Fatalf("DeleteRun: %v", err)
	}
	run, err := store.LoadRun(context.Background(), NamespacePlatformReportRun, "run-delete")
	if err != nil {
		t.Fatalf("LoadRun after delete: %v", err)
	}
	if run != nil {
		t.Fatalf("expected run to be deleted, got %#v", run)
	}
	events, err := store.LoadEvents(context.Background(), NamespacePlatformReportRun, "run-delete")
	if err != nil {
		t.Fatalf("LoadEvents after delete: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events after delete, got %#v", events)
	}
}

func TestSQLiteStoreReplaceRunWithEventsReplacesEventSetAtomically(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC().Truncate(time.Second)
	if err := store.ReplaceRunWithEvents(context.Background(), RunEnvelope{
		Namespace:   NamespacePlatformReportRun,
		RunID:       "run-replace",
		Kind:        "quality",
		Status:      "queued",
		Stage:       "queued",
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     []byte(`{"id":"run-replace","status":"queued"}`),
	}, []EventEnvelope{
		{Sequence: 1, RecordedAt: now, Payload: []byte(`{"type":"queued"}`)},
	}); err != nil {
		t.Fatalf("ReplaceRunWithEvents initial: %v", err)
	}

	later := now.Add(2 * time.Minute)
	if err := store.ReplaceRunWithEvents(context.Background(), RunEnvelope{
		Namespace:   NamespacePlatformReportRun,
		RunID:       "run-replace",
		Kind:        "quality",
		Status:      "succeeded",
		Stage:       "succeeded",
		SubmittedAt: now,
		StartedAt:   &now,
		CompletedAt: &later,
		UpdatedAt:   later,
		Payload:     []byte(`{"id":"run-replace","status":"succeeded"}`),
	}, []EventEnvelope{
		{Sequence: 1, RecordedAt: now, Payload: []byte(`{"type":"queued"}`)},
		{Sequence: 2, RecordedAt: later, Payload: []byte(`{"type":"completed"}`)},
	}); err != nil {
		t.Fatalf("ReplaceRunWithEvents updated: %v", err)
	}

	run, err := store.LoadRun(context.Background(), NamespacePlatformReportRun, "run-replace")
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil || run.Status != "succeeded" {
		t.Fatalf("expected updated run envelope, got %#v", run)
	}
	events, err := store.LoadEvents(context.Background(), NamespacePlatformReportRun, "run-replace")
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected replaced event set, got %#v", events)
	}
	if events[0].Sequence != 1 || string(events[0].Payload) != `{"type":"queued"}` {
		t.Fatalf("unexpected first event after replace: %#v", events[0])
	}
	if events[1].Sequence != 2 || string(events[1].Payload) != `{"type":"completed"}` {
		t.Fatalf("unexpected second event after replace: %#v", events[1])
	}
}
