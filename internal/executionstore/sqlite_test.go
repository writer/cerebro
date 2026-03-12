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
