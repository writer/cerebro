package autonomous

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteRunStoreRoundTrip(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "autonomous.db"))
	if err != nil {
		t.Fatalf("NewSQLiteRunStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	run := &RunRecord{
		ID:           "run-1",
		WorkflowID:   WorkflowCredentialExposureResponse,
		WorkflowName: "Credential Exposure Response",
		Status:       RunStatusAwaitingApproval,
		Stage:        RunStageAwaitingApproval,
		RequestedBy:  "alice",
		SubmittedAt:  now,
		UpdatedAt:    now,
		Provider:     "aws",
	}

	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}
	event, err := store.AppendEvent(context.Background(), run.ID, RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "awaiting approval",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	if event.Sequence == 0 {
		t.Fatal("expected persisted event sequence")
	}

	loadedRun, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	if loadedRun == nil || loadedRun.ID != run.ID || loadedRun.Provider != "aws" {
		t.Fatalf("unexpected loaded run: %#v", loadedRun)
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].Message != "awaiting approval" {
		t.Fatalf("unexpected loaded events: %#v", events)
	}
}
