package runtime

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/executionstore"
)

type casConflictExecutionStore struct {
	env          executionstore.RunEnvelope
	events       []executionstore.EventEnvelope
	compareCalls int
}

func (s *casConflictExecutionStore) Close() error { return nil }

func (s *casConflictExecutionStore) UpsertRun(_ context.Context, env executionstore.RunEnvelope) error {
	s.env = env
	return nil
}

func (s *casConflictExecutionStore) CompareAndSwapRun(_ context.Context, _ executionstore.RunEnvelope, next executionstore.RunEnvelope) (bool, error) {
	s.compareCalls++
	if s.compareCalls == 1 {
		return false, nil
	}
	s.env = next
	return true, nil
}

func (s *casConflictExecutionStore) ReplaceRunWithEvents(_ context.Context, env executionstore.RunEnvelope, events []executionstore.EventEnvelope) error {
	s.env = env
	s.events = append([]executionstore.EventEnvelope(nil), events...)
	return nil
}

func (s *casConflictExecutionStore) LoadRun(_ context.Context, _, _ string) (*executionstore.RunEnvelope, error) {
	if s.env.RunID == "" {
		return nil, nil
	}
	cloned := s.env
	cloned.Payload = append([]byte(nil), s.env.Payload...)
	return &cloned, nil
}

func (s *casConflictExecutionStore) ListRuns(context.Context, string, executionstore.RunListOptions) ([]executionstore.RunEnvelope, error) {
	return nil, nil
}

func (s *casConflictExecutionStore) ListAllRuns(context.Context, executionstore.RunListOptions) ([]executionstore.RunEnvelope, error) {
	return nil, nil
}

func (s *casConflictExecutionStore) DeleteRun(context.Context, string, string) error { return nil }

func (s *casConflictExecutionStore) DeleteEvents(context.Context, string, string) error { return nil }

func (s *casConflictExecutionStore) SaveEvent(_ context.Context, env executionstore.EventEnvelope) (executionstore.EventEnvelope, error) {
	if env.Sequence <= 0 {
		env.Sequence = int64(len(s.events) + 1)
	}
	s.events = append(s.events, env)
	return env, nil
}

func (s *casConflictExecutionStore) LoadEvents(_ context.Context, _, _ string) ([]executionstore.EventEnvelope, error) {
	return append([]executionstore.EventEnvelope(nil), s.events...), nil
}

func (s *casConflictExecutionStore) LookupProcessedEvent(context.Context, string, string, time.Time) (*executionstore.ProcessedEventRecord, error) {
	return nil, nil
}

func (s *casConflictExecutionStore) TouchProcessedEvent(context.Context, string, string, time.Time, time.Duration) error {
	return nil
}

func (s *casConflictExecutionStore) RememberProcessedEvent(context.Context, executionstore.ProcessedEventRecord, int) error {
	return nil
}

func (s *casConflictExecutionStore) DeleteProcessedEvent(context.Context, string, string) error {
	return nil
}

func TestSQLiteIngestStoreSaveLoadRunAndEvents(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	startedAt := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	run := &IngestRunRecord{
		ID:               "run-1",
		Source:           "kubernetes_audit",
		Status:           IngestRunStatusRunning,
		Stage:            "normalize",
		SubmittedAt:      startedAt,
		StartedAt:        &startedAt,
		UpdatedAt:        startedAt,
		ObservationCount: 12,
		FindingCount:     2,
		Metadata: map[string]string{
			"cluster": "prod-west",
		},
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded run")
	}
	if loaded.Source != "kubernetes_audit" {
		t.Fatalf("source = %q, want %q", loaded.Source, "kubernetes_audit")
	}
	if loaded.ObservationCount != 12 {
		t.Fatalf("observation_count = %d, want 12", loaded.ObservationCount)
	}

	first, err := store.AppendEvent(context.Background(), run.ID, IngestEvent{
		Type:       "normalized",
		RecordedAt: startedAt.Add(time.Second),
		Data: map[string]any{
			"observations": 12,
		},
	})
	if err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if first.Sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", first.Sequence)
	}

	second, err := store.AppendEvent(context.Background(), run.ID, IngestEvent{
		Type:       "detected",
		RecordedAt: startedAt.Add(2 * time.Second),
		Data: map[string]any{
			"findings": 2,
		},
	})
	if err != nil {
		t.Fatalf("AppendEvent second: %v", err)
	}
	if second.Sequence != 2 {
		t.Fatalf("second sequence = %d, want 2", second.Sequence)
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[1].Type != "detected" {
		t.Fatalf("second event type = %q, want %q", events[1].Type, "detected")
	}
}

func TestSQLiteIngestStoreCheckpointPersistence(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	run := &IngestRunRecord{
		ID:          "run-1",
		Source:      "tetragon",
		Status:      IngestRunStatusRunning,
		Stage:       "ingest",
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	checkpoint, err := store.SaveCheckpoint(context.Background(), run.ID, IngestCheckpoint{
		Cursor:     "cursor-42",
		RecordedAt: now.Add(time.Minute),
		Metadata: map[string]string{
			"stream": "default",
		},
	})
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if checkpoint.Cursor != "cursor-42" {
		t.Fatalf("cursor = %q, want %q", checkpoint.Cursor, "cursor-42")
	}

	loaded, err := store.LoadCheckpoint(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected checkpoint")
	}
	if loaded.Metadata["stream"] != "default" {
		t.Fatalf("stream metadata = %q, want %q", loaded.Metadata["stream"], "default")
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Type != "checkpoint_saved" {
		t.Fatalf("event type = %q, want %q", events[0].Type, "checkpoint_saved")
	}
}

func TestSQLiteIngestStoreListRunsActiveOnly(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	for _, run := range []*IngestRunRecord{
		{ID: "run-queued", Source: "kubernetes_audit", Status: IngestRunStatusQueued, Stage: "queued", SubmittedAt: now, UpdatedAt: now},
		{ID: "run-running", Source: "tetragon", Status: IngestRunStatusRunning, Stage: "normalize", SubmittedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute)},
		{ID: "run-completed", Source: "tetragon", Status: IngestRunStatusCompleted, Stage: "completed", SubmittedAt: now.Add(2 * time.Minute), UpdatedAt: now.Add(2 * time.Minute)},
	} {
		if err := store.SaveRun(context.Background(), run); err != nil {
			t.Fatalf("SaveRun(%s): %v", run.ID, err)
		}
	}

	active, err := store.ListRuns(context.Background(), IngestRunListOptions{
		ActiveOnly:         true,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("len(active) = %d, want 2", len(active))
	}
	if active[0].ID != "run-running" || active[1].ID != "run-queued" {
		t.Fatalf("active runs = %#v", active)
	}
}

func TestSQLiteIngestStoreSaveCheckpointRetriesCompareAndSwap(t *testing.T) {
	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	run := &IngestRunRecord{
		ID:          "run-cas",
		Source:      "tetragon",
		Status:      IngestRunStatusRunning,
		Stage:       "ingest",
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	env, err := runtimeIngestRunEnvelope(run)
	if err != nil {
		t.Fatalf("runtimeIngestRunEnvelope: %v", err)
	}

	fakeStore := &casConflictExecutionStore{env: env}
	store := NewSQLiteIngestStoreWithExecutionStore(fakeStore)

	checkpoint, err := store.SaveCheckpoint(context.Background(), run.ID, IngestCheckpoint{
		Cursor:     "cursor-99",
		RecordedAt: now.Add(time.Minute),
		Metadata: map[string]string{
			"stream": "audit",
		},
	})
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if fakeStore.compareCalls != 2 {
		t.Fatalf("compareCalls = %d, want 2", fakeStore.compareCalls)
	}

	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if loaded == nil || loaded.LastCheckpoint == nil {
		t.Fatalf("loaded checkpoint missing: %#v", loaded)
	}
	if loaded.LastCheckpoint.Cursor != "cursor-99" {
		t.Fatalf("cursor = %q, want cursor-99", loaded.LastCheckpoint.Cursor)
	}
	if checkpoint.Metadata["stream"] != "audit" {
		t.Fatalf("checkpoint metadata = %#v, want stream=audit", checkpoint.Metadata)
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Type != "checkpoint_saved" {
		t.Fatalf("event type = %q, want checkpoint_saved", events[0].Type)
	}

	var storedRun IngestRunRecord
	if err := json.Unmarshal(fakeStore.env.Payload, &storedRun); err != nil {
		t.Fatalf("Unmarshal fake store payload: %v", err)
	}
	if storedRun.LastCheckpoint == nil || storedRun.LastCheckpoint.Cursor != "cursor-99" {
		t.Fatalf("stored payload checkpoint = %#v, want cursor-99", storedRun.LastCheckpoint)
	}
}
