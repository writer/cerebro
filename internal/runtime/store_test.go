package runtime

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

type casConflictExecutionStore struct {
	env          executionstore.RunEnvelope
	events       []executionstore.EventEnvelope
	compareCalls int
}

type listAllRunsExecutionStore struct {
	envs           []executionstore.RunEnvelope
	listRunsCalled bool
	listAllRunsOps []executionstore.RunListOptions
}

func (s *casConflictExecutionStore) Close() error { return nil }

func (s *listAllRunsExecutionStore) Close() error { return nil }

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

func (s *listAllRunsExecutionStore) UpsertRun(context.Context, executionstore.RunEnvelope) error {
	return nil
}

func (s *listAllRunsExecutionStore) CompareAndSwapRun(context.Context, executionstore.RunEnvelope, executionstore.RunEnvelope) (bool, error) {
	return false, nil
}

func (s *listAllRunsExecutionStore) ReplaceRunWithEvents(context.Context, executionstore.RunEnvelope, []executionstore.EventEnvelope) error {
	return nil
}

func (s *listAllRunsExecutionStore) LoadRun(context.Context, string, string) (*executionstore.RunEnvelope, error) {
	return nil, nil
}

func (s *listAllRunsExecutionStore) ListRuns(context.Context, string, executionstore.RunListOptions) ([]executionstore.RunEnvelope, error) {
	s.listRunsCalled = true
	return nil, nil
}

func (s *listAllRunsExecutionStore) ListAllRuns(_ context.Context, opts executionstore.RunListOptions) ([]executionstore.RunEnvelope, error) {
	s.listAllRunsOps = append(s.listAllRunsOps, opts)
	return append([]executionstore.RunEnvelope(nil), s.envs...), nil
}

func (s *listAllRunsExecutionStore) DeleteRun(context.Context, string, string) error { return nil }

func (s *listAllRunsExecutionStore) DeleteEvents(context.Context, string, string) error { return nil }

func (s *listAllRunsExecutionStore) SaveEvent(context.Context, executionstore.EventEnvelope) (executionstore.EventEnvelope, error) {
	return executionstore.EventEnvelope{}, nil
}

func (s *listAllRunsExecutionStore) LoadEvents(context.Context, string, string) ([]executionstore.EventEnvelope, error) {
	return nil, nil
}

func (s *listAllRunsExecutionStore) LookupProcessedEvent(context.Context, string, string, time.Time) (*executionstore.ProcessedEventRecord, error) {
	return nil, nil
}

func (s *listAllRunsExecutionStore) TouchProcessedEvent(context.Context, string, string, time.Time, time.Duration) error {
	return nil
}

func (s *listAllRunsExecutionStore) ClaimProcessedEvent(context.Context, executionstore.ProcessedEventRecord, int) (bool, *executionstore.ProcessedEventRecord, error) {
	return true, nil, nil
}

func (s *listAllRunsExecutionStore) RememberProcessedEvent(context.Context, executionstore.ProcessedEventRecord, int) error {
	return nil
}

func (s *listAllRunsExecutionStore) DeleteProcessedEvent(context.Context, string, string) error {
	return nil
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

func (s *casConflictExecutionStore) ClaimProcessedEvent(context.Context, executionstore.ProcessedEventRecord, int) (bool, *executionstore.ProcessedEventRecord, error) {
	return true, nil, nil
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

func TestSQLiteIngestStoreSaveLoadAndListJobs(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	replay := &IngestJobRecord{
		ID:               "job-replay-1",
		Type:             IngestJobTypeReplay,
		Source:           "tetragon",
		Status:           IngestRunStatusRunning,
		Stage:            "replay",
		SubmittedAt:      now,
		UpdatedAt:        now,
		ParentRunID:      "run-1",
		ObservationCount: 12,
		Metadata: map[string]string{
			"cursor_start": "100",
			"cursor_end":   "150",
		},
	}
	materialize := &IngestJobRecord{
		ID:            "job-mat-1",
		Type:          IngestJobTypeMaterialization,
		Source:        "graph",
		Status:        IngestRunStatusQueued,
		Stage:         "enqueue",
		SubmittedAt:   now.Add(time.Minute),
		UpdatedAt:     now.Add(time.Minute),
		ParentRunID:   "run-1",
		PromotedCount: 4,
	}
	for _, job := range []*IngestJobRecord{replay, materialize} {
		if err := store.SaveJob(context.Background(), job); err != nil {
			t.Fatalf("SaveJob(%s): %v", job.ID, err)
		}
	}

	loaded, err := store.LoadJob(context.Background(), replay.ID)
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded job")
	}
	if loaded.Type != IngestJobTypeReplay {
		t.Fatalf("type = %q, want %q", loaded.Type, IngestJobTypeReplay)
	}
	if loaded.Metadata["cursor_end"] != "150" {
		t.Fatalf("metadata = %#v, want cursor_end=150", loaded.Metadata)
	}

	jobs, err := store.ListJobs(context.Background(), IngestJobListOptions{
		OrderBySubmittedAt: true,
		ActiveOnly:         true,
	})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("len(jobs) = %d, want 2", len(jobs))
	}
	if jobs[0].ID != materialize.ID || jobs[1].ID != replay.ID {
		t.Fatalf("jobs = %#v, want materialization then replay by submitted_at desc", jobs)
	}

	replayOnly, err := store.ListJobs(context.Background(), IngestJobListOptions{
		Types: []IngestJobType{IngestJobTypeReplay},
	})
	if err != nil {
		t.Fatalf("ListJobs replay only: %v", err)
	}
	if len(replayOnly) != 1 || replayOnly[0].ID != replay.ID {
		t.Fatalf("replay jobs = %#v, want only %s", replayOnly, replay.ID)
	}

	invalidOnly, err := store.ListJobs(context.Background(), IngestJobListOptions{
		Types: []IngestJobType{IngestJobType("invalid")},
	})
	if err != nil {
		t.Fatalf("ListJobs invalid only: %v", err)
	}
	if len(invalidOnly) != 0 {
		t.Fatalf("invalid jobs = %#v, want empty result", invalidOnly)
	}
}

func TestSQLiteIngestStoreSaveJobRejectsUnsupportedType(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	err = store.SaveJob(context.Background(), &IngestJobRecord{
		ID:          "job-unsupported",
		Type:        IngestJobType("unknown"),
		Source:      "tetragon",
		Status:      IngestRunStatusQueued,
		SubmittedAt: time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected unsupported job type error")
	}
}

func TestSQLiteIngestStoreListJobsDefaultOrderingIsGlobalByUpdatedAt(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	replay := &IngestJobRecord{
		ID:          "job-replay-older",
		Type:        IngestJobTypeReplay,
		Source:      "tetragon",
		Status:      IngestRunStatusRunning,
		Stage:       "replay",
		SubmittedAt: now.Add(2 * time.Minute),
		UpdatedAt:   now.Add(time.Minute),
	}
	materialize := &IngestJobRecord{
		ID:          "job-mat-newer",
		Type:        IngestJobTypeMaterialization,
		Source:      "graph",
		Status:      IngestRunStatusRunning,
		Stage:       "materialize",
		SubmittedAt: now,
		UpdatedAt:   now.Add(3 * time.Minute),
	}
	for _, job := range []*IngestJobRecord{replay, materialize} {
		if err := store.SaveJob(context.Background(), job); err != nil {
			t.Fatalf("SaveJob(%s): %v", job.ID, err)
		}
	}

	jobs, err := store.ListJobs(context.Background(), IngestJobListOptions{
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("ListJobs default ordering: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("len(jobs) = %d, want 1", len(jobs))
	}
	if jobs[0].ID != materialize.ID {
		t.Fatalf("jobs[0].ID = %q, want %q", jobs[0].ID, materialize.ID)
	}

	nextPage, err := store.ListJobs(context.Background(), IngestJobListOptions{
		Limit:  1,
		Offset: 1,
	})
	if err != nil {
		t.Fatalf("ListJobs default ordering second page: %v", err)
	}
	if len(nextPage) != 1 {
		t.Fatalf("len(nextPage) = %d, want 1", len(nextPage))
	}
	if nextPage[0].ID != replay.ID {
		t.Fatalf("nextPage[0].ID = %q, want %q", nextPage[0].ID, replay.ID)
	}
}

func TestSQLiteIngestStoreListJobsUsesListAllRunsAcrossNamespaces(t *testing.T) {
	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	replayEnv, err := runtimeIngestJobEnvelope(&IngestJobRecord{
		ID:          "job-replay-1",
		Type:        IngestJobTypeReplay,
		Source:      "tetragon",
		Status:      IngestRunStatusRunning,
		Stage:       "replay",
		SubmittedAt: now,
		UpdatedAt:   now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("runtimeIngestJobEnvelope replay: %v", err)
	}
	materializeEnv, err := runtimeIngestJobEnvelope(&IngestJobRecord{
		ID:          "job-materialize-1",
		Type:        IngestJobTypeMaterialization,
		Source:      "graph",
		Status:      IngestRunStatusQueued,
		Stage:       "materialize",
		SubmittedAt: now.Add(time.Minute),
		UpdatedAt:   now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("runtimeIngestJobEnvelope materialize: %v", err)
	}

	execStore := &listAllRunsExecutionStore{
		envs: []executionstore.RunEnvelope{materializeEnv, replayEnv},
	}
	store := NewSQLiteIngestStoreWithExecutionStore(execStore)

	jobs, err := store.ListJobs(context.Background(), IngestJobListOptions{
		Types:              []IngestJobType{IngestJobTypeReplay, IngestJobTypeMaterialization},
		Statuses:           []IngestRunStatus{IngestRunStatusQueued, IngestRunStatusRunning},
		Limit:              5,
		Offset:             2,
		OrderBySubmittedAt: true,
		ActiveOnly:         true,
	})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if execStore.listRunsCalled {
		t.Fatal("expected ListJobs to avoid per-namespace ListRuns calls")
	}
	if len(execStore.listAllRunsOps) != 1 {
		t.Fatalf("len(listAllRunsOps) = %d, want 1", len(execStore.listAllRunsOps))
	}

	opts := execStore.listAllRunsOps[0]
	if len(opts.Namespaces) != 2 || opts.Namespaces[0] != runtimeReplayNamespace || opts.Namespaces[1] != runtimeMaterializeNamespace {
		t.Fatalf("namespaces = %#v, want replay and materialize namespaces", opts.Namespaces)
	}
	if opts.Limit != 5 || opts.Offset != 2 || !opts.OrderBySubmittedAt {
		t.Fatalf("query opts = %#v, want limit=5 offset=2 order_by_submitted_at=true", opts)
	}
	if len(opts.Statuses) != 2 || opts.Statuses[0] != string(IngestRunStatusQueued) || opts.Statuses[1] != string(IngestRunStatusRunning) {
		t.Fatalf("statuses = %#v, want queued/running", opts.Statuses)
	}
	if len(opts.ExcludeStatuses) != 2 || opts.ExcludeStatuses[0] != string(IngestRunStatusCompleted) || opts.ExcludeStatuses[1] != string(IngestRunStatusFailed) {
		t.Fatalf("exclude_statuses = %#v, want completed/failed", opts.ExcludeStatuses)
	}
	if len(jobs) != 2 || jobs[0].ID != "job-materialize-1" || jobs[1].ID != "job-replay-1" {
		t.Fatalf("jobs = %#v, want materialize then replay payloads returned from ListAllRuns", jobs)
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

func TestSQLiteIngestStoreSourceEventDedupesMatchingPayloadHashes(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	observedAt := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	if err := store.MarkSourceEventProcessed(context.Background(), "telemetry", "evt-1", "hash-a", observedAt); err != nil {
		t.Fatalf("MarkSourceEventProcessed: %v", err)
	}

	duplicate, err := store.checkDuplicateSourceEvent(context.Background(), "telemetry", "evt-1", "hash-a")
	if err != nil {
		t.Fatalf("checkDuplicateSourceEvent: %v", err)
	}
	if !duplicate {
		t.Fatal("expected duplicate match for same source/id/hash")
	}

	record, err := store.store.LookupProcessedEvent(context.Background(), runtimeProcessedEventNamespace, runtimeProcessedEventKey("telemetry", "evt-1"), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record")
	}
	if record.DuplicateCount != 1 {
		t.Fatalf("duplicate_count = %d, want 1", record.DuplicateCount)
	}
}

func TestSQLiteIngestStoreClaimSourceEventProcessingDedupesActiveClaim(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	observedAt := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	duplicate, err := store.ClaimSourceEventProcessing(context.Background(), "telemetry", "evt-claim-1", "hash-a", observedAt)
	if err != nil {
		t.Fatalf("ClaimSourceEventProcessing first: %v", err)
	}
	if duplicate {
		t.Fatal("expected first claim to be accepted")
	}

	duplicate, err = store.ClaimSourceEventProcessing(context.Background(), "telemetry", "evt-claim-1", "hash-a", observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimSourceEventProcessing second: %v", err)
	}
	if !duplicate {
		t.Fatal("expected active claim to suppress duplicate")
	}

	record, err := store.store.LookupProcessedEvent(context.Background(), runtimeProcessedEventNamespace, runtimeProcessedEventKey("telemetry", "evt-claim-1"), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event claim record")
	}
	if record.Status != executionstore.ProcessedEventStatusProcessing {
		t.Fatalf("status = %q, want %q", record.Status, executionstore.ProcessedEventStatusProcessing)
	}
	if record.DuplicateCount != 0 {
		t.Fatalf("duplicate_count = %d, want 0 for in-flight claim", record.DuplicateCount)
	}
}

func TestSQLiteIngestStoreSourceEventAllowsSameIDWithDifferentPayloadHash(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	observedAt := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	if err := store.MarkSourceEventProcessed(context.Background(), "telemetry", "evt-1", "hash-a", observedAt); err != nil {
		t.Fatalf("MarkSourceEventProcessed: %v", err)
	}

	duplicate, err := store.checkDuplicateSourceEvent(context.Background(), "telemetry", "evt-1", "hash-b")
	if err != nil {
		t.Fatalf("checkDuplicateSourceEvent: %v", err)
	}
	if duplicate {
		t.Fatal("expected hash mismatch to bypass duplicate suppression")
	}

	record, err := store.store.LookupProcessedEvent(context.Background(), runtimeProcessedEventNamespace, runtimeProcessedEventKey("telemetry", "evt-1"), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record")
	}
	if record.DuplicateCount != 0 {
		t.Fatalf("duplicate_count = %d, want 0", record.DuplicateCount)
	}
}

func TestSQLiteIngestStoreSourceEventDuplicateTouchUsesWallClockTTL(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	staleObservedAt := now.Add(-(runtimeProcessedEventTTL + 24*time.Hour))
	if err := store.MarkSourceEventProcessed(context.Background(), "telemetry", "evt-stale", "hash-a", staleObservedAt); err != nil {
		t.Fatalf("MarkSourceEventProcessed: %v", err)
	}

	duplicate, err := store.checkDuplicateSourceEvent(context.Background(), "telemetry", "evt-stale", "hash-a")
	if err != nil {
		t.Fatalf("checkDuplicateSourceEvent: %v", err)
	}
	if !duplicate {
		t.Fatal("expected duplicate match for stale observed_at")
	}

	record, err := store.store.LookupProcessedEvent(context.Background(), runtimeProcessedEventNamespace, runtimeProcessedEventKey("telemetry", "evt-stale"), now)
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record to remain after duplicate touch")
	}
	if !record.ExpiresAt.After(now) {
		t.Fatalf("expires_at = %s, want after %s", record.ExpiresAt, now)
	}
	if record.DuplicateCount != 1 {
		t.Fatalf("duplicate_count = %d, want 1", record.DuplicateCount)
	}
}

func TestSQLiteIngestStoreSourceEventDuplicateComparisonTrimsStoredHash(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	if err := store.store.RememberProcessedEvent(context.Background(), executionstore.ProcessedEventRecord{
		Namespace:   runtimeProcessedEventNamespace,
		EventKey:    runtimeProcessedEventKey("telemetry", "evt-trim-1"),
		Status:      executionstore.ProcessedEventStatusProcessed,
		PayloadHash: "  hash-a  ",
		FirstSeenAt: now,
		LastSeenAt:  now,
		ProcessedAt: now,
		ExpiresAt:   now.Add(runtimeProcessedEventTTL),
	}, runtimeProcessedEventMaxRecords); err != nil {
		t.Fatalf("RememberProcessedEvent: %v", err)
	}

	duplicate, err := store.checkDuplicateSourceEvent(context.Background(), "telemetry", "evt-trim-1", "hash-a")
	if err != nil {
		t.Fatalf("checkDuplicateSourceEvent: %v", err)
	}
	if !duplicate {
		t.Fatal("expected trimmed stored hash to match trimmed input")
	}
}
