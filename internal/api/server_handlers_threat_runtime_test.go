package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/runtime"
)

type failingRuntimeIngestStore struct {
	saveRunErr       error
	saveRunErrOnCall int
	saveRunCalls     int

	appendEventErr       error
	appendEventErrOnCall int
	appendEventCalls     int

	saveCheckpointErr       error
	saveCheckpointErrOnCall int
	saveCheckpointCalls     int
}

func (s *failingRuntimeIngestStore) Close() error { return nil }

func (s *failingRuntimeIngestStore) SaveRun(context.Context, *runtime.IngestRunRecord) error {
	s.saveRunCalls++
	if s.saveRunErr != nil && (s.saveRunErrOnCall == 0 || s.saveRunErrOnCall == s.saveRunCalls) {
		return s.saveRunErr
	}
	return nil
}

func (s *failingRuntimeIngestStore) LoadRun(context.Context, string) (*runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) ListRuns(context.Context, runtime.IngestRunListOptions) ([]runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) SaveJob(context.Context, *runtime.IngestJobRecord) error {
	return nil
}

func (s *failingRuntimeIngestStore) LoadJob(context.Context, string) (*runtime.IngestJobRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) ListJobs(context.Context, runtime.IngestJobListOptions) ([]runtime.IngestJobRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) AppendEvent(context.Context, string, runtime.IngestEvent) (runtime.IngestEvent, error) {
	s.appendEventCalls++
	if s.appendEventErr != nil && (s.appendEventErrOnCall == 0 || s.appendEventErrOnCall == s.appendEventCalls) {
		return runtime.IngestEvent{}, s.appendEventErr
	}
	return runtime.IngestEvent{}, nil
}

func (s *failingRuntimeIngestStore) LoadEvents(context.Context, string) ([]runtime.IngestEvent, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) SaveCheckpoint(context.Context, string, runtime.IngestCheckpoint) (runtime.IngestCheckpoint, error) {
	s.saveCheckpointCalls++
	if s.saveCheckpointErr != nil && (s.saveCheckpointErrOnCall == 0 || s.saveCheckpointErrOnCall == s.saveCheckpointCalls) {
		return runtime.IngestCheckpoint{}, s.saveCheckpointErr
	}
	return runtime.IngestCheckpoint{}, nil
}

func (s *failingRuntimeIngestStore) LoadCheckpoint(context.Context, string) (*runtime.IngestCheckpoint, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) ClaimSourceEventProcessing(context.Context, string, string, string, time.Time) (bool, error) {
	return false, nil
}

func (s *failingRuntimeIngestStore) MarkSourceEventProcessed(context.Context, string, string, string, time.Time) error {
	return nil
}

type nilReloadRuntimeIngestStore struct {
	saveRunCalls        int
	saveCheckpointCalls int
}

func (s *nilReloadRuntimeIngestStore) Close() error { return nil }

func (s *nilReloadRuntimeIngestStore) SaveRun(context.Context, *runtime.IngestRunRecord) error {
	s.saveRunCalls++
	return nil
}

func (s *nilReloadRuntimeIngestStore) LoadRun(context.Context, string) (*runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) ListRuns(context.Context, runtime.IngestRunListOptions) ([]runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) SaveJob(context.Context, *runtime.IngestJobRecord) error {
	return nil
}

func (s *nilReloadRuntimeIngestStore) LoadJob(context.Context, string) (*runtime.IngestJobRecord, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) ListJobs(context.Context, runtime.IngestJobListOptions) ([]runtime.IngestJobRecord, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) AppendEvent(context.Context, string, runtime.IngestEvent) (runtime.IngestEvent, error) {
	return runtime.IngestEvent{}, nil
}

func (s *nilReloadRuntimeIngestStore) LoadEvents(context.Context, string) ([]runtime.IngestEvent, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) SaveCheckpoint(context.Context, string, runtime.IngestCheckpoint) (runtime.IngestCheckpoint, error) {
	s.saveCheckpointCalls++
	return runtime.IngestCheckpoint{}, nil
}

func (s *nilReloadRuntimeIngestStore) LoadCheckpoint(context.Context, string) (*runtime.IngestCheckpoint, error) {
	return nil, nil
}

func (s *nilReloadRuntimeIngestStore) ClaimSourceEventProcessing(context.Context, string, string, string, time.Time) (bool, error) {
	return false, nil
}

func (s *nilReloadRuntimeIngestStore) MarkSourceEventProcessed(context.Context, string, string, string, time.Time) error {
	return nil
}

type duplicateCheckErrorStore struct {
	runtime.IngestStore
	checkDuplicateErr       error
	checkDuplicateErrOnCall int
	checkDuplicateCalls     int
}

func (s *duplicateCheckErrorStore) ClaimSourceEventProcessing(ctx context.Context, source, eventID, payloadHash string, observedAt time.Time) (bool, error) {
	s.checkDuplicateCalls++
	if s.checkDuplicateErr != nil && (s.checkDuplicateErrOnCall == 0 || s.checkDuplicateErrOnCall == s.checkDuplicateCalls) {
		return false, s.checkDuplicateErr
	}
	return s.IngestStore.ClaimSourceEventProcessing(ctx, source, eventID, payloadHash, observedAt)
}

type markProcessedErrorStore struct {
	runtime.IngestStore
	markProcessedErr       error
	markProcessedErrOnCall int
	markProcessedCalls     int
}

func (s *markProcessedErrorStore) MarkSourceEventProcessed(ctx context.Context, source, eventID, payloadHash string, observedAt time.Time) error {
	s.markProcessedCalls++
	if s.markProcessedErr != nil && (s.markProcessedErrOnCall == 0 || s.markProcessedErrOnCall == s.markProcessedCalls) {
		return s.markProcessedErr
	}
	return s.IngestStore.MarkSourceEventProcessed(ctx, source, eventID, payloadHash, observedAt)
}

type appendEventErrorStore struct {
	runtime.IngestStore
	appendEventErr       error
	appendEventErrOnCall int
	appendEventCalls     int
}

func (s *appendEventErrorStore) AppendEvent(ctx context.Context, runID string, event runtime.IngestEvent) (runtime.IngestEvent, error) {
	s.appendEventCalls++
	if s.appendEventErr != nil && (s.appendEventErrOnCall == 0 || s.appendEventErrOnCall == s.appendEventCalls) {
		return runtime.IngestEvent{}, s.appendEventErr
	}
	return s.IngestStore.AppendEvent(ctx, runID, event)
}

func TestIngestRuntimeEventPersistsIngestRun(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
		"container": map[string]any{
			"container_id": "container-1",
			"namespace":    "default",
			"pod_name":     "miner-0",
			"image":        "ghcr.io/acme/miner:latest",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Source != "runtime_event" {
		t.Fatalf("source = %q, want runtime_event", run.Source)
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if run.ObservationCount != 1 {
		t.Fatalf("observation_count = %d, want 1", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil || run.LastCheckpoint.Cursor != "evt-1" {
		t.Fatalf("last checkpoint = %#v, want cursor evt-1", run.LastCheckpoint)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("len(events) = %d, want 4", len(events))
	}
	if events[0].Type != "ingest_started" {
		t.Fatalf("events[0].Type = %q, want ingest_started", events[0].Type)
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if got := events[1].Data["finding_count"]; got != float64(1) && got != 1 {
		t.Fatalf("observation event finding_count = %#v, want 1", got)
	}
	if events[2].Type != "checkpoint_saved" {
		t.Fatalf("events[2].Type = %q, want checkpoint_saved", events[2].Type)
	}
	if events[3].Type != "ingest_completed" {
		t.Fatalf("events[3].Type = %q, want ingest_completed", events[3].Type)
	}
}

func TestIngestRuntimeEventRejectsInvalidObservationAndFailsRun(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-invalid",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "hubble",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "network",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Status != runtime.IngestRunStatusFailed {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusFailed)
	}
	if run.Stage != "normalize" {
		t.Fatalf("stage = %q, want normalize", run.Stage)
	}
	if run.ObservationCount != 0 {
		t.Fatalf("observation_count = %d, want 0", run.ObservationCount)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(events))
	}
	if events[0].Type != "ingest_started" {
		t.Fatalf("events[0].Type = %q, want ingest_started", events[0].Type)
	}
	if events[1].Type != "observation_rejected" {
		t.Fatalf("events[1].Type = %q, want observation_rejected", events[1].Type)
	}
	if events[2].Type != "ingest_failed" {
		t.Fatalf("events[2].Type = %q, want ingest_failed", events[2].Type)
	}
}

func TestIngestRuntimeEventInvalidRetryDoesNotTurnIntoDuplicate(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	request := map[string]any{
		"id":            "evt-invalid-retry",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "hubble",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "network",
	}

	first := do(t, s, http.MethodPost, "/api/v1/runtime/events", request)
	if first.Code != http.StatusBadRequest {
		t.Fatalf("expected first 400, got %d: %s", first.Code, first.Body.String())
	}
	retry := do(t, s, http.MethodPost, "/api/v1/runtime/events", request)
	if retry.Code != http.StatusBadRequest {
		t.Fatalf("expected retry 400, got %d: %s", retry.Code, retry.Body.String())
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("len(runs) = %d, want 2", len(runs))
	}
	for i, run := range runs {
		if run.Status != runtime.IngestRunStatusFailed {
			t.Fatalf("runs[%d].status = %q, want failed", i, run.Status)
		}
		events, err := a.RuntimeIngest.LoadEvents(context.Background(), run.ID)
		if err != nil {
			t.Fatalf("LoadEvents(%d): %v", i, err)
		}
		for _, event := range events {
			if event.Type == "observation_duplicate" {
				t.Fatalf("runs[%d] unexpectedly recorded duplicate event: %#v", i, event)
			}
		}
	}
}

func TestTelemetryIngestPersistsRunMetadataAndCheckpoint(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "sh",
					"path": "/bin/sh",
				},
			},
			{
				"id":            "telemetry-2",
				"timestamp":     "2026-03-15T19:36:05Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Source != "telemetry" {
		t.Fatalf("source = %q, want telemetry", run.Source)
	}
	if run.Metadata["cluster"] != "prod-west" {
		t.Fatalf("cluster metadata = %q, want prod-west", run.Metadata["cluster"])
	}
	if run.Metadata["node"] != "worker-7" {
		t.Fatalf("node metadata = %q, want worker-7", run.Metadata["node"])
	}
	if run.Metadata["agent_version"] != "1.4.2" {
		t.Fatalf("agent_version metadata = %q, want 1.4.2", run.Metadata["agent_version"])
	}
	if run.ObservationCount != 2 {
		t.Fatalf("observation_count = %d, want 2", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil || run.LastCheckpoint.Cursor != "telemetry-2" {
		t.Fatalf("last checkpoint = %#v, want cursor telemetry-2", run.LastCheckpoint)
	}
	if run.LastCheckpoint.Metadata["cluster"] != "prod-west" {
		t.Fatalf("checkpoint cluster = %q, want prod-west", run.LastCheckpoint.Metadata["cluster"])
	}
	if run.LastCheckpoint.Metadata["processed_events"] != "2" {
		t.Fatalf("checkpoint processed_events = %q, want 2", run.LastCheckpoint.Metadata["processed_events"])
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("len(events) = %d, want 5", len(events))
	}
	if got := events[1].Data["cluster"]; got != "prod-west" {
		t.Fatalf("first observation cluster = %#v, want prod-west", got)
	}
	if got := events[1].Data["node_name"]; got != "worker-7" {
		t.Fatalf("first observation node_name = %#v, want worker-7", got)
	}
}

func TestTelemetryIngestTracksRejectedObservationsSeparately(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-invalid",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "network",
			},
			{
				"id":            "telemetry-valid",
				"timestamp":     "2026-03-15T19:36:05Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}
	if got := body["processed"]; got != float64(1) && got != 1 {
		t.Fatalf("processed = %#v, want 1", got)
	}
	if got := body["rejected"]; got != float64(1) && got != 1 {
		t.Fatalf("rejected = %#v, want 1", got)
	}
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if run.ObservationCount != 1 {
		t.Fatalf("observation_count = %d, want 1", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil {
		t.Fatal("expected checkpoint")
	}
	if got := run.LastCheckpoint.Metadata["processed_events"]; got != "1" {
		t.Fatalf("checkpoint processed_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["rejected_events"]; got != "1" {
		t.Fatalf("checkpoint rejected_events = %q, want 1", got)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("len(events) = %d, want 5", len(events))
	}
	if events[1].Type != "observation_rejected" {
		t.Fatalf("events[1].Type = %q, want observation_rejected", events[1].Type)
	}
	if events[2].Type != "observation_processed" {
		t.Fatalf("events[2].Type = %q, want observation_processed", events[2].Type)
	}
}

func TestIngestRuntimeEventMarksDuplicateSourcePayloads(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	payload := map[string]any{
		"id":            "evt-dup-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
		"container": map[string]any{
			"container_id": "container-1",
			"namespace":    "default",
			"pod_name":     "miner-0",
			"image":        "ghcr.io/acme/miner:latest",
		},
	}

	first := do(t, s, http.MethodPost, "/api/v1/runtime/events", payload)
	if first.Code != http.StatusOK {
		t.Fatalf("first ingest expected 200, got %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeJSON(t, first)
	firstRunID, ok := firstBody["run_id"].(string)
	if !ok || firstRunID == "" {
		t.Fatalf("expected first run_id, got %#v", firstBody["run_id"])
	}

	second := do(t, s, http.MethodPost, "/api/v1/runtime/events", payload)
	if second.Code != http.StatusOK {
		t.Fatalf("second ingest expected 200, got %d: %s", second.Code, second.Body.String())
	}
	secondBody := decodeJSON(t, second)
	if got := secondBody["processed"]; got != false {
		t.Fatalf("processed = %#v, want false", got)
	}
	if got := secondBody["duplicate"]; got != true {
		t.Fatalf("duplicate = %#v, want true", got)
	}
	if got := secondBody["findings"]; got != float64(0) && got != 0 {
		t.Fatalf("findings = %#v, want 0", got)
	}
	secondRunID, ok := secondBody["run_id"].(string)
	if !ok || secondRunID == "" {
		t.Fatalf("expected second run_id, got %#v", secondBody["run_id"])
	}
	if secondRunID == firstRunID {
		t.Fatalf("duplicate run_id = %q, want a new ingest run", secondRunID)
	}

	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1 after duplicate suppression", got)
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), secondRunID)
	if err != nil {
		t.Fatalf("LoadRun duplicate run: %v", err)
	}
	if run == nil {
		t.Fatal("expected duplicate run")
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if run.ObservationCount != 0 {
		t.Fatalf("observation_count = %d, want 0", run.ObservationCount)
	}
	if run.FindingCount != 0 {
		t.Fatalf("finding_count = %d, want 0", run.FindingCount)
	}
	if run.LastCheckpoint == nil {
		t.Fatal("expected duplicate checkpoint")
	}
	if got := run.LastCheckpoint.Metadata["processed_events"]; got != "0" {
		t.Fatalf("checkpoint processed_events = %q, want 0", got)
	}
	if got := run.LastCheckpoint.Metadata["duplicate_events"]; got != "1" {
		t.Fatalf("checkpoint duplicate_events = %q, want 1", got)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), secondRunID)
	if err != nil {
		t.Fatalf("LoadEvents duplicate run: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("len(events) = %d, want 4", len(events))
	}
	if events[1].Type != "observation_duplicate" {
		t.Fatalf("events[1].Type = %q, want observation_duplicate", events[1].Type)
	}
}

func TestIngestRuntimeEventRejectsWhenDuplicateCheckFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &duplicateCheckErrorStore{
		IngestStore:             a.RuntimeIngest,
		checkDuplicateErr:       errors.New("dedupe unavailable"),
		checkDuplicateErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-dedupe-err-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 0 {
		t.Fatalf("recent findings = %d, want 0", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 0 {
		t.Fatalf("response executions = %d, want 0", got)
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Status != runtime.IngestRunStatusFailed {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusFailed)
	}
	if run.Stage != "dedupe" {
		t.Fatalf("stage = %q, want dedupe", run.Stage)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(events))
	}
	if events[1].Type != "observation_rejected" {
		t.Fatalf("events[1].Type = %q, want observation_rejected", events[1].Type)
	}
	if got := events[1].Data["error"]; got != "dedupe check: dedupe unavailable" {
		t.Fatalf("events[1].Data[error] = %#v, want dedupe rejection", got)
	}
	if events[2].Type != "ingest_failed" {
		t.Fatalf("events[2].Type = %q, want ingest_failed", events[2].Type)
	}
}

func TestIngestRuntimeEventRejectsWhenMarkProcessedFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &markProcessedErrorStore{
		IngestStore:            a.RuntimeIngest,
		markProcessedErr:       errors.New("mark unavailable"),
		markProcessedErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-mark-err-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 1 {
		t.Fatalf("response executions = %d, want 1", got)
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Status != runtime.IngestRunStatusFailed {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusFailed)
	}
	if run.Stage != "dedupe" {
		t.Fatalf("stage = %q, want dedupe", run.Stage)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("len(events) = %d, want 4", len(events))
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if events[2].Type != "observation_rejected" {
		t.Fatalf("events[2].Type = %q, want observation_rejected", events[2].Type)
	}
	if got := events[2].Data["error"]; got != "mark processed: mark unavailable" {
		t.Fatalf("events[1].Data[error] = %#v, want mark rejection", got)
	}
	if events[3].Type != "ingest_failed" {
		t.Fatalf("events[3].Type = %q, want ingest_failed", events[3].Type)
	}

	retry := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-mark-err-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
	})
	if retry.Code != http.StatusOK {
		t.Fatalf("expected retry 200, got %d: %s", retry.Code, retry.Body.String())
	}
	retryBody := decodeJSON(t, retry)
	if got := retryBody["duplicate"]; got != true {
		t.Fatalf("retry duplicate = %#v, want true", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings after retry = %d, want 1", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 1 {
		t.Fatalf("response executions after retry = %d, want 1", got)
	}
}

func TestTelemetryIngestSuppressesDuplicateSourcePayloadsInBatch(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-dup-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
			{
				"id":            "telemetry-dup-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}
	if got := body["processed"]; got != float64(1) && got != 1 {
		t.Fatalf("processed = %#v, want 1", got)
	}
	if got := body["rejected"]; got != float64(0) && got != 0 {
		t.Fatalf("rejected = %#v, want 0", got)
	}
	if got := body["duplicates"]; got != float64(1) && got != 1 {
		t.Fatalf("duplicates = %#v, want 1", got)
	}
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.ObservationCount != 1 {
		t.Fatalf("observation_count = %d, want 1", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil {
		t.Fatal("expected checkpoint")
	}
	if got := run.LastCheckpoint.Metadata["processed_events"]; got != "1" {
		t.Fatalf("checkpoint processed_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["duplicate_events"]; got != "1" {
		t.Fatalf("checkpoint duplicate_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["rejected_events"]; got != "0" {
		t.Fatalf("checkpoint rejected_events = %q, want 0", got)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("len(events) = %d, want 5", len(events))
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if events[2].Type != "observation_duplicate" {
		t.Fatalf("events[2].Type = %q, want observation_duplicate", events[2].Type)
	}
}

func TestTelemetryIngestRejectsEventWhenDuplicateCheckFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &duplicateCheckErrorStore{
		IngestStore:             a.RuntimeIngest,
		checkDuplicateErr:       errors.New("dedupe unavailable"),
		checkDuplicateErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-dedupe-err-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
			{
				"id":            "telemetry-dedupe-ok-2",
				"timestamp":     "2026-03-15T19:36:01Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}
	if got := body["processed"]; got != float64(1) && got != 1 {
		t.Fatalf("processed = %#v, want 1", got)
	}
	if got := body["rejected"]; got != float64(1) && got != 1 {
		t.Fatalf("rejected = %#v, want 1", got)
	}
	if got := body["duplicates"]; got != float64(0) && got != 0 {
		t.Fatalf("duplicates = %#v, want 0", got)
	}
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1", got)
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if got := run.LastCheckpoint.Metadata["processed_events"]; got != "1" {
		t.Fatalf("checkpoint processed_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["rejected_events"]; got != "1" {
		t.Fatalf("checkpoint rejected_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["duplicate_events"]; got != "0" {
		t.Fatalf("checkpoint duplicate_events = %q, want 0", got)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("len(events) = %d, want 5", len(events))
	}
	if events[1].Type != "observation_rejected" {
		t.Fatalf("events[1].Type = %q, want observation_rejected", events[1].Type)
	}
	if got := events[1].Data["error"]; got != "dedupe check: dedupe unavailable" {
		t.Fatalf("events[1].Data[error] = %#v, want dedupe rejection", got)
	}
	if events[2].Type != "observation_processed" {
		t.Fatalf("events[2].Type = %q, want observation_processed", events[2].Type)
	}
}

func TestTelemetryIngestInvalidRetryDoesNotTurnIntoDuplicate(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	request := map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-invalid-retry",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "network",
			},
		},
	}

	first := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", request)
	if first.Code != http.StatusOK {
		t.Fatalf("expected first 200, got %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeJSON(t, first)
	if got := firstBody["processed"]; got != float64(0) && got != 0 {
		t.Fatalf("first processed = %#v, want 0", got)
	}
	if got := firstBody["rejected"]; got != float64(1) && got != 1 {
		t.Fatalf("first rejected = %#v, want 1", got)
	}
	if got := firstBody["duplicates"]; got != float64(0) && got != 0 {
		t.Fatalf("first duplicates = %#v, want 0", got)
	}

	retry := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", request)
	if retry.Code != http.StatusOK {
		t.Fatalf("expected retry 200, got %d: %s", retry.Code, retry.Body.String())
	}
	retryBody := decodeJSON(t, retry)
	if got := retryBody["processed"]; got != float64(0) && got != 0 {
		t.Fatalf("retry processed = %#v, want 0", got)
	}
	if got := retryBody["rejected"]; got != float64(1) && got != 1 {
		t.Fatalf("retry rejected = %#v, want 1", got)
	}
	if got := retryBody["duplicates"]; got != float64(0) && got != 0 {
		t.Fatalf("retry duplicates = %#v, want 0", got)
	}
}

func TestTelemetryIngestRejectsEventWhenMarkProcessedFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &markProcessedErrorStore{
		IngestStore:            a.RuntimeIngest,
		markProcessedErr:       errors.New("mark unavailable"),
		markProcessedErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-mark-err-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
			{
				"id":            "telemetry-mark-ok-2",
				"timestamp":     "2026-03-15T19:36:01Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}
	if got := body["processed"]; got != float64(1) && got != 1 {
		t.Fatalf("processed = %#v, want 1", got)
	}
	if got := body["rejected"]; got != float64(1) && got != 1 {
		t.Fatalf("rejected = %#v, want 1", got)
	}
	if got := body["duplicates"]; got != float64(0) && got != 0 {
		t.Fatalf("duplicates = %#v, want 0", got)
	}
	if got := body["findings"]; got != float64(2) && got != 2 {
		t.Fatalf("findings = %#v, want 2", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 2 {
		t.Fatalf("recent findings = %d, want 2", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 2 {
		t.Fatalf("response executions = %d, want 2", got)
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if got := run.FindingCount; got != 2 {
		t.Fatalf("finding_count = %d, want 2", got)
	}
	if got := run.LastCheckpoint.Metadata["processed_events"]; got != "1" {
		t.Fatalf("checkpoint processed_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["rejected_events"]; got != "1" {
		t.Fatalf("checkpoint rejected_events = %q, want 1", got)
	}
	if got := run.LastCheckpoint.Metadata["duplicate_events"]; got != "0" {
		t.Fatalf("checkpoint duplicate_events = %q, want 0", got)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("len(events) = %d, want 6", len(events))
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if events[2].Type != "observation_rejected" {
		t.Fatalf("events[2].Type = %q, want observation_rejected", events[2].Type)
	}
	if got := events[2].Data["error"]; got != "mark processed: mark unavailable" {
		t.Fatalf("events[1].Data[error] = %#v, want mark rejection", got)
	}
	if events[3].Type != "observation_processed" {
		t.Fatalf("events[3].Type = %q, want observation_processed", events[3].Type)
	}

	retry := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-mark-err-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if retry.Code != http.StatusOK {
		t.Fatalf("expected retry 200, got %d: %s", retry.Code, retry.Body.String())
	}
	retryBody := decodeJSON(t, retry)
	if got := retryBody["processed"]; got != float64(0) && got != 0 {
		t.Fatalf("retry processed = %#v, want 0", got)
	}
	if got := retryBody["duplicates"]; got != float64(1) && got != 1 {
		t.Fatalf("retry duplicates = %#v, want 1", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 2 {
		t.Fatalf("recent findings after retry = %d, want 2", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 2 {
		t.Fatalf("response executions after retry = %d, want 2", got)
	}
}

func TestTelemetryIngestKeepsLaterDedupeWhenDuplicateRecordingFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &appendEventErrorStore{
		IngestStore:          a.RuntimeIngest,
		appendEventErr:       errors.New("append unavailable"),
		appendEventErrOnCall: 3,
	}
	s := NewServerWithDependencies(deps)

	first := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-dup-log-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
			{
				"id":            "telemetry-dup-log-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
			{
				"id":            "telemetry-later-2",
				"timestamp":     "2026-03-15T19:36:01Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if first.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeJSON(t, first)
	if got := firstBody["processed"]; got != float64(2) && got != 2 {
		t.Fatalf("processed = %#v, want 2", got)
	}
	if got := firstBody["duplicates"]; got != float64(1) && got != 1 {
		t.Fatalf("duplicates = %#v, want 1", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 2 {
		t.Fatalf("recent findings after first ingest = %d, want 2", got)
	}

	second := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-later-2",
				"timestamp":     "2026-03-15T19:36:01Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if second.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", second.Code, second.Body.String())
	}
	secondBody := decodeJSON(t, second)
	if got := secondBody["processed"]; got != float64(0) && got != 0 {
		t.Fatalf("processed = %#v, want 0", got)
	}
	if got := secondBody["duplicates"]; got != float64(1) && got != 1 {
		t.Fatalf("duplicates = %#v, want 1", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 2 {
		t.Fatalf("recent findings after duplicate replay = %d, want 2", got)
	}
}

func TestTelemetryIngestPreservesRootCauseWhenRejectedObservationLoggingFailsOnDedupeCheck(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &duplicateCheckErrorStore{
		IngestStore: &appendEventErrorStore{
			IngestStore:          a.RuntimeIngest,
			appendEventErr:       errors.New("append unavailable"),
			appendEventErrOnCall: 2,
		},
		checkDuplicateErr:       errors.New("dedupe unavailable"),
		checkDuplicateErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-dedupe-root-cause-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Status != runtime.IngestRunStatusFailed {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusFailed)
	}
	if run.Error != "dedupe unavailable" {
		t.Fatalf("run.Error = %q, want dedupe unavailable", run.Error)
	}
}

func TestTelemetryIngestPreservesRootCauseWhenRejectedObservationLoggingFailsOnMarkProcessed(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &markProcessedErrorStore{
		IngestStore: &appendEventErrorStore{
			IngestStore:          a.RuntimeIngest,
			appendEventErr:       errors.New("append unavailable"),
			appendEventErrOnCall: 3,
		},
		markProcessedErr:       errors.New("mark unavailable"),
		markProcessedErrOnCall: 1,
	}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-mark-root-cause-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	runs, err := a.RuntimeIngest.ListRuns(context.Background(), runtime.IngestRunListOptions{})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Status != runtime.IngestRunStatusFailed {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusFailed)
	}
	if run.Error != "mark unavailable" {
		t.Fatalf("run.Error = %q, want mark unavailable", run.Error)
	}
}

func TestRuntimeIngestSessionRecordObservationUsesProcessingTimeForRunUpdates(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	session, err := s.startRuntimeIngestSession(context.Background(), "telemetry", map[string]string{"cluster": "prod-west"})
	if err != nil {
		t.Fatalf("startRuntimeIngestSession: %v", err)
	}
	if session == nil || session.run == nil {
		t.Fatal("expected runtime ingest session")
	}

	historicalObservedAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	beforeRecord := time.Now().UTC()
	err = session.recordObservation(context.Background(), &runtime.RuntimeObservation{
		ID:         "historic-1",
		Kind:       runtime.ObservationKindProcessExec,
		Source:     "tetragon",
		ObservedAt: historicalObservedAt,
		ResourceID: "pod:default/api-0",
	}, 0, 0)
	if err != nil {
		t.Fatalf("recordObservation: %v", err)
	}
	afterRecord := time.Now().UTC()

	if session.run.UpdatedAt.Before(beforeRecord) || session.run.UpdatedAt.After(afterRecord) {
		t.Fatalf("run.UpdatedAt = %s, want processing time between %s and %s", session.run.UpdatedAt, beforeRecord, afterRecord)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), session.run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if events[1].RecordedAt.Before(beforeRecord) || events[1].RecordedAt.After(afterRecord) {
		t.Fatalf("events[1].RecordedAt = %s, want processing time between %s and %s", events[1].RecordedAt, beforeRecord, afterRecord)
	}
	if got := events[1].Data["observed_at"]; got != historicalObservedAt.Format(time.RFC3339Nano) {
		t.Fatalf("events[1].Data[observed_at] = %#v, want %q", got, historicalObservedAt.Format(time.RFC3339Nano))
	}
}

func TestEnrichRuntimeObservationPreservesExistingClusterAndNodeMetadata(t *testing.T) {
	observation := &runtime.RuntimeObservation{
		Cluster:  "event-cluster",
		NodeName: "event-node",
		Metadata: map[string]any{
			"cluster":   "event-cluster",
			"node_name": "event-node",
		},
	}

	enriched := enrichRuntimeObservation(observation, "payload-cluster", "payload-node", "1.4.2")
	if enriched == nil {
		t.Fatal("expected enriched observation")
	}
	if enriched.Cluster != "event-cluster" {
		t.Fatalf("cluster = %q, want %q", enriched.Cluster, "event-cluster")
	}
	if enriched.NodeName != "event-node" {
		t.Fatalf("node_name = %q, want %q", enriched.NodeName, "event-node")
	}
	if got := enriched.Metadata["cluster"]; got != "event-cluster" {
		t.Fatalf("metadata cluster = %#v, want %q", got, "event-cluster")
	}
	if got := enriched.Metadata["node_name"]; got != "event-node" {
		t.Fatalf("metadata node_name = %#v, want %q", got, "event-node")
	}
	if got := enriched.Metadata["agent_version"]; got != "1.4.2" {
		t.Fatalf("metadata agent_version = %#v, want %q", got, "1.4.2")
	}
}

func TestRuntimeIngestSessionCompleteFailsWhenReloadLosesCheckpointedRun(t *testing.T) {
	store := &nilReloadRuntimeIngestStore{}
	session := &runtimeIngestSession{
		store: store,
		run: &runtime.IngestRunRecord{
			ID:          "run-1",
			Source:      "runtime_event",
			Status:      runtime.IngestRunStatusRunning,
			Stage:       "detect",
			SubmittedAt: time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
	}

	err := session.complete(context.Background(), runtime.IngestCheckpoint{Cursor: "evt-1"})
	if err == nil {
		t.Fatal("expected complete to fail when reloading checkpointed run returns nil")
	}
	if err.Error() != "reload runtime ingest run: missing run after checkpoint save" {
		t.Fatalf("complete error = %q, want missing run reload error", err.Error())
	}
	if store.saveCheckpointCalls != 1 {
		t.Fatalf("saveCheckpointCalls = %d, want 1", store.saveCheckpointCalls)
	}
	if store.saveRunCalls != 0 {
		t.Fatalf("saveRunCalls = %d, want 0", store.saveRunCalls)
	}
}

func TestIngestRuntimeEventContinuesWhenRunPersistenceFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &failingRuntimeIngestStore{saveRunErr: errors.New("boom"), saveRunErrOnCall: 1}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-err",
		"timestamp":     "2026-03-15T19:37:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/api-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}
	if _, ok := body["run_id"]; ok {
		t.Fatalf("expected no run_id when ingest run start fails, got %#v", body["run_id"])
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1", got)
	}
	if s.app.RuntimeRespond == nil {
		t.Fatal("expected runtime response engine")
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 1 {
		t.Fatalf("response executions = %d, want 1", got)
	}
}

func TestIngestRuntimeEventContinuesWhenObservationPersistenceFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &failingRuntimeIngestStore{saveRunErr: errors.New("boom"), saveRunErrOnCall: 2}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-record-err",
		"timestamp":     "2026-03-15T19:37:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/api-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}
	if _, ok := body["run_id"]; ok {
		t.Fatalf("expected run_id to be omitted after ingest persistence degrades, got %#v", body["run_id"])
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 1 {
		t.Fatalf("response executions = %d, want 1", got)
	}
}

func TestIngestTelemetryContinuesWhenObservationPersistenceFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &failingRuntimeIngestStore{saveRunErr: errors.New("boom"), saveRunErrOnCall: 2}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-err-1",
				"timestamp":     "2026-03-15T19:36:05Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["processed"]; got != float64(1) && got != 1 {
		t.Fatalf("processed = %#v, want 1", got)
	}
	if got := body["findings"]; got != float64(1) && got != 1 {
		t.Fatalf("findings = %#v, want 1", got)
	}
	if got := len(s.app.RuntimeDetect.RecentFindings(10)); got != 1 {
		t.Fatalf("recent findings = %d, want 1", got)
	}
	if got := len(s.app.RuntimeRespond.ListExecutions(10)); got != 1 {
		t.Fatalf("response executions = %d, want 1", got)
	}
}
