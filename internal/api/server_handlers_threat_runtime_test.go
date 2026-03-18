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
