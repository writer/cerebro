package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type scheduleRuntimeStore struct {
	*orchestratorRuntimeStore
	schedules map[string]ports.SourceRuntimeSyncSchedule
	getErr    error
	recordErr error
	failures  []ports.SourceRuntimeSyncFailure
	successes []string
}

func newScheduleRuntimeStore(base *orchestratorRuntimeStore) *scheduleRuntimeStore {
	return &scheduleRuntimeStore{orchestratorRuntimeStore: base, schedules: map[string]ports.SourceRuntimeSyncSchedule{}}
}

func (s *scheduleRuntimeStore) GetSourceRuntimeSyncSchedule(_ context.Context, runtimeID string) (ports.SourceRuntimeSyncSchedule, bool, error) {
	if s.getErr != nil {
		return ports.SourceRuntimeSyncSchedule{}, false, s.getErr
	}
	schedule, ok := s.schedules[runtimeID]
	return schedule, ok, nil
}

func (s *scheduleRuntimeStore) RecordSourceRuntimeSyncFailure(_ context.Context, failure ports.SourceRuntimeSyncFailure) (ports.SourceRuntimeSyncSchedule, error) {
	s.failures = append(s.failures, failure)
	if s.recordErr != nil {
		return ports.SourceRuntimeSyncSchedule{}, s.recordErr
	}
	schedule := s.schedules[failure.RuntimeID]
	schedule.RuntimeID = failure.RuntimeID
	schedule.TenantID = failure.TenantID
	schedule.ConsecutiveFailures++
	schedule.LastFailureClass = failure.FailureClass
	schedule.NextAttemptAt = failure.NextAttemptAt
	schedule.CircuitOpen = failure.CircuitOpenAfter > 0 && schedule.ConsecutiveFailures >= failure.CircuitOpenAfter
	schedule.UpdatedAt = failure.ObservedAt
	s.schedules[failure.RuntimeID] = schedule
	return schedule, nil
}

func (s *scheduleRuntimeStore) RecordSourceRuntimeSyncSuccess(_ context.Context, runtimeID string) error {
	s.successes = append(s.successes, runtimeID)
	if s.recordErr != nil {
		return s.recordErr
	}
	delete(s.schedules, runtimeID)
	return nil
}

func runScheduleIteration(t *testing.T, store *scheduleRuntimeStore, options orchestratorOptions) (*orchestratorIterationResult, error) {
	t.Helper()
	return runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		options,
		1,
	)
}

func TestRunOrchestratorIterationRecordsClassifiedSyncFailure(t *testing.T) {
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", TenantId: "writer"},
		acquired: true,
	})
	before := time.Now().UTC()
	result, err := runScheduleIteration(t, store, orchestratorOptions{})
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if len(store.failures) != 1 {
		t.Fatalf("recorded failures = %d, want 1", len(store.failures))
	}
	failure := store.failures[0]
	if failure.RuntimeID != "runtime-1" || failure.TenantID != "writer" || failure.FailureClass != string(sourceruntime.SyncFailureInternal) {
		t.Fatalf("recorded failure = %#v, want internal failure for runtime-1", failure)
	}
	if failure.ConfigDigest == "" || failure.ConfigDigest != sourceruntime.SyncConfigDigest(store.runtime) {
		t.Fatalf("recorded config digest = %q, want current runtime digest", failure.ConfigDigest)
	}
	if failure.CircuitOpenAfter != sourceruntime.SyncCircuitOpenThreshold {
		t.Fatalf("circuit threshold = %d, want %d", failure.CircuitOpenAfter, sourceruntime.SyncCircuitOpenThreshold)
	}
	if failure.NextAttemptAt.Before(before) || failure.NextAttemptAt.After(time.Now().UTC().Add(sourceruntime.SyncBackoffBase)) {
		t.Fatalf("next attempt = %s, want within first backoff window", failure.NextAttemptAt)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.Sync != "failed" || runtimeResult.FailureClass != "internal" || runtimeResult.ConsecutiveFailures != 1 {
		t.Fatalf("runtime result = %#v, want failed internal with one failure", runtimeResult)
	}
	if len(store.successes) != 0 {
		t.Fatalf("successes = %v, want none", store.successes)
	}
}

func TestRunOrchestratorIterationSkipsRuntimeInBackoff(t *testing.T) {
	next := time.Now().UTC().Add(30 * time.Minute)
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	})
	store.schedules["runtime-1"] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           "runtime-1",
		ConsecutiveFailures: 9,
		LastFailureClass:    "provider_unavailable",
		NextAttemptAt:       next,
		CircuitOpen:         true,
	}
	result, err := runScheduleIteration(t, store, orchestratorOptions{})
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if store.leaseID != "" {
		t.Fatalf("lease acquired for %q, want no lease while in backoff", store.leaseID)
	}
	if len(store.failures) != 0 || len(store.successes) != 0 {
		t.Fatalf("schedule writes = %d failures / %v successes, want none", len(store.failures), store.successes)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.Sync != "skipped" || runtimeResult.FailureClass != "provider_unavailable" || runtimeResult.ConsecutiveFailures != 9 || !runtimeResult.CircuitOpen {
		t.Fatalf("runtime result = %#v, want backoff skip", runtimeResult)
	}
	if runtimeResult.NextAttemptAt != next.Format(time.RFC3339) {
		t.Fatalf("next attempt = %q, want %q", runtimeResult.NextAttemptAt, next.Format(time.RFC3339))
	}
	payload, err := json.Marshal(runtimeResult)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, fragment := range []string{`"failure_class":"provider_unavailable"`, `"consecutive_failures":9`, `"circuit_open":true`, `"next_attempt_at":"`} {
		if !strings.Contains(string(payload), fragment) {
			t.Fatalf("runtime JSON %s missing %s", payload, fragment)
		}
	}
}

func TestRunOrchestratorIterationBackoffSkipDoesNotConsumeLimit(t *testing.T) {
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtimes: []*cerebrov1.SourceRuntime{
			{Id: "backoff-runtime", SourceId: "missing-source"},
			{Id: "due-runtime", SourceId: "missing-source"},
		},
		acquired: true,
	})
	store.schedules["backoff-runtime"] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           "backoff-runtime",
		ConsecutiveFailures: 1,
		LastFailureClass:    "unauthorized",
		NextAttemptAt:       time.Now().UTC().Add(time.Hour),
	}
	result, err := runScheduleIteration(t, store, orchestratorOptions{Filter: ports.SourceRuntimeFilter{Limit: 1}})
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want due runtime sync failure")
	}
	if len(result.Runtimes) != 2 || result.Runtimes[0].Sync != "skipped" || result.Runtimes[1].RuntimeID != "due-runtime" || result.Runtimes[1].Sync != "failed" {
		t.Fatalf("runtime results = %#v, want backoff skip then due attempt", result.Runtimes)
	}
	if store.leaseID != "due-runtime" {
		t.Fatalf("leased runtime = %q, want due-runtime", store.leaseID)
	}
}

func TestRunOrchestratorIterationExplicitRuntimeBypassesBackoff(t *testing.T) {
	for name, filter := range map[string]ports.SourceRuntimeFilter{
		"runtime id":  {RuntimeID: "runtime-1"},
		"runtime ids": {RuntimeIDs: []string{"runtime-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
				runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
				acquired: true,
			})
			store.schedules["runtime-1"] = ports.SourceRuntimeSyncSchedule{
				RuntimeID:           "runtime-1",
				ConsecutiveFailures: 2,
				LastFailureClass:    "internal",
				NextAttemptAt:       time.Now().UTC().Add(time.Hour),
			}
			result, err := runScheduleIteration(t, store, orchestratorOptions{Filter: filter})
			if err == nil {
				t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
			}
			if store.leaseID != "runtime-1" {
				t.Fatalf("leased runtime = %q, want explicit runtime to run", store.leaseID)
			}
			if len(store.failures) != 1 || result.Runtimes[0].ConsecutiveFailures != 3 {
				t.Fatalf("failures = %#v result = %#v, want outcome recorded as third failure", store.failures, result.Runtimes[0])
			}
		})
	}
}

func TestRunOrchestratorIterationSuccessClearsBackoff(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry(orchestratorNoopRule{})
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"},
		acquired: true,
	})
	store.schedules["runtime-1"] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           "runtime-1",
		ConsecutiveFailures: 4,
		LastFailureClass:    "provider_unavailable",
		NextAttemptAt:       time.Now().UTC().Add(-time.Minute),
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := newGraphTestStore()
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry),
		graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore),
		orchestratorOptions{},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if result.Runtimes[0].Sync != "completed" {
		t.Fatalf("sync status = %q, want completed", result.Runtimes[0].Sync)
	}
	if len(store.successes) != 1 || store.successes[0] != "runtime-1" {
		t.Fatalf("successes = %v, want runtime-1", store.successes)
	}
	if _, ok := store.schedules["runtime-1"]; ok {
		t.Fatal("schedule still present after successful sync")
	}
	if result.Runtimes[0].FailureClass != "" || result.Runtimes[0].NextAttemptAt != "" {
		t.Fatalf("runtime result = %#v, want no backoff fields after success", result.Runtimes[0])
	}
}

func TestRunOrchestratorIterationRunsSyncWhenScheduleReadFails(t *testing.T) {
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	})
	store.getErr = errors.New("schedule table unavailable")
	result, err := runScheduleIteration(t, store, orchestratorOptions{})
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if store.leaseID != "runtime-1" {
		t.Fatalf("leased runtime = %q, want sync to run despite schedule read failure", store.leaseID)
	}
	if result.Runtimes[0].Sync != "failed" || len(store.failures) != 1 {
		t.Fatalf("result = %#v failures = %d, want attempted sync with recorded failure", result.Runtimes[0], len(store.failures))
	}
}

func TestRunOrchestratorIterationSurfacesScheduleWriteFailure(t *testing.T) {
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	})
	writeErr := errors.New("schedule write failed")
	store.recordErr = writeErr
	result, err := runScheduleIteration(t, store, orchestratorOptions{})
	if !errors.Is(err, writeErr) {
		t.Fatalf("runOrchestratorIteration() error = %v, want schedule write failure joined", err)
	}
	if !strings.Contains(result.Runtimes[0].Error, "sync_schedule") || result.Runtimes[0].FailureClass != "internal" {
		t.Fatalf("runtime result = %#v, want sync_schedule error and failure class", result.Runtimes[0])
	}
}

func TestRunOrchestratorIterationReportsFailureClassWithoutScheduleStore(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if got := result.Runtimes[0]; got.FailureClass != "internal" || got.NextAttemptAt != "" || got.ConsecutiveFailures != 0 {
		t.Fatalf("runtime result = %#v, want class only without store", got)
	}
	if got := newOrchestratorSyncScheduler(store).storeState(); got != orchestratorSyncScheduleStoreAbsent {
		t.Fatalf("store state = %q, want absent", got)
	}
}

func TestRunOrchestratorIterationDoesNotRecordCancelledSync(t *testing.T) {
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	})
	scheduler := newOrchestratorSyncScheduler(store)
	result, err := scheduler.recordFailure(context.Background(), store.runtime, orchestratorSyncScheduleCheck{}, ports.ErrSourceRuntimeLeaseLost)
	if err != nil {
		t.Fatalf("recordFailure() error = %v", err)
	}
	if result.FailureClass != "cancelled" || len(store.failures) != 0 {
		t.Fatalf("result = %#v failures = %d, want cancelled class and no write", result, len(store.failures))
	}
}

func heldRuntimeStore(t *testing.T, recorded, current *cerebrov1.SourceRuntime) *scheduleRuntimeStore {
	t.Helper()
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{runtime: current, acquired: true})
	store.schedules[current.GetId()] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           current.GetId(),
		ConsecutiveFailures: 1,
		LastFailureClass:    "unauthorized",
		NextAttemptAt:       time.Now().UTC().Add(sourceruntime.SyncOperatorActionHold),
		ConfigDigest:        sourceruntime.SyncConfigDigest(recorded),
	}
	return store
}

func TestRunOrchestratorIterationConfigChangeLiftsBackoff(t *testing.T) {
	recorded := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", Config: map[string]string{"connection": "env:OLD"}}
	current := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", Config: map[string]string{"connection": "env:NEW"}}
	store := heldRuntimeStore(t, recorded, current)
	scheduler := newOrchestratorSyncScheduler(store)
	if check := scheduler.check(context.Background(), current, false); check.backoff || check.bypassReason != orchestratorSyncBackoffBypassConfigChanged {
		t.Fatalf("check = %#v, want config_changed bypass", check)
	}
	if _, err := runScheduleIteration(t, store, orchestratorOptions{}); err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if store.leaseID != "runtime-1" {
		t.Fatalf("leased runtime = %q, want changed runtime to sync", store.leaseID)
	}
	if len(store.failures) != 1 || store.failures[0].ConfigDigest != sourceruntime.SyncConfigDigest(current) {
		t.Fatalf("failures = %#v, want new outcome recorded with current digest", store.failures)
	}
}

func TestRunOrchestratorIterationRuntimeOwnedConfigChangeKeepsBackoff(t *testing.T) {
	recorded := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", Config: map[string]string{"connection": "env:OLD"}}
	current := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", Config: map[string]string{
		"connection":                              "env:OLD",
		"__cerebro_runtime_status":                "failed",
		"__cerebro_runtime_last_failure_category": "auth_error",
	}}
	store := heldRuntimeStore(t, recorded, current)
	result, err := runScheduleIteration(t, store, orchestratorOptions{})
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if store.leaseID != "" || result.Runtimes[0].Sync != "skipped" {
		t.Fatalf("lease = %q result = %#v, want backoff skip", store.leaseID, result.Runtimes[0])
	}
}

func TestOrchestratorSyncScheduleExplicitRunBypassReason(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"}
	store := heldRuntimeStore(t, runtime, runtime)
	check := newOrchestratorSyncScheduler(store).check(context.Background(), runtime, true)
	if check.backoff || check.bypassReason != orchestratorSyncBackoffBypassExplicitRun {
		t.Fatalf("check = %#v, want explicit_run bypass", check)
	}
}
