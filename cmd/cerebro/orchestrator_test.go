package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAppendOrchestratorRunBoundsForeverHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 3; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, true)
	}
	if len(runs) != 1 || runs[0].Iteration != 3 {
		t.Fatalf("forever runs = %#v, want only latest iteration", runs)
	}
}

func TestAppendOrchestratorRunPreservesFiniteHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 2; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, false)
	}
	if len(runs) != 2 || runs[0].Iteration != 1 || runs[1].Iteration != 2 {
		t.Fatalf("finite runs = %#v, want all iterations", runs)
	}
}

func TestShouldPrintOrchestratorResultSkipsNilStartupFailure(t *testing.T) {
	if shouldPrintOrchestratorResult(nil) {
		t.Fatal("shouldPrintOrchestratorResult(nil) = true, want false")
	}
	if !shouldPrintOrchestratorResult(&orchestratorResult{}) {
		t.Fatal("shouldPrintOrchestratorResult(non-nil) = false, want true")
	}
}

func TestParseOrchestratorOptionsRejectsZeroLimit(t *testing.T) {
	if _, err := parseOrchestratorOptions([]string{"limit=0"}); err == nil {
		t.Fatal("parseOrchestratorOptions(limit=0) error = nil, want error")
	}
}

func TestParseOrchestratorOptionsRejectsNonPositiveTimeout(t *testing.T) {
	if _, err := parseOrchestratorOptions([]string{"graph_timeout=0s"}); err == nil {
		t.Fatal("parseOrchestratorOptions(graph_timeout=0s) error = nil, want error")
	}
}

func TestParseOrchestratorOptionsAcceptsRuntimeID(t *testing.T) {
	options, err := parseOrchestratorOptions([]string{"runtime_id=writer-okta-audit"})
	if err != nil {
		t.Fatalf("parseOrchestratorOptions(runtime_id) error = %v", err)
	}
	if got := options.Filter.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("runtime filter = %q, want writer-okta-audit", got)
	}
}

func TestOrchestratorShutdownSignalsIncludeSIGTERM(t *testing.T) {
	signals := orchestratorShutdownSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("orchestratorShutdownSignals() = %#v, want interrupt and SIGTERM", signals)
	}
}

// A blocked downstream call (e.g. a Neo4j tx waiting on a row lock held
// by a concurrent runtime, or a source.Read() retry storm against an
// exhausted upstream rate limit) must not park an orchestrator iteration
// indefinitely. runOrchestratorPhase wraps each post-sync step in a
// dedicated context.WithTimeout that fires independently of the
// runtime-level lease TTL, so a phase that exceeds its budget returns
// context.DeadlineExceeded and the caller can mark the phase failed,
// release the lease, and let the next iteration retry from a clean
// context. Without this, the only path out of a stuck phase is to kill
// the Fargate task — exactly the symptom that motivated this fix.
func TestRunOrchestratorPhaseFailsFastOnTimeout(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	start := time.Now()
	_, err := runOrchestratorPhase[*struct{}](context.Background(), "orchestrator.test_phase", 1, runtime, 5*time.Millisecond, func(phaseCtx context.Context) (*struct{}, error) {
		<-phaseCtx.Done()
		return nil, phaseCtx.Err()
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("runOrchestratorPhase() error = nil, want context.DeadlineExceeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runOrchestratorPhase() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("runOrchestratorPhase elapsed = %v, want fail-fast under per-phase budget; without the timeout the phase would block until lease expiry", elapsed)
	}
}

// runOrchestratorPhase must propagate the result returned by the wrapped
// function on success and not paper over the underlying error type when
// the function fails for non-timeout reasons. This keeps caller error
// branches (e.g. ErrRuleUnavailable / ErrGraphRuntimeUnavailable
// short-circuits) working through the phase wrapper.
func TestRunOrchestratorPhasePassesThroughErrors(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	wantErr := errors.New("downstream failure")
	result, err := runOrchestratorPhase[int](context.Background(), "orchestrator.test_phase", 1, runtime, time.Second, func(_ context.Context) (int, error) {
		return 42, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runOrchestratorPhase() error = %v, want %v", err, wantErr)
	}
	if result != 42 {
		t.Fatalf("runOrchestratorPhase() result = %d, want 42 (passed through even on error so callers can apply counters)", result)
	}
}

func TestRunOrchestratorPhaseAnnotatesMainDuration(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	stderr := captureCommandStderr(t, func() {
		ctx, span := telemetry.StartMain(context.Background(), "orchestrator.run", telemetry.Attrs())
		_, err := runOrchestratorPhase[int](ctx, "orchestrator.test_phase", 1, runtime, time.Second, func(context.Context) (int, error) {
			return 1, nil
		})
		if err != nil {
			t.Fatalf("runOrchestratorPhase() error = %v", err)
		}
		telemetry.End(span, "completed", telemetry.Attrs())
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if _, ok := payload["phase.orchestrator_test_phase.last_duration_ms"].(float64); !ok {
		t.Fatalf("last duration missing: %#v", payload)
	}
	if _, ok := payload["phase.orchestrator_test_phase.max_duration_ms"].(float64); !ok {
		t.Fatalf("max duration missing: %#v", payload)
	}
}

func TestRunOrchestratorPhaseEmitsPlatformJobPhaseEvents(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	stderr := captureCommandStderr(t, func() {
		ctx, span := telemetry.StartMain(context.Background(), "orchestrator.run", telemetry.Attrs())
		ctx = withOrchestratorJobMetadata(ctx, orchestratorJobMetadata{
			ID:        "orchestrator-test-job",
			Kind:      jobs.KindSourceRuntimeOrchestrate,
			Name:      "orchestrator.run",
			Schedule:  "single_run",
			StartedAt: time.Now().Add(-time.Second),
		})
		_, err := runOrchestratorPhase[int](ctx, "orchestrator.test_phase", 3, runtime, time.Second, func(context.Context) (int, error) {
			return 1, nil
		})
		if err != nil {
			t.Fatalf("runOrchestratorPhase() error = %v", err)
		}
		telemetry.End(span, "completed", telemetry.Attrs())
	})

	started := commandTelemetryPayloads(t, stderr, "event", "platform.job.phase.started")
	if len(started) != 1 {
		t.Fatalf("platform.job.phase.started events = %d, want 1; stderr=%s", len(started), stderr)
	}
	completed := commandTelemetryPayloads(t, stderr, "event", "platform.job.phase.completed")
	if len(completed) != 1 {
		t.Fatalf("platform.job.phase.completed events = %d, want 1; stderr=%s", len(completed), stderr)
	}
	payload := completed[0]
	for key, want := range map[string]any{
		"job.id":           "orchestrator-test-job",
		"job.kind":         jobs.KindSourceRuntimeOrchestrate,
		"job.name":         "orchestrator.run",
		"job.phase":        "orchestrator.test_phase",
		"job.phase_key":    "orchestrator_test_phase",
		"job.phase.status": "completed",
		"iteration":        float64(3),
		"runtime_id":       "runtime-1",
		"source_id":        "github",
		"tenant_id":        "writer",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if got, ok := payload["job.phase.duration_ms"].(float64); !ok || got < 0 {
		t.Fatalf("job.phase.duration_ms = %#v, want non-negative number; payload=%#v", payload["job.phase.duration_ms"], payload)
	}
}

func TestEmitOrchestratorRunTerminalWideEvent(t *testing.T) {
	stderr := captureCommandStderr(t, func() {
		ctx, span := telemetry.StartMain(context.Background(), "orchestrator.run", telemetry.Attrs())
		emitOrchestratorRunTerminalWideEvent(ctx, "completed", telemetry.Attrs(
			telemetryField("job.id", "orchestrator-test-job"),
		))
		telemetry.End(span, "completed", telemetry.Attrs())
	})

	events := commandTelemetryPayloads(t, stderr, "event", "orchestrator.run.finished")
	if len(events) != 1 {
		t.Fatalf("orchestrator.run.finished events = %d, want 1; stderr=%s", len(events), stderr)
	}
	payload := events[0]
	for key, want := range map[string]any{
		"event.dataset":       "cerebro.wide_events",
		"event.type":          "end",
		"event.outcome":       "success",
		"wide_event":          true,
		"wide_event.contract": "orchestrator-run-terminal",
		"operation.name":      "orchestrator.run",
		"operation.status":    "completed",
		"status":              "completed",
		"job.id":              "orchestrator-test-job",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

// runOrchestratorPhase must inherit cancellation from the parent runtime
// context so shutdown and caller cancellation reach phase work promptly.
func TestRunOrchestratorPhaseInheritsParentCancellation(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runOrchestratorPhase[*struct{}](parent, "orchestrator.test_phase", 1, runtime, time.Minute, func(phaseCtx context.Context) (*struct{}, error) {
		select {
		case <-phaseCtx.Done():
			return nil, phaseCtx.Err()
		case <-time.After(time.Second):
			return nil, errors.New("phase did not observe parent cancellation")
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runOrchestratorPhase() error = %v, want context.Canceled (inherited from parent)", err)
	}
}

func TestAnnotateOrchestratorRuntimeMainAddsHealthFields(t *testing.T) {
	syncLag := int64(30)
	watermarkLag := int64(45)
	graphLag := int64(60)
	cadence := int64(300)
	staleAfter := int64(600)
	stderr := captureCommandStderr(t, func() {
		ctx, span := telemetry.StartMain(context.Background(), "orchestrator.run", telemetry.Attrs())
		annotateOrchestratorRuntimeMain(ctx, &orchestratorRuntimeResult{
			RuntimeID:      "runtime-1",
			SourceID:       "github",
			TenantID:       "writer",
			Sync:           "completed",
			GraphIngest:    "completed",
			FindingRules:   "completed",
			GraphRules:     "completed",
			PagesRead:      2,
			EventsAppended: 3,
			Health: sourcehealth.Record{
				RuntimeID:                 "runtime-1",
				SourceID:                  "github",
				TenantID:                  "writer",
				Family:                    "code",
				EnabledState:              "enabled",
				Status:                    "healthy",
				ContractProbeState:        "passing",
				CursorPending:             true,
				CheckpointCursorPresent:   true,
				SyncLagSeconds:            &syncLag,
				WatermarkLagSeconds:       &watermarkLag,
				GraphLagSeconds:           &graphLag,
				ExpectedCadenceSeconds:    &cadence,
				StaleAfterSeconds:         &staleAfter,
				LatestGraphRun:            &sourcehealth.GraphRun{Status: "completed"},
				LatestFindingEvaluation:   &sourcehealth.FindingEvaluation{Status: "completed"},
				ScheduleContextConfigured: true,
			},
		}, "completed", telemetry.Attrs())
		telemetry.End(span, "completed", telemetry.Attrs())
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"runtime_id":                                      "runtime-1",
		"source_runtime_id":                               "runtime-1",
		"source_id":                                       "github",
		"tenant_id":                                       "writer",
		"job.runtime.status":                              "completed",
		"job_runtime_status":                              "completed",
		"orchestrator.runtime.last_status":                "completed",
		"source_runtime.family":                           "code",
		"source_runtime.enabled_state":                    "enabled",
		"source_runtime.freshness_state":                  "healthy",
		"source_runtime.source_sync_state":                "current",
		"source_runtime.graph_ingest_state":               "current",
		"source_runtime.finding_evaluation_state":         "current",
		"source_runtime.next_action":                      "monitor",
		"source_runtime.backfill_eligible":                false,
		"source_runtime.contract_probe_state":             "passing",
		"source_runtime.contract_probe_status":            "success",
		"source_runtime.cursor_pending":                   true,
		"source_runtime.checkpoint_cursor_present":        true,
		"orchestrator.runtime.freshness.healthy.count":    float64(1),
		"orchestrator.runtime_health_gate.status":         "pass",
		"orchestrator.runtime_health_gate.blocking_state": "none",
		"orchestrator.runtime_health_gate.pass_count":     float64(1),
		"orchestrator.runtime_health_gate.healthy_count":  float64(1),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	for key, want := range map[string]float64{
		"source_runtime.sync_lag_seconds":                            30,
		"source_runtime.watermark_lag_seconds":                       45,
		"source_runtime.graph_lag_seconds":                           60,
		"source_runtime.expected_cadence_seconds":                    300,
		"source_runtime.stale_after_seconds":                         600,
		"orchestrator.runtime_health_gate.max_sync_lag_seconds":      30,
		"orchestrator.runtime_health_gate.max_watermark_lag_seconds": 45,
		"orchestrator.runtime_health_gate.max_graph_lag_seconds":     60,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestCaptureOrchestratorErrorAnnotatesFirstFailureOnly(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"}
	stderr := captureCommandStderr(t, func() {
		ctx, span := telemetry.StartMain(context.Background(), "orchestrator.run", telemetry.Attrs())
		captureOrchestratorError(ctx, "orchestrator.runtime.error", 1, runtime, "sync", context.DeadlineExceeded)
		captureOrchestratorError(ctx, "orchestrator.runtime.error", 1, runtime, "graph_ingest", errors.New("graph failed"))
		telemetry.End(span, "failed", telemetry.Attrs())
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"orchestrator.first_failure.present":    true,
		"orchestrator.first_failure.event_name": "orchestrator.runtime.error",
		"orchestrator.first_failure.stage":      "sync",
		"orchestrator.first_failure.error_kind": "context_deadline_exceeded",
		"orchestrator.first_failure.iteration":  float64(1),
		"orchestrator.first_failure.runtime_id": "runtime-1",
		"orchestrator.first_failure.source_id":  "github",
		"orchestrator.first_failure.tenant_id":  "writer",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if got, ok := payload["orchestrator.first_failure.error_fingerprint"].(string); !ok || got == "" {
		t.Fatalf("first failure fingerprint missing: %#v", payload)
	}
}

func commandTelemetryPayloads(t *testing.T, stderr string, kind string, name string) []map[string]any {
	t.Helper()
	var payloads []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("telemetry line is not JSON: %v\nline=%s\nstderr=%s", err, line, stderr)
		}
		if payload["kind"] == kind && payload["name"] == name {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

func TestNewOrchestratorRuntimeServiceProjectsSourceSyncToStateOnly(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
	}
	eventLog := &orchestratorEventLog{}
	stateStore := newGraphTestStore()

	service := newOrchestratorRuntimeService(registry, store, eventLog, stateStore)
	result, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-1", PageLimit: 1})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.GetEventsAppended() != 1 {
		t.Fatalf("Sync().EventsAppended = %d, want 1", result.GetEventsAppended())
	}
	if result.GetEntitiesProjected() == 0 || result.GetLinksProjected() == 0 {
		t.Fatalf("Sync() projected entities/links = %d/%d, want state projections", result.GetEntitiesProjected(), result.GetLinksProjected())
	}
	if len(stateStore.entities) == 0 || len(stateStore.links) == 0 {
		t.Fatalf("state projections not stored: entities=%d links=%d", len(stateStore.entities), len(stateStore.links))
	}
}

func TestNewOrchestratorSyncProjectorDoesNotCreateGraphOnlyProjector(t *testing.T) {
	if projector := newOrchestratorSyncProjector(nil); projector != nil {
		t.Fatalf("newOrchestratorSyncProjector(nil) = %#v, want nil", projector)
	}
}

func TestOrchestratorGraphPageLimitCoversSyncedPages(t *testing.T) {
	tests := []struct {
		name        string
		configured  uint32
		syncedPages uint32
		want        uint32
	}{
		{name: "uses configured when higher", configured: 10, syncedPages: 3, want: 10},
		{name: "raises unset to synced pages", configured: 0, syncedPages: 3, want: 3},
		{name: "raises lower configured to synced pages", configured: 1, syncedPages: 3, want: 3},
		{name: "leaves defaulting to graph ingest when no sync pages", configured: 0, syncedPages: 0, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orchestratorGraphPageLimit(tt.configured, tt.syncedPages); got != tt.want {
				t.Fatalf("orchestratorGraphPageLimit(%d, %d) = %d, want %d", tt.configured, tt.syncedPages, got, tt.want)
			}
		})
	}
}

func TestOrchestratorRuntimeStartCursorOpaque(t *testing.T) {
	if got := orchestratorRuntimeStartCursorOpaque(&cerebrov1.SourceRuntime{
		NextCursor: &cerebrov1.SourceCursor{Opaque: "next-page"},
		Checkpoint: &cerebrov1.SourceCheckpoint{
			CursorOpaque: "checkpoint-page",
		},
	}); got != "next-page" {
		t.Fatalf("start cursor = %q, want next-page", got)
	}
	if got := orchestratorRuntimeStartCursorOpaque(&cerebrov1.SourceRuntime{
		Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "checkpoint-page"},
	}); got != "checkpoint-page" {
		t.Fatalf("start cursor = %q, want checkpoint-page", got)
	}
	if got := orchestratorRuntimeStartCursorOpaque(&cerebrov1.SourceRuntime{}); got != "" {
		t.Fatalf("start cursor = %q, want empty", got)
	}
}

func TestRunOrchestratorIterationStopsAfterSyncFailure(t *testing.T) {
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
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	if result.Runtimes[0].FindingRules != "" || result.Runtimes[0].GraphIngest != "" || result.Runtimes[0].GraphRules != "" {
		t.Fatalf("downstream stages ran after sync failure: %#v", result.Runtimes[0])
	}
	if store.leaseID != "runtime-1" || store.releaseID != "runtime-1" {
		t.Fatalf("lease/release = %q/%q, want runtime-1/runtime-1", store.leaseID, store.releaseID)
	}
}

func TestRunOrchestratorIterationPreservesGraphCountersOnPartialFailure(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry(orchestratorNoopRule{})
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := &failingCompletedIngestGraphStore{graphTestStore: newGraphTestStore()}
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
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want graph ingest completion failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "failed" {
		t.Fatalf("graph ingest status = %q, want failed", runtimeResult.GraphIngest)
	}
	if runtimeResult.EntitiesProjected != 6 || runtimeResult.LinksProjected != 7 {
		t.Fatalf("graph counters = %d/%d, want 6/7", runtimeResult.EntitiesProjected, runtimeResult.LinksProjected)
	}
}

func TestRunOrchestratorIterationRunsGraphRulesAfterIngest(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	graphRule := &orchestratorGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "orchestrator-graph-rule", Name: "Orchestrator graph rule"},
		sourceID: "github",
		query: ports.CypherQueryRequest{
			Query:  "MATCH (n) RETURN n LIMIT 1",
			Params: map[string]any{"tenant_id": "writer"},
		},
		emit: []*ports.FindingRecord{
			{
				ID:           "finding-graph-orchestrator-1",
				Fingerprint:  "fp-graph-orchestrator-1",
				TenantID:     "writer",
				RuntimeID:    "runtime-1",
				RuleID:       "orchestrator-graph-rule",
				Title:        "Graph rule fired in orchestrator",
				Severity:     "CRITICAL",
				Status:       "open",
				Summary:      "graph rule emitted via orchestrator",
				ResourceURNs: []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
			},
		},
	}
	ruleRegistry, err := findings.NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := newGraphTestStore()
	graphStore.cypherRows = []ports.CypherRow{
		{Values: map[string]any{"label": "alice@writer.com"}},
	}
	findingService := findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry).WithGraphQueryStore(graphStore)
	graphService := graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore)
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findingService,
		graphService,
		orchestratorOptions{},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "completed" {
		t.Fatalf("graph ingest status = %q, want completed", runtimeResult.GraphIngest)
	}
	if runtimeResult.GraphRules != "completed" {
		t.Fatalf("graph rules status = %q, want completed", runtimeResult.GraphRules)
	}
	if runtimeResult.GraphRuleEvaluations != 1 {
		t.Fatalf("graph rule evaluations = %d, want 1", runtimeResult.GraphRuleEvaluations)
	}
	if runtimeResult.GraphRuleFindings != 1 {
		t.Fatalf("graph rule findings = %d, want 1", runtimeResult.GraphRuleFindings)
	}
	if runtimeResult.GraphRuleRowsRead != 1 {
		t.Fatalf("graph rule rows read = %d, want 1", runtimeResult.GraphRuleRowsRead)
	}
	if runtimeResult.Error != "" {
		t.Fatalf("runtime error = %q, want empty", runtimeResult.Error)
	}
}

func TestRunOrchestratorIterationRunsFindingRulesAfterGraphIngest(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	graphStore := newGraphTestStore()
	resourceURN := "urn:cerebro:writer:github_pull_request:writer/cerebro#515"
	findingRule := &orchestratorResourceAwareRule{
		spec:        &cerebrov1.RuleSpec{Id: "resource-aware-rule", Name: "Resource aware rule"},
		sourceID:    "github",
		graph:       graphStore,
		resourceURN: resourceURN,
	}
	ruleRegistry, err := findings.NewRegistry(findingRule)
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	findingService := findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry).WithGraphStore(graphStore)
	graphService := graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore)

	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findingService,
		graphService,
		orchestratorOptions{},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "completed" || runtimeResult.FindingRules != "completed" {
		t.Fatalf("graph/finding statuses = %q/%q, want completed/completed", runtimeResult.GraphIngest, runtimeResult.FindingRules)
	}
	if !findingRule.sawResource {
		t.Fatal("finding rule ran before graph ingest wrote the source resource")
	}
	linkKey := resourceURN + "|has_finding|urn:cerebro:writer:finding:finding-resource-aware"
	if _, ok := graphStore.links[linkKey]; !ok {
		t.Fatalf("finding resource link %q missing", linkKey)
	}
}

func TestRunOrchestratorIterationReleasesLeaseBeforeGraphIngest(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := &releaseCheckingGraphStore{graphTestStore: newGraphTestStore(), store: store}

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
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	if !graphStore.checked {
		t.Fatal("graph ingest did not project any entities")
	}
	if store.releaseID != "runtime-1" {
		t.Fatalf("releaseID = %q, want runtime-1 before graph ingest", store.releaseID)
	}
	if result.Runtimes[0].GraphIngest != "completed" {
		t.Fatalf("graph ingest status = %q, want completed", result.Runtimes[0].GraphIngest)
	}
}

func TestRunOrchestratorIterationKeepsFindingRulesIndependentOfGraphIngestFailure(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry(orchestratorNoopRule{})
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := &failingProjectionGraphStore{
		graphTestStore: newGraphTestStore(),
		err:            errors.New("neo4j unavailable"),
	}

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
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want graph ingest failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "failed" {
		t.Fatalf("graph ingest status = %q, want failed", runtimeResult.GraphIngest)
	}
	if runtimeResult.FindingRules != "completed" || runtimeResult.EventsEvaluated != 1 {
		t.Fatalf("finding status/events = %q/%d, want completed/1", runtimeResult.FindingRules, runtimeResult.EventsEvaluated)
	}
}

func TestRunOrchestratorIterationSkipsGraphRulesUntilGraphIngestCatchesSyncCursor(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorPagedSource{pages: 3})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	graphRule := &orchestratorGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "orchestrator-graph-rule"},
		sourceID: "github",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1"},
	}
	ruleRegistry, err := findings.NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:         "runtime-1",
			SourceId:   "github",
			TenantId:   "writer",
			NextCursor: &cerebrov1.SourceCursor{Opaque: "2"},
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := newGraphTestStore()
	findingService := findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry).WithGraphQueryStore(graphStore)
	graphService := graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore)

	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findingService,
		graphService,
		orchestratorOptions{PageLimit: 1, GraphPageLimit: 1},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "completed" {
		t.Fatalf("graph ingest status = %q, want completed", runtimeResult.GraphIngest)
	}
	if runtimeResult.GraphRules != "skipped" {
		t.Fatalf("graph rules status = %q, want skipped while graph cursor trails sync cursor", runtimeResult.GraphRules)
	}
	if graphRule.calls != 0 {
		t.Fatalf("graph rule calls = %d, want 0 while graph is still catching up", graphRule.calls)
	}
}

func TestRunOrchestratorIterationAlignsGraphIngestWithSyncPageBudget(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorPagedSource{pages: 3})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
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
		orchestratorOptions{PageLimit: 3, GraphPageLimit: 1},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v, want nil", err)
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.PagesRead != 3 || runtimeResult.EventsAppended != 3 {
		t.Fatalf("sync pages/events = %d/%d, want 3/3", runtimeResult.PagesRead, runtimeResult.EventsAppended)
	}
	if runtimeResult.GraphIngest != "completed" {
		t.Fatalf("graph ingest status = %q, want completed", runtimeResult.GraphIngest)
	}
	runs, err := graphStore.ListIngestRuns(context.Background(), graphstore.IngestRunFilter{RuntimeID: "runtime-1", Status: graphstore.IngestRunStatusCompleted})
	if err != nil {
		t.Fatalf("ListIngestRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("completed ingest runs = %d, want 1", len(runs))
	}
	if runs[0].PagesRead != 3 {
		t.Fatalf("graph ingest pages read = %d, want synced page budget 3 despite graph_page_limit=1", runs[0].PagesRead)
	}
}

func TestRunOrchestratorIterationRunsGraphRulesWhenOnlyRunRecordWriteFails(t *testing.T) {
	// The projection updates the graph BEFORE the trailing PutIngestRun(completed) write, so a
	// transient run-record write failure leaves the graph fresh and graph rules MUST still run.
	// Otherwise new detections and stale auto-resolutions are delayed until the next iteration.
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	graphRule := &orchestratorGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "orchestrator-graph-rule"},
		sourceID: "github",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1"},
	}
	ruleRegistry, err := findings.NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := &failingCompletedIngestGraphStore{graphTestStore: newGraphTestStore()}
	findingService := findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry).WithGraphQueryStore(graphStore)
	graphService := graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore)
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findingService,
		graphService,
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want graph ingest run-record write failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "failed" {
		t.Fatalf("graph ingest status = %q, want failed", runtimeResult.GraphIngest)
	}
	if runtimeResult.EntitiesProjected == 0 || runtimeResult.LinksProjected == 0 {
		t.Fatalf("expected projection counters to be populated despite run-record failure, got %#v", runtimeResult)
	}
	if runtimeResult.GraphRules != "completed" {
		t.Fatalf("graph rules status = %q, want completed (graph is fresh)", runtimeResult.GraphRules)
	}
	if graphRule.calls != 1 {
		t.Fatalf("graph rule should have been called once after fresh projection, got %d calls", graphRule.calls)
	}
}

func TestRunOrchestratorIterationSkipsUnavailableFindingRules(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
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
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.Sync != "completed" {
		t.Fatalf("sync status = %q, want completed", runtimeResult.Sync)
	}
	if runtimeResult.FindingRules != "skipped" {
		t.Fatalf("finding rules status = %q, want skipped", runtimeResult.FindingRules)
	}
	if runtimeResult.GraphIngest != "completed" {
		t.Fatalf("graph ingest status = %q, want completed", runtimeResult.GraphIngest)
	}
	if runtimeResult.Error != "" {
		t.Fatalf("runtime error = %q, want empty", runtimeResult.Error)
	}
}

func TestAcquireOrchestratorRuntimeLeaseClaimsRuntime(t *testing.T) {
	store := &leaseRuntimeStore{acquired: true}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}

	acquired, err := acquireOrchestratorRuntimeLease(context.Background(), store, runtime, "owner-1")
	if err != nil {
		t.Fatalf("acquireOrchestratorRuntimeLease() error = %v", err)
	}
	if !acquired {
		t.Fatal("acquireOrchestratorRuntimeLease() = false, want true")
	}
	if store.leaseID != "runtime-1" || store.leaseOwner != "owner-1" || store.leaseTTL != defaultSourceRuntimeLeaseTTL {
		t.Fatalf("lease = (%q, %q, %s), want runtime-1 owner-1 %s", store.leaseID, store.leaseOwner, store.leaseTTL, defaultSourceRuntimeLeaseTTL)
	}
}

func TestReleaseOrchestratorRuntimeLeaseIgnoresCancellation(t *testing.T) {
	store := &leaseRuntimeStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := releaseOrchestratorRuntimeLease(ctx, store, runtime, "owner-1"); err != nil {
		t.Fatalf("releaseOrchestratorRuntimeLease() error = %v", err)
	}
	if store.releaseContextErr != nil {
		t.Fatalf("release context err = %v, want nil", store.releaseContextErr)
	}
	if !store.releaseHasDeadline {
		t.Fatal("release context has no deadline")
	}
	if time.Until(store.releaseDeadline) > sourceRuntimeLeaseReleaseTimeout {
		t.Fatalf("release deadline = %s, want within %s", store.releaseDeadline, sourceRuntimeLeaseReleaseTimeout)
	}
}

func TestSourceRuntimeLeaseRenewalIntervalUsesHalfTTL(t *testing.T) {
	if got := sourceRuntimeLeaseRenewalInterval(time.Minute); got != 30*time.Second {
		t.Fatalf("sourceRuntimeLeaseRenewalInterval() = %s, want 30s", got)
	}
	if got := sourceRuntimeLeaseRenewalInterval(30 * time.Minute); got != sourceruntime.LeaseRenewalMaxInterval {
		t.Fatalf("sourceRuntimeLeaseRenewalInterval() = %s, want %s", got, sourceruntime.LeaseRenewalMaxInterval)
	}
}

func TestOrchestratorListFilterRequestsAllByDefault(t *testing.T) {
	if got := orchestratorListFilter(ports.SourceRuntimeFilter{}).Limit; got != ^uint32(0) {
		t.Fatalf("orchestratorListFilter(default).Limit = %d, want max uint32", got)
	}
}

func TestOrchestratorListFilterPreservesRuntimeID(t *testing.T) {
	filter := orchestratorListFilter(ports.SourceRuntimeFilter{RuntimeID: "writer-okta-audit", Limit: 1})
	if got := filter.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("orchestratorListFilter().RuntimeID = %q, want writer-okta-audit", got)
	}
}

func TestLeaseRenewalFailureCancelsRuntimeWork(t *testing.T) {
	store := &leaseRuntimeStore{renewed: false}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}
	workCtx, cancelWork := context.WithCancel(context.Background())
	stopRenewal := startOrchestratorRuntimeLeaseRenewalWithTTL(context.Background(), store, runtime, "owner-1", cancelWork, time.Millisecond)

	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime work context was not canceled after lease renewal failed")
	}
	if err := stopRenewal(); err == nil {
		t.Fatal("stopRenewal() error = nil, want lease lost error")
	}
}

func TestRunOrchestratorIterationSkipsLockedRuntime(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: false,
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
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v", err)
	}
	if got := result.Runtimes[0].Sync; got != "skipped" {
		t.Fatalf("runtime sync status = %q, want skipped", got)
	}
}

func TestRunOrchestratorIterationContinuesPastLockedRuntimeWithLimit(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtimes: []*cerebrov1.SourceRuntime{
			{Id: "locked-runtime", SourceId: "missing-source"},
			{Id: "unlocked-runtime", SourceId: "missing-source"},
		},
		acquiredByID: map[string]bool{
			"locked-runtime":   false,
			"unlocked-runtime": true,
		},
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{Filter: ports.SourceRuntimeFilter{Limit: 1}},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want unlocked runtime sync failure")
	}
	if store.listFilter.Limit != 1+sourceRuntimeLeaseOverscanLimit {
		t.Fatalf("list limit = %d, want overscan limit", store.listFilter.Limit)
	}
	if got := len(result.Runtimes); got != 2 {
		t.Fatalf("runtime result count = %d, want locked skip plus unlocked attempt", got)
	}
	if result.Runtimes[0].RuntimeID != "locked-runtime" || result.Runtimes[0].Sync != "skipped" {
		t.Fatalf("first runtime result = %#v, want locked skip", result.Runtimes[0])
	}
	if result.Runtimes[1].RuntimeID != "unlocked-runtime" {
		t.Fatalf("second runtime id = %q, want unlocked-runtime", result.Runtimes[1].RuntimeID)
	}
}

func TestRunOrchestratorIterationStopsBeforeRuntimeWhenContextCanceled(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := runOrchestratorIteration(
		ctx,
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
		t.Fatal("runOrchestratorIteration() error = nil, want context cancellation")
	}
	if got := len(result.Runtimes); got != 0 {
		t.Fatalf("runtime result count = %d, want 0", got)
	}
}

type leaseRuntimeStore struct {
	leaseID            string
	leaseOwner         string
	leaseTTL           time.Duration
	releaseContextErr  error
	releaseHasDeadline bool
	releaseDeadline    time.Time
	acquired           bool
	renewed            bool
}

func (s *leaseRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	s.leaseID = runtimeID
	s.leaseOwner = owner
	s.leaseTTL = ttl
	return s.acquired, nil
}

func (s *leaseRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return s.renewed, nil
}

func (s *leaseRuntimeStore) ReleaseSourceRuntimeLease(ctx context.Context, _ string, _ string) error {
	s.releaseContextErr = ctx.Err()
	s.releaseDeadline, s.releaseHasDeadline = ctx.Deadline()
	return nil
}

type orchestratorRuntimeStore struct {
	runtime      *cerebrov1.SourceRuntime
	runtimes     []*cerebrov1.SourceRuntime
	acquired     bool
	acquiredByID map[string]bool
	listFilter   ports.SourceRuntimeFilter
	leaseID      string
	releaseID    string
}

func (s *orchestratorRuntimeStore) Ping(context.Context) error { return nil }

func (s *orchestratorRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *orchestratorRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	for _, runtime := range s.runtimes {
		if runtime.GetId() == id {
			return runtime, nil
		}
	}
	return s.runtime, nil
}

func (s *orchestratorRuntimeStore) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	s.listFilter = filter
	if len(s.runtimes) > 0 {
		return s.runtimes, nil
	}
	return []*cerebrov1.SourceRuntime{s.runtime}, nil
}

func (s *orchestratorRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, _ string, _ time.Duration) (bool, error) {
	s.leaseID = runtimeID
	if s.acquiredByID != nil {
		return s.acquiredByID[runtimeID], nil
	}
	return s.acquired, nil
}

func (s *orchestratorRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (s *orchestratorRuntimeStore) ReleaseSourceRuntimeLease(_ context.Context, runtimeID string, _ string) error {
	s.releaseID = runtimeID
	return nil
}

type orchestratorTestSource struct{}

func (orchestratorTestSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"}
}

func (orchestratorTestSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (orchestratorTestSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (orchestratorTestSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{
		orchestratorSourceEvent("github-pr-515", map[string]string{
			"author":      "alice",
			"owner":       "writer",
			"pull_number": "515",
			"repository":  "writer/cerebro",
			"state":       "open",
		}),
	}}, nil
}

type orchestratorPagedSource struct {
	pages int
}

func (orchestratorPagedSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"}
}

func (orchestratorPagedSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (orchestratorPagedSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s orchestratorPagedSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	page := 1
	if cursor != nil && cursor.GetOpaque() != "" {
		parsed, err := strconv.Atoi(cursor.GetOpaque())
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		page = parsed
	}
	var nextCursor *cerebrov1.SourceCursor
	if page < s.pages {
		nextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(page + 1)}
	}
	return sourcecdk.Pull{
		Events: []*cerebrov1.EventEnvelope{
			orchestratorSourceEvent("github-pr-page-"+strconv.Itoa(page), map[string]string{
				"author":      "alice-" + strconv.Itoa(page),
				"owner":       "writer",
				"pull_number": strconv.Itoa(500 + page),
				"repository":  "writer/cerebro",
				"state":       "open",
			}),
		},
		NextCursor: nextCursor,
	}, nil
}

func orchestratorSourceEvent(id string, attributes map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.pull_request",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "github/pull_request/v1",
		Payload:    []byte(`{"fixture":true}`),
		Attributes: attributes,
	}
}

type orchestratorNoopRule struct{}

func (orchestratorNoopRule) Spec() *cerebrov1.RuleSpec {
	return &cerebrov1.RuleSpec{Id: "noop-rule", Name: "Noop rule"}
}

func (orchestratorNoopRule) SupportsRuntime(*cerebrov1.SourceRuntime) bool {
	return true
}

func (orchestratorNoopRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

type orchestratorGraphRule struct {
	spec     *cerebrov1.RuleSpec
	sourceID string
	query    ports.CypherQueryRequest
	emit     []*ports.FindingRecord
	calls    int
}

func (r *orchestratorGraphRule) Spec() *cerebrov1.RuleSpec {
	return r.spec
}

func (r *orchestratorGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return runtime != nil && runtime.GetSourceId() == r.sourceID
}

func (r *orchestratorGraphRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *orchestratorGraphRule) QueryFor(*cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	return r.query
}

//nolint:unparam // Test rule implements the graph-rule interface, including the error result.
func (r *orchestratorGraphRule) EvaluateRows(_ context.Context, _ *cerebrov1.SourceRuntime, _ []ports.CypherRow) ([]*ports.FindingRecord, error) {
	r.calls++
	return r.emit, nil
}

type orchestratorResourceAwareRule struct {
	spec        *cerebrov1.RuleSpec
	sourceID    string
	graph       *graphTestStore
	resourceURN string
	sawResource bool
}

func (r *orchestratorResourceAwareRule) Spec() *cerebrov1.RuleSpec {
	return r.spec
}

func (r *orchestratorResourceAwareRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return runtime != nil && runtime.GetSourceId() == r.sourceID
}

func (r *orchestratorResourceAwareRule) Evaluate(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	r.graph.mu.Lock()
	_, ok := r.graph.entities[r.resourceURN]
	r.graph.mu.Unlock()
	r.sawResource = ok
	if !ok {
		return nil, errors.New("resource graph entity missing before finding evaluation")
	}
	return []*ports.FindingRecord{{
		ID:           "finding-resource-aware",
		Fingerprint:  "fp-resource-aware",
		TenantID:     runtime.GetTenantId(),
		RuntimeID:    runtime.GetId(),
		RuleID:       r.spec.GetId(),
		Title:        "Resource-aware finding",
		Severity:     "HIGH",
		Status:       "open",
		Summary:      "resource-aware finding",
		ResourceURNs: []string{r.resourceURN},
		EventIDs:     []string{event.GetId()},
	}}, nil
}

type orchestratorEventLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *orchestratorEventLog) Ping(context.Context) error {
	return nil
}

func (l *orchestratorEventLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func (l *orchestratorEventLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	events := make([]*cerebrov1.EventEnvelope, 0, len(l.events))
	for _, event := range l.events {
		if request.RuntimeID != "" && event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != request.RuntimeID {
			continue
		}
		if request.TenantID != "" && event.GetTenantId() != request.TenantID {
			continue
		}
		if request.KindPrefix != "" && !strings.HasPrefix(event.GetKind(), request.KindPrefix) {
			continue
		}
		events = append(events, event)
		if request.Limit > 0 && uint32(len(events)) >= request.Limit { // #nosec G115 -- replay fixture size is bounded by in-memory test setup.
			break
		}
	}
	return events, nil
}

type orchestratorFindingStore struct{}

func (s *orchestratorFindingStore) Ping(context.Context) error { return nil }

func (s *orchestratorFindingStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	return finding, nil
}

func (s *orchestratorFindingStore) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) ListFindings(context.Context, ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) UpdateFindingStatus(context.Context, ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) UpdateFindingAssignee(context.Context, ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) UpdateFindingDueDate(context.Context, ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) AddFindingNote(context.Context, ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) LinkFindingTicket(context.Context, ports.FindingTicketLink) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) LinkFindingExternalRef(context.Context, ports.FindingExternalRefLink) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) PutFindingEvaluationRun(context.Context, *cerebrov1.FindingEvaluationRun) error {
	return nil
}

func (s *orchestratorFindingStore) GetFindingEvaluationRun(context.Context, string) (*cerebrov1.FindingEvaluationRun, error) {
	return nil, ports.ErrFindingEvaluationRunNotFound
}

func (s *orchestratorFindingStore) ListFindingEvaluationRuns(context.Context, ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) PutFindingEvidence(context.Context, *cerebrov1.FindingEvidence) error {
	return nil
}

func (s *orchestratorFindingStore) GetFindingEvidence(context.Context, string) (*cerebrov1.FindingEvidence, error) {
	return nil, ports.ErrFindingEvidenceNotFound
}

func (s *orchestratorFindingStore) ListFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	return claim, nil
}

func (s *orchestratorFindingStore) ListClaims(context.Context, ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	return nil, nil
}

type failingCompletedIngestGraphStore struct {
	*graphTestStore
}

func (s *failingCompletedIngestGraphStore) PutIngestRun(ctx context.Context, run graphstore.IngestRun) error {
	if run.Status == graphstore.IngestRunStatusCompleted {
		return errors.New("run completion failed")
	}
	return s.graphTestStore.PutIngestRun(ctx, run)
}

type failingProjectionGraphStore struct {
	*graphTestStore
	err error
}

func (s *failingProjectionGraphStore) UpsertProjectedEntity(context.Context, *ports.ProjectedEntity) error {
	return s.err
}

type releaseCheckingGraphStore struct {
	*graphTestStore
	store   *orchestratorRuntimeStore
	checked bool
}

func (s *releaseCheckingGraphStore) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	s.checked = true
	if s.store.releaseID == "" {
		return errors.New("graph ingest started before runtime lease release")
	}
	return s.graphTestStore.UpsertProjectedEntity(ctx, entity)
}
