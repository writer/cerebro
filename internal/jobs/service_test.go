package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestCreateRejectsUnsupportedKind(t *testing.T) {
	service := New(newMemoryJobStore())
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return nil, nil, nil
	})

	_, _, err := service.Create(context.Background(), ports.CreateJobRequest{Kind: KindGraphRebuildDryRun})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create unsupported kind error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestCreateRejectsIdempotencyKeyWithDifferentRequest(t *testing.T) {
	service := New(newMemoryJobStore())
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return nil, nil, nil
	})
	first := ports.CreateJobRequest{Kind: KindReportRun, TenantID: "tenant-a", IdempotencyKey: "same-key", Payload: map[string]any{"report_id": "one"}}
	job, created, err := service.Create(context.Background(), first)
	if err != nil || !created {
		t.Fatalf("Create(first) job=%+v created=%v error=%v", job, created, err)
	}
	reused, created, err := service.Create(context.Background(), first)
	if err != nil || created || reused.ID != job.ID {
		t.Fatalf("Create(reuse) job=%+v created=%v error=%v", reused, created, err)
	}
	_, _, err = service.Create(context.Background(), ports.CreateJobRequest{Kind: KindReportRun, TenantID: "tenant-a", IdempotencyKey: "same-key", Payload: map[string]any{"report_id": "two"}})
	if !errors.Is(err, ports.ErrJobIdempotencyConflict) {
		t.Fatalf("Create(conflict) error = %v, want ErrJobIdempotencyConflict", err)
	}
}

func TestCancelDoesNotOverwriteTerminalJob(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-complete"] = &ports.Job{ID: "job-complete", Kind: KindReportRun, Status: ports.JobStatusCompleted}
	service := New(store)

	job, err := service.Cancel(context.Background(), "job-complete")
	if err != nil {
		t.Fatalf("Cancel terminal job error = %v", err)
	}
	if job.Status != ports.JobStatusCompleted {
		t.Fatalf("status = %q, want %q", job.Status, ports.JobStatusCompleted)
	}
	if got := len(store.events); got != 0 {
		t.Fatalf("events = %d, want 0", got)
	}
}

func TestCancelRunningJobRequestsCancellationWithoutTerminalTransition(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-running"] = &ports.Job{ID: "job-running", Kind: KindReportRun, Status: ports.JobStatusRunning}
	service := New(store)

	job, err := service.Cancel(context.Background(), "job-running")
	if err != nil {
		t.Fatalf("Cancel running job error = %v", err)
	}
	if job.Status != ports.JobStatusRunning {
		t.Fatalf("status = %q, want %q", job.Status, ports.JobStatusRunning)
	}
	if !job.CancelRequested {
		t.Fatal("CancelRequested = false, want true")
	}
	if len(store.events) != 1 || store.events[0].Type != "cancellation_requested" {
		t.Fatalf("events = %#v, want one cancellation_requested event", store.events)
	}
}

func TestRunRecoversRunnerPanicAndMarksJobFailed(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-panic"] = &ports.Job{ID: "job-panic", Kind: KindReportRun, Status: ports.JobStatusQueued}
	service := New(store)
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		panic("boom")
	})

	err := service.Run(context.Background(), "job-panic")
	if !errors.Is(err, ErrJobPanic) {
		t.Fatalf("Run panic error = %v, want job panic", err)
	}
	job, err := store.GetJob(context.Background(), "job-panic")
	if err != nil {
		t.Fatalf("GetJob error = %v", err)
	}
	if job.Status != ports.JobStatusFailed {
		t.Fatalf("status = %q, want %q", job.Status, ports.JobStatusFailed)
	}
	if job.Error != "job panic: boom" {
		t.Fatalf("job error = %q, want panic detail", job.Error)
	}
	if len(store.events) < 2 || store.events[len(store.events)-1].Type != "failed" {
		t.Fatalf("events = %#v, want final failed event", store.events)
	}
}

func TestRunEmitsPlatformJobWideEventWithoutPayloadValues(t *testing.T) {
	createdAt := time.Date(2026, 6, 18, 21, 0, 0, 0, time.UTC)
	store := newMemoryJobStore()
	store.jobs["job-telemetry"] = &ports.Job{
		ID:             "job-telemetry",
		Kind:           KindSourceRuntimeOrchestrate,
		Status:         ports.JobStatusQueued,
		TenantID:       "writer",
		SubjectType:    "source_runtime",
		SubjectID:      "writer-okta-audit",
		IdempotencyKey: "idem-secret-value",
		Payload: map[string]any{
			"runtime_id": "writer-okta-audit",
			"api_token":  "raw-secret-token-value",
		},
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}
	service := New(store)
	now := createdAt
	service.now = func() time.Time {
		now = now.Add(2 * time.Second)
		return now
	}
	service.WithRunner(KindSourceRuntimeOrchestrate, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return map[string]any{
			"events_appended": 25,
			"private_result":  "raw-result-private-value",
		}, map[string]string{"graph_ingest_run_id": "graph-run-1"}, nil
	})

	stderr := captureJobServiceStderr(t, func() {
		if err := service.Run(context.Background(), "job-telemetry"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	})

	payload := jobTelemetrySpanEndPayload(t, stderr, "platform.job.run")
	for key, want := range map[string]any{
		"main":                  true,
		"wide_event":            true,
		"event.dataset":         "cerebro.wide_events",
		"job.id":                "job-telemetry",
		"job.kind":              KindSourceRuntimeOrchestrate,
		"job.status.final":      ports.JobStatusCompleted,
		"job_id":                "job-telemetry",
		"job_kind":              KindSourceRuntimeOrchestrate,
		"job_status":            ports.JobStatusCompleted,
		"tenant_id":             "writer",
		"runtime_id":            "writer-okta-audit",
		"source_runtime_id":     "writer-okta-audit",
		"job.payload.key_count": float64(2),
		"job.payload.keys":      "api_token,runtime_id",
		"job.result.key_count":  float64(2),
		"job.result.keys":       "events_appended,private_result",
		"job.result_ref.keys":   "graph_ingest_run_id",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if got, ok := payload["job.queue_latency_ms"].(float64); !ok || got <= 0 {
		t.Fatalf("job.queue_latency_ms = %#v, want positive number; payload=%#v", payload["job.queue_latency_ms"], payload)
	}
	if got, ok := payload["job.run_duration_ms"].(float64); !ok || got <= 0 {
		t.Fatalf("job.run_duration_ms = %#v, want positive number; payload=%#v", payload["job.run_duration_ms"], payload)
	}
	if strings.Contains(stderr, "raw-secret-token-value") || strings.Contains(stderr, "raw-result-private-value") || strings.Contains(stderr, "idem-secret-value") {
		t.Fatalf("platform job telemetry leaked raw payload/result/idempotency values: %s", stderr)
	}
	if !strings.Contains(stderr, `"name":"platform.job.started"`) || !strings.Contains(stderr, `"name":"platform.job.completed"`) {
		t.Fatalf("platform job lifecycle events missing from stderr: %s", stderr)
	}
}

func TestRunEmitsSinglePlatformJobFailedEvent(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-failed-telemetry"] = &ports.Job{
		ID:     "job-failed-telemetry",
		Kind:   KindReportRun,
		Status: ports.JobStatusQueued,
	}
	service := New(store)
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return nil, nil, errors.New("runner failed")
	})

	stderr := captureJobServiceStderr(t, func() {
		if err := service.Run(context.Background(), "job-failed-telemetry"); err == nil {
			t.Fatal("Run() error = nil, want runner failure")
		}
	})

	failedEvents := jobTelemetryPayloads(t, stderr, "event", "platform.job.failed")
	if len(failedEvents) != 1 {
		t.Fatalf("platform.job.failed events = %d, want 1; stderr=%s", len(failedEvents), stderr)
	}
	runPayload := jobTelemetrySpanEndPayload(t, stderr, "platform.job.run")
	if got := runPayload["job.status.final"]; got != ports.JobStatusFailed {
		t.Fatalf("job.status.final = %#v, want %q; payload=%#v", got, ports.JobStatusFailed, runPayload)
	}
}

func TestRunReportTelemetryFallsBackToSubjectID(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-report-telemetry"] = &ports.Job{
		ID:          "job-report-telemetry",
		Kind:        KindReportRun,
		Status:      ports.JobStatusQueued,
		SubjectType: "report",
		SubjectID:   "report-subject-id",
		Payload:     map[string]any{"report_id": "   "},
	}
	service := New(store)
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return nil, nil, nil
	})

	stderr := captureJobServiceStderr(t, func() {
		if err := service.Run(context.Background(), "job-report-telemetry"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	})

	payload := jobTelemetrySpanEndPayload(t, stderr, "platform.job.run")
	if got := payload["report_id"]; got != "report-subject-id" {
		t.Fatalf("report_id = %#v, want SubjectID fallback; payload=%#v", got, payload)
	}
}

func TestStartAsyncDetachesFromRequestAndWaitCancelsJob(t *testing.T) {
	store := newMemoryJobStore()
	service := New(store)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	service.WithRunner(KindReportRun, func(ctx context.Context, _ *ports.Job, _ *Service) (map[string]any, map[string]string, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, nil, ctx.Err()
	})
	job, created, err := service.Create(context.Background(), ports.CreateJobRequest{Kind: KindReportRun})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created {
		t.Fatal("created = false, want true")
	}
	requestCtx, requestCancel := context.WithCancel(context.Background())
	requestCancel()
	service.StartAsync(requestCtx, job)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("async job did not start after request context cancellation")
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := service.Wait(waitCtx); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("runner did not observe service cancellation")
	}
}

func TestRunCancellationTransitionsLeasedJobToCancelled(t *testing.T) {
	store := newMemoryJobStore()
	service := New(store).WithLeaseTiming(200*time.Millisecond, 20*time.Millisecond)
	started := make(chan struct{})
	service.WithRunner(KindReportRun, func(ctx context.Context, _ *ports.Job, _ *Service) (map[string]any, map[string]string, error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})
	job, _, err := service.Create(context.Background(), ports.CreateJobRequest{Kind: KindReportRun})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	service.StartAsync(context.Background(), job)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	if _, err := service.Cancel(context.Background(), job.ID); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stored, getErr := store.GetJob(context.Background(), job.ID)
		if getErr != nil {
			t.Fatalf("GetJob() error = %v", getErr)
		}
		if stored.Status == ports.JobStatusCancelled {
			if stored.LeaseOwner != "" || !stored.LeaseExpiresAt.IsZero() {
				t.Fatalf("cancelled job retained lease: %+v", stored)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not transition to cancelled")
}

func TestRecoverRestartsExpiredLeasedJob(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryJobStore()
	store.jobs["job-expired"] = &ports.Job{
		ID:             "job-expired",
		Kind:           KindReportRun,
		Status:         ports.JobStatusRunning,
		Attempt:        1,
		LeaseOwner:     "dead-worker",
		LeaseExpiresAt: now.Add(-time.Minute),
	}
	service := New(store)
	service.now = func() time.Time { return now }
	completed := make(chan struct{})
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		close(completed)
		return nil, nil, nil
	})

	count, err := service.Recover(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("Recover() count = %d, want 1", count)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("recovered job did not execute")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stored, getErr := store.GetJob(context.Background(), "job-expired")
		if getErr != nil {
			t.Fatalf("GetJob() error = %v", getErr)
		}
		if stored.Status == ports.JobStatusCompleted {
			if stored.Attempt != 2 {
				t.Fatalf("attempt = %d, want 2", stored.Attempt)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("recovered job did not complete")
}

func TestRecoverMarksMissingRunnerTerminalBeforeNextBatch(t *testing.T) {
	store := &boundedRecoveryJobStore{
		memoryJobStore: newMemoryJobStore(),
		order:          []string{"job-orphan", "job-valid"},
	}
	store.jobs["job-orphan"] = &ports.Job{ID: "job-orphan", Kind: "removed_job_kind", Status: ports.JobStatusQueued}
	store.jobs["job-valid"] = &ports.Job{ID: "job-valid", Kind: KindReportRun, Status: ports.JobStatusQueued}
	service := New(store)
	completed := make(chan struct{})
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		close(completed)
		return nil, nil, nil
	})

	count, err := service.Recover(context.Background(), 1)
	if err != nil {
		t.Fatalf("Recover(orphan) error = %v", err)
	}
	if count != 1 {
		t.Fatalf("Recover(orphan) count = %d, want 1", count)
	}
	waitForJobStatus(t, store.memoryJobStore, "job-orphan", ports.JobStatusFailed)
	orphan, err := store.GetJob(context.Background(), "job-orphan")
	if err != nil {
		t.Fatalf("GetJob(orphan) error = %v", err)
	}
	if orphan.FailureClass != JobFailurePermanent || orphan.Error != "job runner unavailable" {
		t.Fatalf("orphan job = %+v, want permanent runner-unavailable failure", orphan)
	}

	count, err = service.Recover(context.Background(), 1)
	if err != nil {
		t.Fatalf("Recover(valid) error = %v", err)
	}
	if count != 1 {
		t.Fatalf("Recover(valid) count = %d, want 1", count)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("valid job behind orphan did not execute")
	}
	waitForJobStatus(t, store.memoryJobStore, "job-valid", ports.JobStatusCompleted)
}

func TestRunClassifiesRetryableFailure(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-retryable"] = &ports.Job{ID: "job-retryable", Kind: KindReportRun, Status: ports.JobStatusQueued}
	service := New(store)
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		return nil, nil, Retryable(errors.New("temporary dependency failure"))
	})

	if err := service.Run(context.Background(), "job-retryable"); err == nil {
		t.Fatal("Run() error = nil, want retryable failure")
	}
	stored, err := store.GetJob(context.Background(), "job-retryable")
	if err != nil {
		t.Fatalf("GetJob() error = %v", err)
	}
	if stored.Status != ports.JobStatusFailed || stored.FailureClass != JobFailureRetryable {
		t.Fatalf("job = %+v, want failed/retryable", stored)
	}
}

func TestRunRenewsLeaseDuringLongExecution(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-heartbeat"] = &ports.Job{ID: "job-heartbeat", Kind: KindReportRun, Status: ports.JobStatusQueued}
	service := New(store).WithLeaseTiming(100*time.Millisecond, 10*time.Millisecond)
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		time.Sleep(35 * time.Millisecond)
		return nil, nil, nil
	})

	if err := service.Run(context.Background(), "job-heartbeat"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	store.mu.Lock()
	renewCount := store.renewCount
	store.mu.Unlock()
	if renewCount == 0 {
		t.Fatal("job lease was not renewed")
	}
}

func TestRunCannotCompleteAfterLeaseOwnershipChanges(t *testing.T) {
	store := newMemoryJobStore()
	store.jobs["job-stale-worker"] = &ports.Job{ID: "job-stale-worker", Kind: KindReportRun, Status: ports.JobStatusQueued}
	service := New(store).WithLeaseTiming(time.Second, 500*time.Millisecond)
	started := make(chan struct{})
	release := make(chan struct{})
	service.WithRunner(KindReportRun, func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error) {
		close(started)
		<-release
		return nil, nil, nil
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(context.Background(), "job-stale-worker")
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	store.mu.Lock()
	store.jobs["job-stale-worker"].LeaseOwner = "replacement-worker"
	store.mu.Unlock()
	close(release)
	if err := <-errCh; !errors.Is(err, ports.ErrJobUpdateConflict) {
		t.Fatalf("Run() error = %v, want ErrJobUpdateConflict", err)
	}
	stored, err := store.GetJob(context.Background(), "job-stale-worker")
	if err != nil {
		t.Fatalf("GetJob() error = %v", err)
	}
	if stored.Status != ports.JobStatusRunning || stored.LeaseOwner != "replacement-worker" {
		t.Fatalf("stale worker changed job: %+v", stored)
	}
}

type memoryJobStore struct {
	mu         sync.Mutex
	nextID     int
	jobs       map[string]*ports.Job
	events     []*ports.JobEvent
	renewCount int
}

type boundedRecoveryJobStore struct {
	*memoryJobStore
	order []string
}

func (s *boundedRecoveryJobStore) RecoverJobs(_ context.Context, request ports.JobRecoveryRequest) ([]*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := request.Limit
	if limit == 0 {
		limit = ^uint32(0)
	}
	jobs := make([]*ports.Job, 0, len(s.order))
	var recovered uint32
	for _, id := range s.order {
		job := s.jobs[id]
		if job == nil || job.Status != ports.JobStatusQueued || job.CancelRequested {
			continue
		}
		jobs = append(jobs, cloneJob(job))
		recovered++
		if recovered == limit {
			break
		}
	}
	return jobs, nil
}

func newMemoryJobStore() *memoryJobStore {
	return &memoryJobStore{jobs: map[string]*ports.Job{}, nextID: 1}
}

func (s *memoryJobStore) Ping(context.Context) error {
	return nil
}

func (s *memoryJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.IdempotencyKey != "" {
		for _, existing := range s.jobs {
			if existing.TenantID == request.TenantID && existing.IdempotencyKey == request.IdempotencyKey {
				if existing.RequestHash != request.RequestHash {
					return nil, false, ports.ErrJobIdempotencyConflict
				}
				return cloneJob(existing), false, nil
			}
		}
	}
	id := "job-test"
	if s.nextID > 1 {
		id = fmt.Sprintf("job-test-%d", s.nextID)
	}
	s.nextID++
	job := &ports.Job{
		ID:             id,
		Kind:           request.Kind,
		Status:         ports.JobStatusQueued,
		TenantID:       request.TenantID,
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		IdempotencyKey: request.IdempotencyKey,
		RequestHash:    request.RequestHash,
		Payload:        cloneAnyMap(request.Payload),
	}
	s.jobs[id] = cloneJob(job)
	return cloneJob(job), true, nil
}

func (s *memoryJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, ports.ErrJobNotFound
	}
	return cloneJob(job), nil
}

func (s *memoryJobStore) ListJobs(context.Context, ports.JobFilter) ([]*ports.Job, error) {
	return nil, nil
}

func (s *memoryJobStore) CountJobs(context.Context, ports.JobFilter) (uint64, error) {
	return 0, nil
}

func (s *memoryJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, ports.ErrJobNotFound
	}
	if len(update.AllowedStatuses) > 0 && !containsStatus(update.AllowedStatuses, job.Status) {
		return nil, ports.ErrJobUpdateConflict
	}
	if update.ExpectedLeaseOwner != "" && update.ExpectedLeaseOwner != job.LeaseOwner {
		return nil, ports.ErrJobUpdateConflict
	}
	if update.RequireNotCancelled && job.CancelRequested {
		return nil, ports.ErrJobUpdateConflict
	}
	if update.Status != "" {
		job.Status = update.Status
	}
	if update.Progress != nil {
		job.Progress = *update.Progress
	}
	if update.Message != "" {
		job.Message = update.Message
	}
	if update.Error != "" {
		job.Error = update.Error
	}
	if update.FailureClass != "" {
		job.FailureClass = update.FailureClass
	}
	if update.Result != nil {
		job.Result = cloneAnyMap(update.Result)
	}
	if update.ResultRefs != nil {
		job.ResultRefs = cloneStringMap(update.ResultRefs)
	}
	if update.StartedAt != nil {
		job.StartedAt = *update.StartedAt
	}
	if update.FinishedAt != nil {
		job.FinishedAt = *update.FinishedAt
	}
	if update.CancelRequested != nil {
		job.CancelRequested = *update.CancelRequested
	}
	if update.ClearLease {
		job.LeaseOwner = ""
		job.LeaseExpiresAt = time.Time{}
		job.HeartbeatAt = time.Time{}
	}
	return cloneJob(job), nil
}

func (s *memoryJobStore) ClaimJob(_ context.Context, request ports.JobClaimRequest) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[request.JobID]
	if !ok {
		return nil, ports.ErrJobNotFound
	}
	now := request.Now.UTC()
	claimable := job.Status == ports.JobStatusQueued || (job.Status == ports.JobStatusRunning && (job.LeaseExpiresAt.IsZero() || !job.LeaseExpiresAt.After(now)))
	if !claimable || job.CancelRequested {
		return nil, ports.ErrJobLeaseConflict
	}
	job.Status = ports.JobStatusRunning
	job.Attempt++
	job.LeaseOwner = request.Owner
	job.LeaseExpiresAt = now.Add(request.TTL)
	job.HeartbeatAt = now
	if job.StartedAt.IsZero() {
		job.StartedAt = now
	}
	return cloneJob(job), nil
}

func (s *memoryJobStore) RenewJobLease(_ context.Context, request ports.JobLeaseRenewRequest) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[request.JobID]
	if !ok {
		return nil, ports.ErrJobNotFound
	}
	if job.Status != ports.JobStatusRunning || job.LeaseOwner != request.Owner || !job.LeaseExpiresAt.After(request.Now) {
		return nil, ports.ErrJobLeaseConflict
	}
	job.HeartbeatAt = request.Now
	job.LeaseExpiresAt = request.Now.Add(request.TTL)
	s.renewCount++
	return cloneJob(job), nil
}

func (s *memoryJobStore) RecoverJobs(_ context.Context, request ports.JobRecoveryRequest) ([]*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := make([]*ports.Job, 0)
	for _, job := range s.jobs {
		if job.Status == ports.JobStatusRunning && (job.LeaseExpiresAt.IsZero() || !job.LeaseExpiresAt.After(request.Now)) {
			job.Status = ports.JobStatusQueued
			job.LeaseOwner = ""
			job.LeaseExpiresAt = time.Time{}
			job.HeartbeatAt = time.Time{}
		}
		if job.Status == ports.JobStatusQueued && !job.CancelRequested {
			jobs = append(jobs, cloneJob(job))
		}
	}
	return jobs, nil
}

func (s *memoryJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := event
	s.events = append(s.events, &cloned)
	return &cloned, nil
}

func (s *memoryJobStore) ListJobEvents(context.Context, string, uint32) ([]*ports.JobEvent, error) {
	return nil, nil
}

func containsStatus(values []string, status string) bool {
	for _, value := range values {
		if value == status {
			return true
		}
	}
	return false
}

func cloneJob(job *ports.Job) *ports.Job {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.Payload = cloneAnyMap(job.Payload)
	cloned.Result = cloneAnyMap(job.Result)
	cloned.ResultRefs = cloneStringMap(job.ResultRefs)
	return &cloned
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func waitForJobStatus(t *testing.T, store *memoryJobStore, jobID string, status string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err := store.GetJob(context.Background(), jobID)
		if err != nil {
			t.Fatalf("GetJob(%s) error = %v", jobID, err)
		}
		if job.Status == status {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not transition to %s", jobID, status)
}

func captureJobServiceStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func jobTelemetrySpanEndPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	payloads := jobTelemetryPayloads(t, stderr, "span_end", name)
	if len(payloads) > 0 {
		return payloads[0]
	}
	t.Fatalf("telemetry span_end %q not found in stderr: %s", name, stderr)
	return nil
}

func jobTelemetryPayloads(t *testing.T, stderr string, kind string, name string) []map[string]any {
	t.Helper()
	payloads := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", line, err)
		}
		if payload["kind"] == kind && payload["name"] == name {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}
