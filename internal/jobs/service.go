package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

var (
	ErrInvalidRequest     = errors.New("invalid job request")
	ErrRuntimeUnavailable = errors.New("job runtime is unavailable")
	ErrJobPanic           = errors.New("job panic")
)

const (
	defaultLeaseTTL          = 30 * time.Second
	defaultHeartbeatInterval = 10 * time.Second
	defaultRecoveryBatch     = uint32(100)
	defaultRecoveryInterval  = 15 * time.Second

	JobFailurePermanent = "permanent"
	JobFailureRetryable = "retryable"
	JobFailureCancelled = "cancelled"

	KindSourceRuntimeSync         = "source_runtime_sync"
	KindSourceRuntimeOrchestrate  = "source_runtime_orchestrate"
	KindGraphIngestRuntime        = "graph_ingest_runtime"
	KindFindingRulesEvaluate      = "finding_rules_evaluate"
	KindFindingCandidatesEvaluate = "finding_candidates_evaluate"
	KindFindingsEvaluate          = "findings_evaluate"
	KindReportRun                 = "report_run"
	KindVulnDBSyncJobRun          = "vulndb_sync_job_run"
	KindGraphRebuildDryRun        = "graph_rebuild_dry_run"
	KindAppendLogRuntimeIndex     = "append_log_runtime_index"
	KindProactiveFindingTriage    = "proactive_finding_triage"
	KindGRCUpload                 = "grc_upload"
	KindComplianceAssessment      = "compliance_assessment"
)

type Runner func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error)

type retryableJobError struct {
	err error
}

func (e retryableJobError) Error() string { return e.err.Error() }
func (e retryableJobError) Unwrap() error { return e.err }

// Retryable marks an execution failure safe for an explicit retry policy.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableJobError{err: err}
}

type Service struct {
	store             ports.JobStore
	runners           map[string]Runner
	now               func() time.Time
	nextAsyncID       uint64
	asyncCancels      map[uint64]context.CancelFunc
	jobCancels        map[string]context.CancelFunc
	leaseTTL          time.Duration
	heartbeatInterval time.Duration
	wg                sync.WaitGroup
	mu                sync.Mutex
}

func New(store ports.JobStore) *Service {
	return &Service{
		store:             store,
		runners:           map[string]Runner{},
		now:               func() time.Time { return time.Now().UTC() },
		asyncCancels:      map[uint64]context.CancelFunc{},
		jobCancels:        map[string]context.CancelFunc{},
		leaseTTL:          defaultLeaseTTL,
		heartbeatInterval: defaultHeartbeatInterval,
	}
}

func (s *Service) WithRunner(kind string, runner Runner) *Service {
	if s == nil {
		return nil
	}
	kind = strings.TrimSpace(kind)
	if kind == "" || runner == nil {
		return s
	}
	s.runners[kind] = runner
	return s
}

// WithLeaseTiming overrides worker lease timing. Production uses the defaults;
// focused tests use shorter intervals to exercise renewal and cancellation.
func (s *Service) WithLeaseTiming(ttl time.Duration, heartbeatInterval time.Duration) *Service {
	if s == nil {
		return nil
	}
	if ttl > 0 {
		s.leaseTTL = ttl
		if s.heartbeatInterval >= ttl {
			s.heartbeatInterval = ttl / 3
			if s.heartbeatInterval <= 0 {
				s.heartbeatInterval = ttl
			}
		}
	}
	if heartbeatInterval > 0 && heartbeatInterval < s.leaseTTL {
		s.heartbeatInterval = heartbeatInterval
	}
	return s
}

func (s *Service) Create(ctx context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	if s == nil || s.store == nil {
		return nil, false, ErrRuntimeUnavailable
	}
	request.Kind = strings.TrimSpace(request.Kind)
	if request.Kind == "" {
		return nil, false, fmt.Errorf("%w: kind is required", ErrInvalidRequest)
	}
	if s.runners[request.Kind] == nil {
		return nil, false, fmt.Errorf("%w: unsupported job kind %q", ErrInvalidRequest, request.Kind)
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.SubjectType = strings.TrimSpace(request.SubjectType)
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.Payload == nil {
		request.Payload = map[string]any{}
	}
	requestHash, err := jobRequestHash(request)
	if err != nil {
		return nil, false, fmt.Errorf("%w: hash request: %w", ErrInvalidRequest, err)
	}
	request.RequestHash = requestHash
	job, created, err := s.store.CreateJob(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if created {
		appendJobEventLogged(ctx, s.store, ports.JobEvent{JobID: job.ID, Type: "created", Status: job.Status, Message: "job created"})
	}
	eventName := "platform.job.reused"
	if created {
		eventName = "platform.job.created"
	}
	telemetry.Event(ctx, eventName, jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "job.created", Value: created},
		telemetry.Field{Key: "job.idempotency_key.present", Value: request.IdempotencyKey != ""},
		telemetry.Field{Key: "job.idempotency_key.hash", Value: hashText(request.IdempotencyKey)},
	)))
	return job, created, nil
}

func (s *Service) StartAsync(ctx context.Context, job *ports.Job) { //nolint:contextcheck // Async jobs intentionally outlive request cancellation while preserving context values.
	if s == nil || job == nil {
		return
	}
	if ctx == nil {
		return
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.nextAsyncID++
	asyncID := s.nextAsyncID
	if s.asyncCancels == nil {
		s.asyncCancels = map[uint64]context.CancelFunc{}
	}
	s.asyncCancels[asyncID] = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.asyncCancels, asyncID)
			s.mu.Unlock()
			s.wg.Done()
		}()
		telemetry.Event(runCtx, "platform.job.async_started", jobTelemetryAttrs(job).WithField(telemetry.Field{Key: "job.async_id", Value: asyncID}))
		_ = s.Run(runCtx, job.ID)
	}()
}

func (s *Service) Wait(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.asyncCancels))
	for _, cancel := range s.asyncCancels {
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	select {
	case <-done:
		return nil
	case <-ctxDone:
		return ctx.Err()
	}
}

// Recover resets expired leases and starts queued work. Claiming remains atomic,
// so multiple replicas may call Recover safely during startup.
func (s *Service) Recover(ctx context.Context, limit uint32) (int, error) {
	if s == nil || s.store == nil {
		return 0, ErrRuntimeUnavailable
	}
	leaseStore, ok := s.store.(ports.JobLeaseStore)
	if !ok {
		return 0, ErrRuntimeUnavailable
	}
	if limit == 0 {
		limit = defaultRecoveryBatch
	}
	queued, err := leaseStore.RecoverJobs(ctx, ports.JobRecoveryRequest{Now: s.now(), Limit: limit})
	if err != nil {
		return 0, err
	}
	for _, job := range queued {
		s.StartAsync(ctx, job)
	}
	return len(queued), nil
}

// StartRecovery periodically resumes expired and queued work until cancellation.
func (s *Service) StartRecovery(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	if s == nil {
		close(done)
		return done
	}
	if _, ok := s.store.(ports.JobLeaseStore); !ok {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(defaultRecoveryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.Recover(ctx, 0); err != nil && ctx.Err() == nil && logf != nil {
					logf("recover platform jobs: %v", err)
				}
			}
		}
	}()
	return done
}

// Run claims and executes one job. Stores that implement JobLeaseStore get
// owner-checked completion, heartbeat, cancellation, and crash recovery.
func (s *Service) Run(ctx context.Context, jobID string) error {
	if s == nil || s.store == nil {
		return ErrRuntimeUnavailable
	}
	leaseStore, ok := s.store.(ports.JobLeaseStore)
	if !ok {
		return s.runWithoutLease(ctx, jobID)
	}
	return s.runWithLease(ctx, jobID, leaseStore)
}

func (s *Service) runWithLease(ctx context.Context, jobID string, leaseStore ports.JobLeaseStore) (err error) {
	job, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	ctx, span := telemetry.StartMain(ctx, "platform.job.run", jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "operation.type", Value: "platform_job"},
		telemetry.Field{Key: "workload.kind", Value: "platform_job"},
		telemetry.Field{Key: "job.name", Value: job.Kind},
		telemetry.Field{Key: "job.status.initial", Value: job.Status},
	)))
	status := "failed"
	spanAttrs := telemetry.Attrs()
	startedAt := time.Time{}
	leaseOwner := newJobLeaseOwner()
	defer func() {
		if recovered := recover(); recovered != nil {
			status = ports.JobStatusFailed
			panicErr := fmt.Errorf("%w: %v", ErrJobPanic, recovered)
			spanAttrs = spanAttrs.With(telemetry.Attrs(
				telemetry.Field{Key: "job.panic", Value: true},
				telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(panicErr)},
				telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("platform.job.run", panicErr, jobTelemetryAttrs(job))},
			))
			err = s.failPanickedLeasedJob(context.WithoutCancel(ctx), jobID, leaseOwner, recovered)
		}
		if job != nil {
			spanAttrs = spanAttrs.With(jobTelemetryAttrs(job))
		}
		if !startedAt.IsZero() {
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "job.run_duration_ms", Value: s.now().Sub(startedAt).Milliseconds()})
		}
		telemetry.End(span, status, spanAttrs.WithField(telemetry.Field{Key: "job.status.final", Value: status}))
	}()

	runner := s.runners[job.Kind]
	if runner == nil {
		finished := s.now()
		if updated, updateErr := s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{
			Status:          ports.JobStatusFailed,
			Message:         "job runner unavailable",
			Error:           "job runner unavailable",
			FailureClass:    JobFailurePermanent,
			FinishedAt:      &finished,
			AllowedStatuses: []string{ports.JobStatusQueued},
		}); updateErr == nil {
			job = updated
			appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: "job runner unavailable"})
		}
		status = ports.JobStatusFailed
		return fmt.Errorf("%w: runner missing for %s", ErrRuntimeUnavailable, job.Kind)
	}

	job, err = leaseStore.ClaimJob(ctx, ports.JobClaimRequest{JobID: job.ID, Owner: leaseOwner, Now: s.now(), TTL: s.leaseTTL})
	if err != nil {
		if errors.Is(err, ports.ErrJobLeaseConflict) {
			status = "skipped"
			spanAttrs = spanAttrs.With(telemetry.Attrs(
				telemetry.Field{Key: "job.run.skipped", Value: true},
				telemetry.Field{Key: "job.run.skipped_reason", Value: "lease_conflict"},
			))
			return nil
		}
		return err
	}
	startedAt = job.StartedAt
	eventType := "started"
	eventMessage := "job started"
	if job.Attempt > 1 {
		eventType = "resumed"
		eventMessage = "job resumed after recovery"
	}
	appendJobEventLogged(ctx, s.store, ports.JobEvent{JobID: job.ID, Type: eventType, Status: ports.JobStatusRunning, Message: eventMessage, Payload: map[string]any{"attempt": job.Attempt}})
	telemetry.Event(ctx, "platform.job.started", jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "job.queue_latency_ms", Value: jobQueueLatencyMs(job)},
		telemetry.Field{Key: "job.runner.available", Value: true},
	)))

	runnerCtx, runnerCancel := context.WithCancel(ctx)
	s.registerJobCancel(job.ID, runnerCancel)
	var cancelRequested atomic.Bool
	var leaseLost atomic.Bool
	heartbeatCtx, stopHeartbeat := context.WithCancel(context.WithoutCancel(ctx))
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(s.heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				renewed, renewErr := leaseStore.RenewJobLease(heartbeatCtx, ports.JobLeaseRenewRequest{JobID: job.ID, Owner: leaseOwner, Now: s.now(), TTL: s.leaseTTL})
				if renewErr != nil {
					leaseLost.Store(true)
					runnerCancel()
					return
				}
				if renewed.CancelRequested {
					cancelRequested.Store(true)
					runnerCancel()
					return
				}
			}
		}
	}()
	var cleanupHeartbeat sync.Once
	cleanup := func() {
		cleanupHeartbeat.Do(func() {
			stopHeartbeat()
			<-heartbeatDone
			s.unregisterJobCancel(job.ID)
			runnerCancel()
		})
	}
	defer cleanup()

	result, refs, runErr := runner(runnerCtx, job, s)
	cleanup()

	if current, getErr := s.store.GetJob(context.WithoutCancel(ctx), job.ID); getErr == nil {
		job = current
		if current.CancelRequested {
			cancelRequested.Store(true)
		}
	}
	if cancelRequested.Load() {
		finished := s.now()
		job, err = s.store.UpdateJob(context.WithoutCancel(ctx), job.ID, ports.JobUpdate{
			Status:             ports.JobStatusCancelled,
			Message:            "job cancelled",
			FailureClass:       JobFailureCancelled,
			FinishedAt:         &finished,
			AllowedStatuses:    []string{ports.JobStatusRunning},
			ExpectedLeaseOwner: leaseOwner,
			ClearLease:         true,
		})
		if err != nil {
			return err
		}
		appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "cancelled", Status: ports.JobStatusCancelled, Message: "job cancelled"})
		status = ports.JobStatusCancelled
		return nil
	}
	if leaseLost.Load() {
		status = "abandoned"
		return fmt.Errorf("%w: %s", ports.ErrJobLeaseConflict, job.ID)
	}
	if runErr != nil && errors.Is(runErr, context.Canceled) && ctx.Err() != nil {
		status = "interrupted"
		return runErr
	}

	finished := s.now()
	if runErr != nil {
		failureClass := classifyJobFailure(runErr)
		job, err = s.store.UpdateJob(context.WithoutCancel(ctx), job.ID, ports.JobUpdate{
			Status:             ports.JobStatusFailed,
			Error:              runErr.Error(),
			Message:            "job failed",
			FailureClass:       failureClass,
			FinishedAt:         &finished,
			AllowedStatuses:    []string{ports.JobStatusRunning},
			ExpectedLeaseOwner: leaseOwner,
			ClearLease:         true,
		})
		if err != nil {
			return err
		}
		appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: runErr.Error(), Payload: map[string]any{"failure_class": failureClass, "attempt": job.Attempt}})
		status = ports.JobStatusFailed
		spanAttrs = spanAttrs.With(jobResultTelemetryAttrs(result, refs)).With(telemetry.Attrs(
			telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(runErr)},
			telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("platform.job.run", runErr, jobTelemetryAttrs(job))},
		))
		telemetry.CaptureError(ctx, "platform.job.failed", runErr, jobTelemetryAttrs(job).With(spanAttrs))
		return runErr
	}

	progress := uint32(100)
	completedJobID := job.ID
	completedJob, updateErr := s.store.UpdateJob(context.WithoutCancel(ctx), completedJobID, ports.JobUpdate{
		Status:              ports.JobStatusCompleted,
		Progress:            &progress,
		Message:             "job completed",
		Result:              result,
		ResultRefs:          refs,
		FinishedAt:          &finished,
		AllowedStatuses:     []string{ports.JobStatusRunning},
		ExpectedLeaseOwner:  leaseOwner,
		RequireNotCancelled: true,
		ClearLease:          true,
	})
	if updateErr != nil {
		if errors.Is(updateErr, ports.ErrJobUpdateConflict) {
			if current, getErr := s.store.GetJob(context.WithoutCancel(ctx), completedJobID); getErr == nil && current.CancelRequested && current.LeaseOwner == leaseOwner {
				cancelled, cancelErr := s.store.UpdateJob(context.WithoutCancel(ctx), completedJobID, ports.JobUpdate{
					Status:             ports.JobStatusCancelled,
					Message:            "job cancelled",
					FailureClass:       JobFailureCancelled,
					FinishedAt:         &finished,
					AllowedStatuses:    []string{ports.JobStatusRunning},
					ExpectedLeaseOwner: leaseOwner,
					ClearLease:         true,
				})
				if cancelErr == nil {
					job = cancelled
					appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "cancelled", Status: ports.JobStatusCancelled, Message: "job cancelled"})
					status = ports.JobStatusCancelled
					return nil
				}
			}
			status = "skipped"
		}
		return updateErr
	}
	job = completedJob
	appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "completed", Status: ports.JobStatusCompleted, Message: "job completed", Payload: map[string]any{"attempt": job.Attempt}})
	status = ports.JobStatusCompleted
	spanAttrs = spanAttrs.With(jobResultTelemetryAttrs(result, refs)).With(telemetry.Attrs(
		telemetry.Field{Key: "job.queue_latency_ms", Value: jobQueueLatencyMs(job)},
		telemetry.Field{Key: "job.finished_at_unix_ms", Value: finished.UnixMilli()},
		telemetry.Field{Key: "job.progress_percent", Value: progress},
	))
	telemetry.Event(ctx, "platform.job.completed", jobTelemetryAttrs(job).With(spanAttrs))
	return nil
}

func (s *Service) runWithoutLease(ctx context.Context, jobID string) (err error) {
	if s == nil || s.store == nil {
		return ErrRuntimeUnavailable
	}
	var (
		job       *ports.Job
		span      *telemetry.Span
		status    = "failed"
		spanAttrs = telemetry.Attrs()
		startedAt time.Time
	)
	defer func() {
		recovered := recover()
		if recovered != nil {
			status = ports.JobStatusFailed
			panicErr := fmt.Errorf("%w: %v", ErrJobPanic, recovered)
			spanAttrs = spanAttrs.With(telemetry.Attrs(
				telemetry.Field{Key: "job.panic", Value: true},
				telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(panicErr)},
				telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("platform.job.run", panicErr, jobTelemetryAttrs(job))},
			))
			err = s.failPanickedJob(context.WithoutCancel(ctx), jobID, recovered)
		}
		if span != nil {
			if job != nil {
				spanAttrs = spanAttrs.With(jobTelemetryAttrs(job))
			}
			if !startedAt.IsZero() {
				spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "job.run_duration_ms", Value: s.now().Sub(startedAt).Milliseconds()})
			}
			telemetry.End(span, status, spanAttrs.WithField(telemetry.Field{Key: "job.status.final", Value: status}))
		}
	}()
	job, err = s.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	ctx, span = telemetry.StartMain(ctx, "platform.job.run", jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "operation.type", Value: "platform_job"},
		telemetry.Field{Key: "workload.kind", Value: "platform_job"},
		telemetry.Field{Key: "job.name", Value: job.Kind},
		telemetry.Field{Key: "job.status.initial", Value: job.Status},
	)))
	if job.Status != ports.JobStatusQueued {
		status = "skipped"
		spanAttrs = spanAttrs.With(telemetry.Attrs(
			telemetry.Field{Key: "job.run.skipped", Value: true},
			telemetry.Field{Key: "job.run.skipped_reason", Value: "not_queued"},
			telemetry.Field{Key: "job.status.current", Value: job.Status},
		))
		skippedAttrs := jobTelemetryAttrs(job).WithField(telemetry.Field{Key: "job.run.skipped_reason", Value: "not_queued"})
		telemetry.Event(ctx, "platform.job.run_skipped", skippedAttrs)
		return nil
	}
	runner := s.runners[job.Kind]
	if runner == nil {
		finished := s.now()
		if updated, err := s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusFailed, Message: "job runner unavailable", Error: "job runner unavailable", FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusQueued}}); err == nil {
			job = updated
			appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: "job runner unavailable"})
		}
		status = ports.JobStatusFailed
		runErr := fmt.Errorf("%w: runner missing for %s", ErrRuntimeUnavailable, job.Kind)
		spanAttrs = spanAttrs.With(telemetry.Attrs(
			telemetry.Field{Key: "job.runner.available", Value: false},
			telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(runErr)},
			telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("platform.job.run", runErr, jobTelemetryAttrs(job))},
		))
		telemetry.CaptureError(ctx, "platform.job.runner_unavailable", runErr, jobTelemetryAttrs(job))
		return nil
	}
	now := s.now()
	startedAt = now
	job, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusRunning, Message: "job running", StartedAt: &now, AllowedStatuses: []string{ports.JobStatusQueued}})
	if err != nil {
		if errors.Is(err, ports.ErrJobUpdateConflict) {
			status = "skipped"
			spanAttrs = spanAttrs.With(telemetry.Attrs(
				telemetry.Field{Key: "job.run.skipped", Value: true},
				telemetry.Field{Key: "job.run.skipped_reason", Value: "state_conflict"},
				telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)},
			))
			return nil
		}
		spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
		return err
	}
	appendJobEventLogged(ctx, s.store, ports.JobEvent{JobID: job.ID, Type: "started", Status: ports.JobStatusRunning, Message: "job started"})
	telemetry.Event(ctx, "platform.job.started", jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "job.queue_latency_ms", Value: jobQueueLatencyMs(job)},
		telemetry.Field{Key: "job.runner.available", Value: true},
	)))
	result, refs, runErr := runner(ctx, job, s)
	finished := s.now()
	if runErr != nil {
		job, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusFailed, Error: runErr.Error(), Message: "job failed", FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusRunning}})
		if err != nil {
			if errors.Is(err, ports.ErrJobUpdateConflict) {
				status = ports.JobStatusFailed
				spanAttrs = spanAttrs.With(telemetry.Attrs(
					telemetry.Field{Key: "job.update_conflict", Value: true},
					telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(runErr)},
				))
				return runErr
			}
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
			return err
		}
		appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: runErr.Error()})
		status = ports.JobStatusFailed
		spanAttrs = spanAttrs.With(jobResultTelemetryAttrs(result, refs)).With(telemetry.Attrs(
			telemetry.Field{Key: "job.queue_latency_ms", Value: jobQueueLatencyMs(job)},
			telemetry.Field{Key: "job.finished_at_unix_ms", Value: finished.UnixMilli()},
			telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(runErr)},
			telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("platform.job.run", runErr, jobTelemetryAttrs(job))},
		))
		telemetry.CaptureError(ctx, "platform.job.failed", runErr, jobTelemetryAttrs(job).With(spanAttrs))
		return runErr
	}
	progress := uint32(100)
	job, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusCompleted, Progress: &progress, Message: "job completed", Result: result, ResultRefs: refs, FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusRunning}})
	if errors.Is(err, ports.ErrJobUpdateConflict) {
		status = "skipped"
		spanAttrs = spanAttrs.With(telemetry.Attrs(
			telemetry.Field{Key: "job.update_conflict", Value: true},
			telemetry.Field{Key: "job.run.skipped_reason", Value: "completion_conflict"},
		))
		return nil
	}
	if err == nil {
		appendJobEventLogged(context.WithoutCancel(ctx), s.store, ports.JobEvent{JobID: job.ID, Type: "completed", Status: ports.JobStatusCompleted, Message: "job completed"})
		status = ports.JobStatusCompleted
		spanAttrs = spanAttrs.With(jobResultTelemetryAttrs(result, refs)).With(telemetry.Attrs(
			telemetry.Field{Key: "job.queue_latency_ms", Value: jobQueueLatencyMs(job)},
			telemetry.Field{Key: "job.finished_at_unix_ms", Value: finished.UnixMilli()},
			telemetry.Field{Key: "job.progress_percent", Value: progress},
		))
		telemetry.Event(ctx, "platform.job.completed", jobTelemetryAttrs(job).With(spanAttrs))
	} else {
		spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	}
	return err
}

func (s *Service) failPanickedJob(ctx context.Context, jobID string, recovered any) error {
	panicErr := fmt.Errorf("%w: %v", ErrJobPanic, recovered)
	jobID = strings.TrimSpace(jobID)
	if s == nil || s.store == nil || jobID == "" {
		return panicErr
	}
	finished := s.now()
	_, err := s.store.UpdateJob(ctx, jobID, ports.JobUpdate{
		Status:          ports.JobStatusFailed,
		Message:         "job failed",
		Error:           panicErr.Error(),
		FinishedAt:      &finished,
		AllowedStatuses: []string{ports.JobStatusQueued, ports.JobStatusRunning},
	})
	if err != nil {
		if errors.Is(err, ports.ErrJobUpdateConflict) {
			return panicErr
		}
		return fmt.Errorf("%w; mark job failed: %w", panicErr, err)
	}
	appendJobEventLogged(ctx, s.store, ports.JobEvent{JobID: jobID, Type: "failed", Status: ports.JobStatusFailed, Message: panicErr.Error()})
	return panicErr
}

func (s *Service) failPanickedLeasedJob(ctx context.Context, jobID string, owner string, recovered any) error {
	panicErr := fmt.Errorf("%w: %v", ErrJobPanic, recovered)
	jobID = strings.TrimSpace(jobID)
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || jobID == "" || owner == "" {
		return panicErr
	}
	finished := s.now()
	_, err := s.store.UpdateJob(ctx, jobID, ports.JobUpdate{
		Status:             ports.JobStatusFailed,
		Message:            "job failed",
		Error:              panicErr.Error(),
		FailureClass:       JobFailurePermanent,
		FinishedAt:         &finished,
		AllowedStatuses:    []string{ports.JobStatusRunning},
		ExpectedLeaseOwner: owner,
		ClearLease:         true,
	})
	if err != nil {
		if errors.Is(err, ports.ErrJobUpdateConflict) || errors.Is(err, ports.ErrJobLeaseConflict) {
			return panicErr
		}
		return fmt.Errorf("%w; mark job failed: %w", panicErr, err)
	}
	appendJobEventLogged(ctx, s.store, ports.JobEvent{JobID: jobID, Type: "failed", Status: ports.JobStatusFailed, Message: panicErr.Error(), Payload: map[string]any{"failure_class": JobFailurePermanent}})
	return panicErr
}

func (s *Service) registerJobCancel(jobID string, cancel context.CancelFunc) {
	if s == nil || cancel == nil {
		return
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return
	}
	s.mu.Lock()
	if s.jobCancels == nil {
		s.jobCancels = map[string]context.CancelFunc{}
	}
	s.jobCancels[jobID] = cancel
	s.mu.Unlock()
}

func (s *Service) unregisterJobCancel(jobID string) {
	if s == nil {
		return
	}
	jobID = strings.TrimSpace(jobID)
	s.mu.Lock()
	delete(s.jobCancels, jobID)
	s.mu.Unlock()
}

func (s *Service) cancelRunningJob(jobID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.jobCancels[strings.TrimSpace(jobID)]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func classifyJobFailure(err error) string {
	if err == nil {
		return ""
	}
	var retryable retryableJobError
	if errors.As(err, &retryable) || errors.Is(err, context.DeadlineExceeded) {
		return JobFailureRetryable
	}
	if errors.Is(err, context.Canceled) {
		return JobFailureCancelled
	}
	return JobFailurePermanent
}

func newJobLeaseOwner() string {
	return "worker-" + strings.TrimPrefix(NewID(), "job-")
}

func (s *Service) Get(ctx context.Context, id string) (*ports.Job, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.GetJob(ctx, id)
}

func (s *Service) List(ctx context.Context, filter ports.JobFilter) ([]*ports.Job, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.ListJobs(ctx, filter)
}

func (s *Service) Events(ctx context.Context, jobID string, limit uint32) ([]*ports.JobEvent, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.ListJobEvents(ctx, jobID, limit)
}

func (s *Service) Cancel(ctx context.Context, jobID string) (*ports.Job, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	existing, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	switch existing.Status {
	case ports.JobStatusCompleted, ports.JobStatusFailed, ports.JobStatusCancelled:
		return existing, nil
	}
	requested := true
	finished := s.now()
	update := ports.JobUpdate{Message: "job cancellation requested", CancelRequested: &requested, AllowedStatuses: []string{existing.Status}}
	event := ports.JobEvent{JobID: existing.ID, Type: "cancellation_requested", Status: existing.Status, Message: "job cancellation requested"}
	if existing.Status == ports.JobStatusQueued {
		update.Status = ports.JobStatusCancelled
		update.FinishedAt = &finished
		event.Type = "cancelled"
		event.Status = ports.JobStatusCancelled
	}
	job, err := s.store.UpdateJob(ctx, jobID, update)
	if err != nil {
		if errors.Is(err, ports.ErrJobUpdateConflict) {
			return s.store.GetJob(ctx, jobID)
		}
		return nil, err
	}
	appendJobEventLogged(ctx, s.store, event)
	if event.Type == "cancellation_requested" {
		s.cancelRunningJob(jobID)
	}
	telemetry.Event(ctx, "platform.job.cancel_requested", jobTelemetryAttrs(job).With(telemetry.Attrs(
		telemetry.Field{Key: "job.cancel_requested", Value: true},
		telemetry.Field{Key: "job.cancel.transitioned_terminal", Value: event.Type == "cancelled"},
	)))
	return job, nil
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return "job-" + hex.EncodeToString(b[:])
}

func jobTelemetryAttrs(job *ports.Job) telemetry.Attributes {
	if job == nil {
		return telemetry.Attrs()
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "job.id", Value: job.ID},
		telemetry.Field{Key: "job.kind", Value: job.Kind},
		telemetry.Field{Key: "job.status", Value: job.Status},
		telemetry.Field{Key: "job_id", Value: job.ID},
		telemetry.Field{Key: "job_kind", Value: job.Kind},
		telemetry.Field{Key: "job_status", Value: job.Status},
		telemetry.Field{Key: "tenant_id", Value: job.TenantID},
		telemetry.Field{Key: "job.tenant_id", Value: job.TenantID},
		telemetry.Field{Key: "job.subject_type", Value: job.SubjectType},
		telemetry.Field{Key: "job.subject_id", Value: job.SubjectID},
		telemetry.Field{Key: "job_subject_type", Value: job.SubjectType},
		telemetry.Field{Key: "job_subject_id", Value: job.SubjectID},
		telemetry.Field{Key: "job.progress_percent", Value: job.Progress},
		telemetry.Field{Key: "job.cancel_requested", Value: job.CancelRequested},
		telemetry.Field{Key: "job.attempt", Value: job.Attempt},
		telemetry.Field{Key: "job.failure_class", Value: job.FailureClass},
		telemetry.Field{Key: "job.created_at_unix_ms", Value: unixMilliOrZero(job.CreatedAt)},
		telemetry.Field{Key: "job.started_at_unix_ms", Value: unixMilliOrZero(job.StartedAt)},
		telemetry.Field{Key: "job.finished_at_unix_ms", Value: unixMilliOrZero(job.FinishedAt)},
		telemetry.Field{Key: "job.updated_at_unix_ms", Value: unixMilliOrZero(job.UpdatedAt)},
		telemetry.Field{Key: "job.payload.key_count", Value: len(job.Payload)},
		telemetry.Field{Key: "job.payload.keys", Value: strings.Join(sortedAnyMapKeys(job.Payload), ",")},
		telemetry.Field{Key: "job.result.key_count", Value: len(job.Result)},
		telemetry.Field{Key: "job.result.keys", Value: strings.Join(sortedAnyMapKeys(job.Result), ",")},
		telemetry.Field{Key: "job.result_ref.key_count", Value: len(job.ResultRefs)},
		telemetry.Field{Key: "job.result_ref.keys", Value: strings.Join(sortedStringMapKeys(job.ResultRefs), ",")},
		telemetry.Field{Key: "job.idempotency_key.present", Value: job.IdempotencyKey != ""},
		telemetry.Field{Key: "job.idempotency_key.hash", Value: hashText(job.IdempotencyKey)},
	)
	if runtimeID := jobRuntimeID(job); runtimeID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "runtime_id", Value: runtimeID})
		attrs = attrs.WithField(telemetry.Field{Key: "source_runtime_id", Value: runtimeID})
	}
	if sourceID := firstStringPayload(job.Payload, "source_id"); sourceID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "source_id", Value: sourceID})
	}
	reportID := firstStringPayload(job.Payload, "report_id")
	if reportID == "" {
		reportID = strings.TrimSpace(job.SubjectID)
	}
	if reportID != "" && (job.Kind == KindReportRun || job.SubjectType == "report") {
		attrs = attrs.WithField(telemetry.Field{Key: "report_id", Value: reportID})
	}
	if !job.CreatedAt.IsZero() && !job.StartedAt.IsZero() {
		attrs = attrs.WithField(telemetry.Field{Key: "job.queue_latency_ms", Value: job.StartedAt.Sub(job.CreatedAt).Milliseconds()})
	}
	if !job.StartedAt.IsZero() && !job.FinishedAt.IsZero() {
		attrs = attrs.WithField(telemetry.Field{Key: "job.run_duration_ms", Value: job.FinishedAt.Sub(job.StartedAt).Milliseconds()})
	}
	return attrs
}

func jobResultTelemetryAttrs(result map[string]any, refs map[string]string) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "job.result.key_count", Value: len(result)},
		telemetry.Field{Key: "job.result.keys", Value: strings.Join(sortedAnyMapKeys(result), ",")},
		telemetry.Field{Key: "job.result_ref.key_count", Value: len(refs)},
		telemetry.Field{Key: "job.result_ref.keys", Value: strings.Join(sortedStringMapKeys(refs), ",")},
	)
}

func jobRuntimeID(job *ports.Job) string {
	if job == nil {
		return ""
	}
	if runtimeID := firstStringPayload(job.Payload, "runtime_id", "source_runtime_id"); runtimeID != "" {
		return runtimeID
	}
	if strings.Contains(job.Kind, "source_runtime") || strings.Contains(job.Kind, "graph_ingest") || strings.Contains(job.Kind, "finding") || job.SubjectType == "source_runtime" {
		return strings.TrimSpace(job.SubjectID)
	}
	return ""
}

func firstStringPayload(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func jobQueueLatencyMs(job *ports.Job) int64 {
	if job == nil || job.CreatedAt.IsZero() || job.StartedAt.IsZero() {
		return 0
	}
	return job.StartedAt.Sub(job.CreatedAt).Milliseconds()
}

func unixMilliOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func sortedAnyMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hashText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func jobRequestHash(request ports.CreateJobRequest) (string, error) {
	payload := struct {
		Kind        string         `json:"kind"`
		TenantID    string         `json:"tenant_id"`
		SubjectType string         `json:"subject_type"`
		SubjectID   string         `json:"subject_id"`
		Payload     map[string]any `json:"payload"`
	}{
		Kind:        strings.TrimSpace(request.Kind),
		TenantID:    strings.TrimSpace(request.TenantID),
		SubjectType: strings.TrimSpace(request.SubjectType),
		SubjectID:   strings.TrimSpace(request.SubjectID),
		Payload:     request.Payload,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func appendJobEventLogged(ctx context.Context, store ports.JobStore, event ports.JobEvent) {
	if _, err := store.AppendJobEvent(ctx, event); err != nil {
		telemetry.CaptureError(ctx, "platform.job.event_append_failed", err, telemetry.Attrs(
			telemetry.Field{Key: "job_id", Value: event.JobID},
			telemetry.Field{Key: "event_type", Value: event.Type},
		))
	}
}
