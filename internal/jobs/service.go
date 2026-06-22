package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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
)

type Runner func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error)

type Service struct {
	store        ports.JobStore
	runners      map[string]Runner
	now          func() time.Time
	nextAsyncID  uint64
	asyncCancels map[uint64]context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
}

func New(store ports.JobStore) *Service {
	return &Service{store: store, runners: map[string]Runner{}, now: func() time.Time { return time.Now().UTC() }, asyncCancels: map[uint64]context.CancelFunc{}}
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
	job, created, err := s.store.CreateJob(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if created {
		_, _ = s.store.AppendJobEvent(ctx, ports.JobEvent{JobID: job.ID, Type: "created", Status: job.Status, Message: "job created"})
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
	runner := s.runners[job.Kind]
	if runner == nil {
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

func (s *Service) Run(ctx context.Context, jobID string) (err error) {
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
			_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: "job runner unavailable"})
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
	_, _ = s.store.AppendJobEvent(ctx, ports.JobEvent{JobID: job.ID, Type: "started", Status: ports.JobStatusRunning, Message: "job started"})
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
		_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: runErr.Error()})
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
		_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "completed", Status: ports.JobStatusCompleted, Message: "job completed"})
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
	_, _ = s.store.AppendJobEvent(ctx, ports.JobEvent{JobID: jobID, Type: "failed", Status: ports.JobStatusFailed, Message: panicErr.Error()})
	return panicErr
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
	_, _ = s.store.AppendJobEvent(ctx, event)
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
