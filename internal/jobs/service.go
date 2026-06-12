package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
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
)

type Runner func(context.Context, *ports.Job, *Service) (map[string]any, map[string]string, error)

type Service struct {
	store   ports.JobStore
	runners map[string]Runner
	now     func() time.Time
}

func New(store ports.JobStore) *Service {
	return &Service{store: store, runners: map[string]Runner{}, now: func() time.Time { return time.Now().UTC() }}
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
	return job, created, nil
}

func (s *Service) StartAsync(parent context.Context, job *ports.Job) {
	if s == nil || job == nil {
		return
	}
	runner := s.runners[job.Kind]
	if runner == nil {
		return
	}
	ctx := context.WithoutCancel(parent)
	go func() {
		_ = s.Run(ctx, job.ID)
	}()
}

func (s *Service) Run(ctx context.Context, jobID string) (err error) {
	if s == nil || s.store == nil {
		return ErrRuntimeUnavailable
	}
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		err = s.failPanickedJob(context.WithoutCancel(ctx), jobID, recovered)
	}()
	job, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	if job.Status != ports.JobStatusQueued {
		return nil
	}
	runner := s.runners[job.Kind]
	if runner == nil {
		finished := s.now()
		if _, err := s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusFailed, Message: "job runner unavailable", Error: "job runner unavailable", FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusQueued}}); err == nil {
			_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: "job runner unavailable"})
		}
		return nil
	}
	now := s.now()
	job, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusRunning, Message: "job running", StartedAt: &now, AllowedStatuses: []string{ports.JobStatusQueued}})
	if err != nil {
		if errors.Is(err, ports.ErrJobUpdateConflict) {
			return nil
		}
		return err
	}
	_, _ = s.store.AppendJobEvent(ctx, ports.JobEvent{JobID: job.ID, Type: "started", Status: ports.JobStatusRunning, Message: "job started"})
	result, refs, runErr := runner(ctx, job, s)
	finished := s.now()
	if runErr != nil {
		_, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusFailed, Error: runErr.Error(), Message: "job failed", FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusRunning}})
		if err != nil {
			if errors.Is(err, ports.ErrJobUpdateConflict) {
				return runErr
			}
			return err
		}
		_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "failed", Status: ports.JobStatusFailed, Message: runErr.Error()})
		return runErr
	}
	progress := uint32(100)
	_, err = s.store.UpdateJob(ctx, job.ID, ports.JobUpdate{Status: ports.JobStatusCompleted, Progress: &progress, Message: "job completed", Result: result, ResultRefs: refs, FinishedAt: &finished, AllowedStatuses: []string{ports.JobStatusRunning}})
	if errors.Is(err, ports.ErrJobUpdateConflict) {
		return nil
	}
	if err == nil {
		_, _ = s.store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{JobID: job.ID, Type: "completed", Status: ports.JobStatusCompleted, Message: "job completed"})
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
	return job, nil
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return "job-" + hex.EncodeToString(b[:])
}
