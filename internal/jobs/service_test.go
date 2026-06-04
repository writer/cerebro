package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

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

type memoryJobStore struct {
	mu     sync.Mutex
	nextID int
	jobs   map[string]*ports.Job
	events []*ports.JobEvent
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
	return cloneJob(job), nil
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
