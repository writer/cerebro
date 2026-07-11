package compliancemonitor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func TestRunDueCreatesJobBeforeAdvancingAndPreventsOverlap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{due: []*ports.ComplianceMonitor{{
		ID: "monitor-1", TenantID: "tenant-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", TriggerKind: ports.ComplianceTriggerTime,
		IntervalSeconds: 3600, Enabled: true, NextRunAt: now,
	}}}
	jobStore := newMemoryJobStore(now)
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, CompleteRun(ctx, monitors, job, true, now.Add(time.Minute))
	})

	count, err := RunDue(context.Background(), monitors, jobs, now)
	if err != nil {
		t.Fatalf("RunDue() error = %v", err)
	}
	if count != 1 || !monitors.completed || !monitors.jobExistedAtComplete(jobStore) {
		t.Fatalf("count=%d completed=%v jobExistedAtComplete=%v", count, monitors.completed, monitors.jobExistedAtComplete(jobStore))
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if monitors.planLeaseOwner != "" {
		t.Fatalf("plan lease owner after completion = %q", monitors.planLeaseOwner)
	}
	if !monitors.outcomeRecorded {
		t.Fatal("monitor outcome was not recorded")
	}
}

func TestRunDueReleasesClaimsWhenJobCreationFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{due: []*ports.ComplianceMonitor{{
		ID: "monitor-1", TenantID: "tenant-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", TriggerKind: ports.ComplianceTriggerTime,
		IntervalSeconds: 3600, Enabled: true, NextRunAt: now,
	}}}
	jobStore := newMemoryJobStore(now)
	jobStore.createErr = errors.New("store unavailable")
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(context.Context, *ports.Job, *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, nil
	})

	count, err := RunDue(context.Background(), monitors, jobs, now)
	if err == nil || count != 0 {
		t.Fatalf("RunDue() = (%d, %v), want error", count, err)
	}
	if !monitors.claimReleased || monitors.planLeaseOwner != "" {
		t.Fatalf("claimReleased=%v planLeaseOwner=%q", monitors.claimReleased, monitors.planLeaseOwner)
	}
}

func TestRunDueSkipsOverlappingPlan(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{due: []*ports.ComplianceMonitor{{
		ID: "monitor-2", TenantID: "tenant-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", TriggerKind: ports.ComplianceTriggerTime,
		IntervalSeconds: 3600, Enabled: true, NextRunAt: now,
	}}, planLeaseOwner: "active-run"}
	jobs := platformjobs.New(newMemoryJobStore(now)).WithRunner(platformjobs.KindComplianceAssessment, func(context.Context, *ports.Job, *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, nil
	})

	count, err := RunDue(context.Background(), monitors, jobs, now)
	if err != nil || count != 0 || !monitors.claimReleased {
		t.Fatalf("RunDue() = (%d, %v), claimReleased=%v", count, err, monitors.claimReleased)
	}
}

type memoryMonitorStore struct {
	mu               sync.Mutex
	due              []*ports.ComplianceMonitor
	planLeaseOwner   string
	completed        bool
	claimReleased    bool
	completeJobCount int
	outcomeRecorded  bool
}

func (s *memoryMonitorStore) PutComplianceMonitor(context.Context, *ports.ComplianceMonitor, uint64) (*ports.ComplianceMonitor, error) {
	return nil, nil
}
func (s *memoryMonitorStore) GetComplianceMonitor(context.Context, string, string) (*ports.ComplianceMonitor, error) {
	return nil, ports.ErrComplianceMonitorNotFound
}
func (s *memoryMonitorStore) ListComplianceMonitors(context.Context, ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error) {
	return nil, nil
}
func (s *memoryMonitorStore) ClaimDueComplianceMonitors(context.Context, time.Time, string, time.Duration, uint32) ([]*ports.ComplianceMonitor, error) {
	return s.due, nil
}
func (s *memoryMonitorStore) CompleteComplianceMonitorClaim(_ context.Context, _, _, _ string, _, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completed = true
	return nil
}
func (s *memoryMonitorStore) ReleaseComplianceMonitorClaim(context.Context, string, string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimReleased = true
	return nil
}
func (s *memoryMonitorStore) AcquireCompliancePlanLease(_ context.Context, _, _, owner, _ string, _ time.Time, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planLeaseOwner != "" && s.planLeaseOwner != owner {
		return ports.ErrComplianceMonitorOverlap
	}
	s.planLeaseOwner = owner
	return nil
}
func (s *memoryMonitorStore) ReleaseCompliancePlanLease(_ context.Context, _, _, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planLeaseOwner == owner {
		s.planLeaseOwner = ""
	}
	return nil
}
func (s *memoryMonitorStore) RecordComplianceMonitorOutcome(context.Context, string, string, bool, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outcomeRecorded = true
	return nil
}
func (s *memoryMonitorStore) jobExistedAtComplete(store *memoryJobStore) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	store.mu.Lock()
	defer store.mu.Unlock()
	return s.completed && len(store.jobs) == 1
}

type memoryJobStore struct {
	mu        sync.Mutex
	now       time.Time
	jobs      map[string]*ports.Job
	byKey     map[string]*ports.Job
	createErr error
}

func newMemoryJobStore(now time.Time) *memoryJobStore {
	return &memoryJobStore{now: now, jobs: map[string]*ports.Job{}, byKey: map[string]*ports.Job{}}
}
func (s *memoryJobStore) Ping(context.Context) error { return nil }
func (s *memoryJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return nil, false, s.createErr
	}
	if existing := s.byKey[request.IdempotencyKey]; existing != nil {
		return cloneJob(existing), false, nil
	}
	job := &ports.Job{ID: "job-1", Kind: request.Kind, Status: ports.JobStatusQueued, TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, IdempotencyKey: request.IdempotencyKey, RequestHash: request.RequestHash, Payload: request.Payload, CreatedAt: s.now, UpdatedAt: s.now}
	s.jobs[job.ID] = job
	s.byKey[request.IdempotencyKey] = job
	return cloneJob(job), true, nil
}
func (s *memoryJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	return cloneJob(job), nil
}
func (s *memoryJobStore) ListJobs(context.Context, ports.JobFilter) ([]*ports.Job, error) {
	return nil, nil
}
func (s *memoryJobStore) CountJobs(context.Context, ports.JobFilter) (uint64, error) { return 0, nil }
func (s *memoryJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	if update.Status != "" {
		job.Status = update.Status
	}
	job.Result = update.Result
	job.ResultRefs = update.ResultRefs
	if update.StartedAt != nil {
		job.StartedAt = *update.StartedAt
	}
	if update.FinishedAt != nil {
		job.FinishedAt = *update.FinishedAt
	}
	return cloneJob(job), nil
}
func (s *memoryJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	return &event, nil
}
func (s *memoryJobStore) ListJobEvents(context.Context, string, uint32) ([]*ports.JobEvent, error) {
	return nil, nil
}

func cloneJob(job *ports.Job) *ports.Job {
	if job == nil {
		return nil
	}
	clone := *job
	clone.Payload = map[string]any{}
	for key, value := range job.Payload {
		clone.Payload[key] = value
	}
	return &clone
}
