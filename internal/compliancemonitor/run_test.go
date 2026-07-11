package compliancemonitor

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
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
	appendLog := &memoryMonitorAppendLog{jobStore: jobStore, monitorStore: monitors}
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, CompleteRun(ctx, monitors, job, true, now.Add(time.Minute))
	})
	service := newMonitorTestService(t, monitors, appendLog, jobs)

	count, err := service.RunDue(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDue() error = %v", err)
	}
	if count != 1 || !monitors.completed || !monitors.jobExistedAtComplete(jobStore) {
		t.Fatalf("count=%d completed=%v jobExistedAtComplete=%v", count, monitors.completed, monitors.jobExistedAtComplete(jobStore))
	}
	assertTriggerEvent(t, appendLog.events, ports.ComplianceTriggerTime, "monitor-1", 0)
	if !appendLog.jobExistedAtAppend || appendLog.monitorAcknowledgedAtAppend {
		t.Fatalf("jobExistedAtAppend=%v monitorAcknowledgedAtAppend=%v", appendLog.jobExistedAtAppend, appendLog.monitorAcknowledgedAtAppend)
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
	service := newMonitorTestService(t, monitors, &memoryMonitorAppendLog{}, jobs)

	count, err := service.RunDue(context.Background(), now)
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
	service := newMonitorTestService(t, monitors, &memoryMonitorAppendLog{}, jobs)

	count, err := service.RunDue(context.Background(), now)
	if err != nil || count != 0 || !monitors.claimReleased {
		t.Fatalf("RunDue() = (%d, %v), claimReleased=%v", count, err, monitors.claimReleased)
	}
}

func TestRunDueRetriesSameJobAndEventAfterAppendFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 30, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{due: []*ports.ComplianceMonitor{{
		ID: "monitor-retry", TenantID: "tenant-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", TriggerKind: ports.ComplianceTriggerTime,
		IntervalSeconds: 3600, Enabled: true, NextRunAt: now,
	}}}
	jobStore := newMemoryJobStore(now)
	appendLog := &memoryMonitorAppendLog{err: errors.New("log unavailable"), failCount: 1, jobStore: jobStore, monitorStore: monitors}
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, CompleteRun(ctx, monitors, job, true, now.Add(time.Minute))
	})
	service := newMonitorTestService(t, monitors, appendLog, jobs)

	if count, err := service.RunDue(context.Background(), now); err == nil || count != 0 {
		t.Fatalf("first RunDue() = (%d, %v)", count, err)
	}
	if monitors.completed || !monitors.claimReleased || monitors.planLeaseOwner == "" {
		t.Fatalf("completed=%v claimReleased=%v planLeaseOwner=%q", monitors.completed, monitors.claimReleased, monitors.planLeaseOwner)
	}
	if count, err := service.RunDue(context.Background(), now.Add(time.Second)); err != nil || count != 1 {
		t.Fatalf("second RunDue() = (%d, %v)", count, err)
	}
	if len(jobStore.jobs) != 1 || len(appendLog.attempts) != 2 || len(appendLog.events) != 1 {
		t.Fatalf("jobs=%d attempts=%d events=%d", len(jobStore.jobs), len(appendLog.attempts), len(appendLog.events))
	}
	if !sameEnvelope(appendLog.attempts[0], appendLog.attempts[1]) {
		t.Fatal("append retry changed trigger event identity or payload")
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunDueRetriesAcknowledgementWithoutChangingJobRequest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 45, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{due: []*ports.ComplianceMonitor{{
		ID: "monitor-ack-retry", TenantID: "tenant-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", TriggerKind: ports.ComplianceTriggerTime,
		IntervalSeconds: 3600, Enabled: true, NextRunAt: now,
	}}, completeErrCount: 1, completeErr: errors.New("projection unavailable")}
	jobStore := newMemoryJobStore(now)
	appendLog := &memoryMonitorAppendLog{jobStore: jobStore, monitorStore: monitors}
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, CompleteRun(ctx, monitors, job, true, now.Add(time.Minute))
	})
	service := newMonitorTestService(t, monitors, appendLog, jobs)

	if count, err := service.RunDue(context.Background(), now); err == nil || count != 0 {
		t.Fatalf("first RunDue() = (%d, %v)", count, err)
	}
	if count, err := service.RunDue(context.Background(), now.Add(time.Second)); err != nil || count != 1 {
		t.Fatalf("second RunDue() = (%d, %v)", count, err)
	}
	if len(jobStore.jobs) != 1 || len(appendLog.events) != 2 || !sameEnvelope(appendLog.events[0], appendLog.events[1]) {
		t.Fatalf("jobs=%d events=%d", len(jobStore.jobs), len(appendLog.events))
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunDueChangesCreatesJobBeforeAcknowledgingExactWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	monitors := &memoryMonitorStore{changeWindows: []*ports.ComplianceChangeWindow{{
		TenantID: "tenant-1", MonitorID: "monitor-change-1", ProgramID: "program-1",
		PlanRevisionID: "plan-revision-1", Version: 4, OpenedAt: now.Add(-time.Minute),
		LastSignalAt: now.Add(-30 * time.Second), ReadyAt: now, SignalCount: 3,
		ScopeDigest: "sha256:scope",
	}}}
	jobStore := newMemoryJobStore(now)
	appendLog := &memoryMonitorAppendLog{jobStore: jobStore, monitorStore: monitors}
	jobs := platformjobs.New(jobStore).WithRunner(platformjobs.KindComplianceAssessment, func(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
		return nil, nil, CompleteRun(ctx, monitors, job, true, now.Add(time.Minute))
	})
	service := newMonitorTestService(t, monitors, appendLog, jobs)

	count, err := service.RunDueChanges(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueChanges() error = %v", err)
	}
	if count != 1 || !monitors.changeCompleted || monitors.completedChangeVersion != 4 || !monitors.changeJobExistedAtComplete(jobStore) {
		t.Fatalf("count=%d completed=%v version=%d jobExistedAtComplete=%v", count, monitors.changeCompleted, monitors.completedChangeVersion, monitors.changeJobExistedAtComplete(jobStore))
	}
	assertTriggerEvent(t, appendLog.events, ports.ComplianceTriggerChange, "monitor-change-1", 4)
	if !appendLog.jobExistedAtAppend || appendLog.changeAcknowledgedAtAppend {
		t.Fatalf("jobExistedAtAppend=%v changeAcknowledgedAtAppend=%v", appendLog.jobExistedAtAppend, appendLog.changeAcknowledgedAtAppend)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

type memoryMonitorStore struct {
	mu                     sync.Mutex
	due                    []*ports.ComplianceMonitor
	planLeaseOwner         string
	planLeaseOccurrence    string
	completed              bool
	completeErrCount       int
	completeErr            error
	claimReleased          bool
	outcomeRecorded        bool
	changeWindows          []*ports.ComplianceChangeWindow
	changeCompleted        bool
	completedChangeVersion uint64
}

func (s *memoryMonitorStore) ProjectComplianceMonitor(context.Context, *ports.ComplianceMonitor, uint64) (*ports.ComplianceMonitor, error) {
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
	if s.completeErrCount > 0 {
		s.completeErrCount--
		return s.completeErr
	}
	s.completed = true
	return nil
}
func (s *memoryMonitorStore) ReleaseComplianceMonitorClaim(context.Context, string, string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimReleased = true
	return nil
}
func (s *memoryMonitorStore) AcquireCompliancePlanLease(_ context.Context, _, _, owner, occurrence string, _ time.Time, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planLeaseOwner != "" && s.planLeaseOwner != owner && s.planLeaseOccurrence != occurrence {
		return ports.ErrComplianceMonitorOverlap
	}
	s.planLeaseOwner = owner
	s.planLeaseOccurrence = occurrence
	return nil
}
func (s *memoryMonitorStore) ReleaseCompliancePlanLease(_ context.Context, _, _, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planLeaseOwner == owner {
		s.planLeaseOwner = ""
		s.planLeaseOccurrence = ""
	}
	return nil
}
func (s *memoryMonitorStore) RecordComplianceMonitorOutcome(context.Context, string, string, bool, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outcomeRecorded = true
	return nil
}
func (s *memoryMonitorStore) RecordComplianceChangeSignal(context.Context, ports.ComplianceChangeSignal) (bool, error) {
	return true, nil
}
func (s *memoryMonitorStore) ClaimDueComplianceChangeWindows(context.Context, time.Time, string, time.Duration, uint32) ([]*ports.ComplianceChangeWindow, error) {
	return s.changeWindows, nil
}
func (s *memoryMonitorStore) CompleteComplianceChangeWindow(_ context.Context, _, _, _ string, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changeCompleted = true
	s.completedChangeVersion = version
	return nil
}
func (s *memoryMonitorStore) ReleaseComplianceChangeWindow(context.Context, string, string, string) error {
	return nil
}
func (s *memoryMonitorStore) jobExistedAtComplete(store *memoryJobStore) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	store.mu.Lock()
	defer store.mu.Unlock()
	return s.completed && len(store.jobs) == 1
}
func (s *memoryMonitorStore) changeJobExistedAtComplete(store *memoryJobStore) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	store.mu.Lock()
	defer store.mu.Unlock()
	return s.changeCompleted && len(store.jobs) == 1
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
		if existing.RequestHash != request.RequestHash {
			return nil, false, ports.ErrJobIdempotencyConflict
		}
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

type memoryMonitorAppendLog struct {
	mu                          sync.Mutex
	events                      []*cerebrov1.EventEnvelope
	attempts                    []*cerebrov1.EventEnvelope
	err                         error
	failCount                   int
	jobStore                    *memoryJobStore
	monitorStore                *memoryMonitorStore
	jobExistedAtAppend          bool
	monitorAcknowledgedAtAppend bool
	changeAcknowledgedAtAppend  bool
}

func (l *memoryMonitorAppendLog) Ping(context.Context) error { return nil }
func (l *memoryMonitorAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts = append(l.attempts, event)
	if l.failCount > 0 {
		l.failCount--
		return l.err
	}
	l.events = append(l.events, event)
	if l.jobStore != nil {
		l.jobStore.mu.Lock()
		l.jobExistedAtAppend = len(l.jobStore.jobs) != 0
		l.jobStore.mu.Unlock()
	}
	if l.monitorStore != nil {
		l.monitorStore.mu.Lock()
		l.monitorAcknowledgedAtAppend = l.monitorStore.completed
		l.changeAcknowledgedAtAppend = l.monitorStore.changeCompleted
		l.monitorStore.mu.Unlock()
	}
	return nil
}

func newMonitorTestService(t *testing.T, store ports.ComplianceMonitorStore, appendLog ports.AppendLog, jobs *platformjobs.Service) *Service {
	t.Helper()
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	return service.WithJobs(jobs)
}

func assertTriggerEvent(t *testing.T, events []*cerebrov1.EventEnvelope, triggerKind, monitorID string, windowVersion uint64) {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("trigger events = %d, want 1", len(events))
	}
	payload, err := workflowevents.DecodeComplianceAggregate(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if payload.Kind != workflowevents.EventKindComplianceMonitorTriggered || payload.AggregateVersion != 1 || payload.RevisionID != "job-1" {
		t.Fatalf("trigger aggregate = %#v", payload)
	}
	var trigger monitorTriggerEvent
	if err := json.Unmarshal([]byte(payload.PayloadJSON), &trigger); err != nil {
		t.Fatal(err)
	}
	if trigger.TriggerKind != triggerKind || trigger.MonitorID != monitorID || trigger.WindowVersion != windowVersion {
		t.Fatalf("trigger payload = %#v", trigger)
	}
}
