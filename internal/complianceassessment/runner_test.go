package complianceassessment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func TestAssessmentRunBindsJobAndPersistsCompleteChunkChain(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	log := &runLog{}
	jobStore := newRunJobStore(now)
	jobs := platformjobs.New(jobStore)
	collector := &testCollector{manifest: completeManifest(now), results: validResults(now, 1205)}
	service := NewAssessmentService(store, log, jobs, collector)
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)

	run, created, err := service.RequestRun(context.Background(), RunRequest{
		TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID,
		PeriodStart: now.Add(-24 * time.Hour), PeriodEnd: now,
		IdempotencyKey: "run-key-1", RequestedBy: "assessor-1",
	})
	if err != nil || !created || run.JobID == "" {
		t.Fatalf("RequestRun() = (%#v, %v, %v)", run, created, err)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	completed, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != RunComplete || completed.InputHash == "" || completed.AutomatedResultHash == "" || completed.ResultCount != 1205 {
		t.Fatalf("completed run = %#v", completed)
	}
	chunks, err := store.ListResultChunks(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 5 {
		t.Fatalf("chunk count = %d, want 5", len(chunks))
	}
	for index, chunk := range chunks {
		if chunk.Sequence != uint32(index+1) {
			t.Fatalf("chunk sequence[%d] = %d", index, chunk.Sequence)
		}
		if index > 0 && chunk.PreviousDigest != chunks[index-1].Digest {
			t.Fatalf("chunk %d previous digest mismatch", chunk.Sequence)
		}
	}
}

func TestAssessmentRunIdempotencyBindsRequestBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	jobs := platformjobs.New(newRunJobStore(now))
	service := NewAssessmentService(store, &runLog{}, jobs, &testCollector{manifest: completeManifest(now), results: validResults(now, 1)})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)
	request := RunRequest{TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID, PeriodStart: now.Add(-time.Hour), PeriodEnd: now, IdempotencyKey: "same-key", RequestedBy: "assessor-1"}
	first, created, err := service.RequestRun(context.Background(), request)
	if err != nil || !created {
		t.Fatalf("first RequestRun() = (%#v, %v, %v)", first, created, err)
	}
	second, created, err := service.RequestRun(context.Background(), request)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("second RequestRun() = (%#v, %v, %v)", second, created, err)
	}
	request.PeriodStart = request.PeriodStart.Add(-time.Hour)
	if _, _, err := service.RequestRun(context.Background(), request); !errors.Is(err, ports.ErrJobIdempotencyConflict) {
		t.Fatalf("changed request error = %v", err)
	}
}

func TestIncompleteManifestFailsWithoutTerminalResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	jobs := platformjobs.New(newRunJobStore(now))
	manifest := completeManifest(now)
	manifest.Receipts[0].Completeness = CollectionTruncated
	service := NewAssessmentService(store, &runLog{}, jobs, &testCollector{manifest: manifest, results: validResults(now, 1)})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)
	run, _, err := service.RequestRun(context.Background(), RunRequest{TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID, PeriodStart: now.Add(-time.Hour), PeriodEnd: now, IdempotencyKey: "incomplete", RequestedBy: "assessor-1"})
	if err != nil {
		t.Fatal(err)
	}
	_ = jobs.Wait(context.Background())
	failed, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != RunFailed || failed.FailureCode != "collection_incomplete" || failed.AutomatedResultHash != "" {
		t.Fatalf("failed run = %#v", failed)
	}
}

func TestAssessmentRunnerDoesNotReexecuteTerminalRun(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	for _, state := range []string{RunComplete, RunFailed, RunCancelled, RunSuperseded} {
		state := state
		t.Run(state, func(t *testing.T) {
			store := newRunStore()
			run := AssessmentRun{ID: "run-1", TenantID: "tenant-1", State: state, Version: 3}
			store.runs[runKey(run.TenantID, run.ID)] = run
			collector := &testCollector{err: errors.New("terminal run was re-executed")}
			service := NewAssessmentService(store, &runLog{}, platformjobs.New(newRunJobStore(now)), collector)

			result, refs, err := service.Runner()(context.Background(), &ports.Job{
				TenantID: run.TenantID,
				Payload:  map[string]any{"run_id": run.ID},
			}, nil)
			if err != nil {
				t.Fatalf("Runner() error = %v", err)
			}
			if result["state"] != state || refs["assessment_run"] != run.ID {
				t.Fatalf("Runner() = (%v, %v), want terminal state %q", result, refs, state)
			}
			if collector.calls != 0 {
				t.Fatalf("collector calls = %d, want 0", collector.calls)
			}
		})
	}
}

func TestAssessmentResultProjectionFailureMarksRunFailed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	store.applyChunkErr = errors.New("result projection unavailable")
	jobs := platformjobs.New(newRunJobStore(now))
	service := NewAssessmentService(store, &runLog{}, jobs, &testCollector{manifest: completeManifest(now), results: validResults(now, 1)})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)
	run, _, err := service.RequestRun(context.Background(), RunRequest{
		TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID,
		PeriodStart: now.Add(-time.Hour), PeriodEnd: now,
		IdempotencyKey: "projection-failure", RequestedBy: "assessor-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	failed, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != RunFailed || failed.FailureCode != "result_projection_failed" {
		t.Fatalf("failed run = %#v", failed)
	}
}

func TestRunRequestAppendFailurePreventsProjectionAndEnqueue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	log := &runLog{err: errors.New("append unavailable")}
	jobStore := newRunJobStore(now)
	jobs := platformjobs.New(jobStore)
	service := NewAssessmentService(store, log, jobs, &testCollector{})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	_, err := service.RecordPlan(context.Background(), validPlan(now), "owner-1", 0)
	if err == nil {
		t.Fatal("RecordPlan() unexpectedly succeeded with failed append")
	}
	if len(store.plans) != 0 || len(jobStore.jobs) != 0 {
		t.Fatalf("state changed after append failure: plans=%d jobs=%d", len(store.plans), len(jobStore.jobs))
	}
}

func TestReconcileUnboundRunStartsExistingQueuedJob(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newRunStore()
	jobStore := newRunJobStore(now)
	jobs := platformjobs.New(jobStore)
	service := NewAssessmentService(store, &runLog{}, jobs, &testCollector{manifest: completeManifest(now), results: validResults(now, 1)})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)

	store.applyRunVersion = 2
	store.applyRunErr = errors.New("run projection unavailable")
	run, _, err := service.RequestRun(context.Background(), RunRequest{
		TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID,
		PeriodStart: now.Add(-time.Hour), PeriodEnd: now,
		IdempotencyKey: "recover-existing-job", RequestedBy: "assessor-1",
	})
	if err == nil || run.ID == "" || run.JobID == "" {
		t.Fatalf("RequestRun() = (%#v, %v), want run and binding projection error", run, err)
	}
	persisted, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.JobID != "" || persisted.State != RunQueued {
		t.Fatalf("persisted run = %#v, want queued without a job binding", persisted)
	}

	store.applyRunErr = nil
	bound, err := service.ReconcileUnboundRuns(context.Background(), 10)
	if err != nil || bound != 1 {
		t.Fatalf("ReconcileUnboundRuns() = (%d, %v), want (1, nil)", bound, err)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	completed, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != RunComplete || completed.JobID != run.JobID {
		t.Fatalf("completed run = %#v, want completed with recovered job %q", completed, run.JobID)
	}
}

func recordPublishedPlan(t *testing.T, service *Service, now time.Time) AssessmentPlanRevision {
	t.Helper()
	plan, err := service.RecordPlan(context.Background(), validPlan(now), "owner-1", 0)
	if err != nil {
		t.Fatalf("RecordPlan() error = %v", err)
	}
	plan, err = service.PublishPlan(context.Background(), plan.TenantID, plan.ID, "approver-1", plan.Version)
	if err != nil {
		t.Fatalf("PublishPlan() error = %v", err)
	}
	return plan
}

func validPlan(now time.Time) AssessmentPlanRevision {
	return AssessmentPlanRevision{
		TenantID: "tenant-1", Name: "Annual access assessment", Status: PlanDraft,
		Scope:      PlanScope{ProgramID: "program-1", ScopeRevisionID: "scope-revision-1", ImplementationRevisions: []string{"implementation-revision-1"}, ObjectiveIDs: []string{"objective-1"}},
		Execution:  PlanExecution{Methods: []string{"test"}, Depth: "moderate", CoverageTarget: "complete", AssuranceTarget: "high", OrderedTaskIDs: []string{"task-1"}, CancellationRule: "stop_after_checkpoint"},
		Governance: PlanGovernance{OwnerID: "owner-1", AssessorIDs: []string{"assessor-1"}, ApproverIDs: []string{"approver-1"}, IndependenceRule: "approver_not_assessor", RulesOfEngagement: "Read-only source access."},
		CreatedAt:  now, CreatedBy: "owner-1",
	}
}

func completeManifest(now time.Time) InputManifest {
	total := uint64(1)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return InputManifest{
		ProgramID: "program-1", ScopeRevisionID: "scope-revision-1", PlanRevisionID: "plan-revision-1",
		PeriodStart: now.Add(-24 * time.Hour), PeriodEnd: now, CollectionCutoff: now,
		RequestedScopeDigest: digest, ResolvedObjectiveSetDigest: digest, MappingSetDigest: digest,
		Revisions: []ManifestRevision{{Kind: "plan", ID: "plan-1", RevisionID: "plan-revision-1", Version: 1, Digest: digest}},
		Receipts:  []CollectionReceipt{{Kind: "findings", QueryDigest: digest, PageIndex: 0, RawCount: 1, Deduplicated: 1, Included: 1, ExpectedTotal: &total, Watermark: now, Cutoff: now, Completeness: CollectionComplete, PageDigest: digest}},
	}
}

func validResults(now time.Time, count int) []ObjectiveResult {
	results := make([]ObjectiveResult, 0, count)
	for index := 0; index < count; index++ {
		results = append(results, ObjectiveResult{
			ID: fmt.Sprintf("result-%04d", index), ControlRef: compliance.ControlRef{FrameworkID: "framework-1", ControlID: "control-1"},
			ObjectiveID: fmt.Sprintf("objective-%04d", index), ScopeState: ScopeInScope,
			AutomatedOutcome: OutcomeSatisfied, DesignState: DesignEffective, OperatingEffectivenessState: OperatingEffective,
			EvidenceState: EvidenceSufficient, DispositionState: DispositionNone, Assurance: AssuranceHigh,
			AuditorState: AuditorNotReviewed, ReasonCodes: []ReasonCode{ReasonSatisfied}, NextActions: []NextAction{ActionNone},
			EvaluatorRevision: "evaluator-1", EvaluatedAt: now,
		})
	}
	return results
}

type testCollector struct {
	manifest InputManifest
	results  []ObjectiveResult
	err      error
	calls    int
}

func (c *testCollector) Collect(context.Context, AssessmentRun) (InputManifest, []ObjectiveResult, error) {
	c.calls++
	return c.manifest, append([]ObjectiveResult(nil), c.results...), c.err
}

type runLog struct {
	mu     sync.Mutex
	events []*cerebrov1.EventEnvelope
	err    error
}

func (l *runLog) Ping(context.Context) error { return nil }
func (l *runLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.events = append(l.events, event)
	return nil
}

type runStore struct {
	mu              sync.Mutex
	plans           map[string]AssessmentPlanRevision
	runs            map[string]AssessmentRun
	byKey           map[string]string
	chunks          map[string]map[uint32]ResultChunk
	events          map[string]struct{}
	applyRunVersion uint64
	applyRunErr     error
	applyChunkErr   error
}

func newRunStore() *runStore {
	return &runStore{plans: map[string]AssessmentPlanRevision{}, runs: map[string]AssessmentRun{}, byKey: map[string]string{}, chunks: map[string]map[uint32]ResultChunk{}, events: map[string]struct{}{}}
}

func runKey(tenantID, id string) string { return tenantID + "\x00" + id }
func (s *runStore) ApplyPlan(_ context.Context, eventID string, plan AssessmentPlanRevision, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[eventID]; ok {
		return nil
	}
	key := runKey(plan.TenantID, plan.ID)
	existing, ok := s.plans[key]
	if (ok && existing.Version != expected) || (!ok && expected != 0) {
		return ErrAssessmentConflict
	}
	s.events[eventID] = struct{}{}
	s.plans[key] = plan
	s.plans[runKey(plan.TenantID, plan.RevisionID)] = plan
	return nil
}
func (s *runStore) GetPlan(_ context.Context, tenantID, id string) (AssessmentPlanRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, ok := s.plans[runKey(tenantID, id)]
	if !ok {
		return AssessmentPlanRevision{}, ErrPlanNotFound
	}
	return plan, nil
}
func (s *runStore) ApplyRun(_ context.Context, eventID string, run AssessmentRun, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run.Version == s.applyRunVersion && s.applyRunErr != nil {
		return s.applyRunErr
	}
	if _, ok := s.events[eventID]; ok {
		return nil
	}
	key := runKey(run.TenantID, run.ID)
	existing, ok := s.runs[key]
	if (ok && existing.Version != expected) || (!ok && expected != 0) {
		return ErrAssessmentConflict
	}
	s.events[eventID] = struct{}{}
	s.runs[key] = run
	s.byKey[runKey(run.TenantID, run.IdempotencyKey)] = run.ID
	return nil
}
func (s *runStore) GetRun(_ context.Context, tenantID, id string) (AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runKey(tenantID, id)]
	if !ok {
		return AssessmentRun{}, ErrRunNotFound
	}
	return run, nil
}
func (s *runStore) FindRunByIdempotency(_ context.Context, tenantID, key string) (AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.byKey[runKey(tenantID, key)]
	if id == "" {
		return AssessmentRun{}, ErrRunNotFound
	}
	return s.runs[runKey(tenantID, id)], nil
}
func (s *runStore) ListUnboundRuns(context.Context, uint32) ([]AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []AssessmentRun
	for _, run := range s.runs {
		if run.JobID == "" && run.State == RunQueued {
			result = append(result, run)
		}
	}
	return result, nil
}
func (s *runStore) ApplyResultChunk(_ context.Context, eventID, tenantID string, chunk ResultChunk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyChunkErr != nil {
		return s.applyChunkErr
	}
	if _, ok := s.events[eventID]; ok {
		return nil
	}
	key := runKey(tenantID, chunk.RunID)
	if s.chunks[key] == nil {
		s.chunks[key] = map[uint32]ResultChunk{}
	}
	if existing, ok := s.chunks[key][chunk.Sequence]; ok && existing.Digest != chunk.Digest {
		return ErrAssessmentConflict
	}
	s.events[eventID] = struct{}{}
	s.chunks[key][chunk.Sequence] = chunk
	return nil
}
func (s *runStore) ListResultChunks(_ context.Context, tenantID, runID string) ([]ResultChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySequence := s.chunks[runKey(tenantID, runID)]
	result := make([]ResultChunk, 0, len(bySequence))
	for _, chunk := range bySequence {
		result = append(result, chunk)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Sequence < result[j].Sequence })
	return result, nil
}

type runJobStore struct {
	mu    sync.Mutex
	now   time.Time
	jobs  map[string]*ports.Job
	byKey map[string]*ports.Job
}

func newRunJobStore(now time.Time) *runJobStore {
	return &runJobStore{now: now, jobs: map[string]*ports.Job{}, byKey: map[string]*ports.Job{}}
}
func (s *runJobStore) Ping(context.Context) error { return nil }
func (s *runJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.byKey[request.IdempotencyKey]; existing != nil {
		return cloneRunJob(existing), false, nil
	}
	id := fmt.Sprintf("job-%d", len(s.jobs)+1)
	job := &ports.Job{ID: id, Kind: request.Kind, Status: ports.JobStatusQueued, TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, IdempotencyKey: request.IdempotencyKey, RequestHash: request.RequestHash, Payload: request.Payload, CreatedAt: s.now, UpdatedAt: s.now}
	s.jobs[id] = job
	s.byKey[request.IdempotencyKey] = job
	return cloneRunJob(job), true, nil
}
func (s *runJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	return cloneRunJob(job), nil
}
func (s *runJobStore) ListJobs(context.Context, ports.JobFilter) ([]*ports.Job, error) {
	return nil, nil
}
func (s *runJobStore) CountJobs(context.Context, ports.JobFilter) (uint64, error) { return 0, nil }
func (s *runJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
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
	return cloneRunJob(job), nil
}
func (s *runJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	return &event, nil
}
func (s *runJobStore) ListJobEvents(context.Context, string, uint32) ([]*ports.JobEvent, error) {
	return nil, nil
}
func cloneRunJob(job *ports.Job) *ports.Job {
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
