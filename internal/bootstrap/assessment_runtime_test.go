package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/config"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func TestNewRegistersAssessmentRuntimeWhenDurableCapabilitiesExist(t *testing.T) {
	store := &assessmentRuntimeStore{
		a2ATestJobStore: newA2ATestJobStore(),
		runs: map[string]complianceassessment.AssessmentRun{
			"tenant-1\x00run-1": {ID: "run-1", TenantID: "tenant-1", State: complianceassessment.RunQueued, Version: 1},
		},
	}
	log := &assessmentRuntimeLog{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store, AppendLog: log}, nil)
	if app.services.assessments == nil {
		t.Fatal("assessment service = nil, want configured service")
	}
	job, created, err := app.jobService().Create(context.Background(), ports.CreateJobRequest{
		Kind: complianceassessment.JobKindComplianceAssessment, TenantID: "tenant-1",
		SubjectType: "assessment_run", SubjectID: "run-1", IdempotencyKey: "assessment-run:run-1",
		Payload: map[string]any{"run_id": "run-1", "tenant_id": "tenant-1"},
	})
	if err != nil || !created || job.Kind != complianceassessment.JobKindComplianceAssessment {
		t.Fatalf("Create() = (%#v, %v, %v)", job, created, err)
	}
	tenantID, err := authorizeJobCreate(context.Background(), store, createJobHTTPRequest{
		Kind: complianceassessment.JobKindComplianceAssessment, TenantID: "tenant-1",
		SubjectID: "run-1", Payload: map[string]any{"run_id": "run-1"},
	})
	if err != nil || tenantID != "tenant-1" {
		t.Fatalf("authorizeJobCreate() = (%q, %v)", tenantID, err)
	}
	if _, err := app.RecoverPlatformJobs(context.Background()); err != nil {
		t.Fatalf("RecoverPlatformJobs() error = %v", err)
	}
}

func TestNewLeavesAssessmentRuntimeDisabledWithoutReplayPager(t *testing.T) {
	store := &assessmentRuntimeStore{a2ATestJobStore: newA2ATestJobStore()}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	if app.services.assessments != nil {
		t.Fatal("assessment service configured without append-log replay")
	}
}

func TestNormalizeAssessmentJobRequestPinsRunIdentity(t *testing.T) {
	request := createJobHTTPRequest{
		Kind: complianceassessment.JobKindComplianceAssessment, TenantID: "tenant-1",
		Payload: map[string]any{"run_id": "run-1"},
	}
	if err := normalizeAssessmentJobRequest(&request); err != nil {
		t.Fatalf("normalizeAssessmentJobRequest() error = %v", err)
	}
	if request.SubjectType != "assessment_run" || request.SubjectID != "run-1" || request.IdempotencyKey != "assessment-run:run-1" {
		t.Fatalf("normalized request = %#v", request)
	}
	request.IdempotencyKey = "different"
	if err := normalizeAssessmentJobRequest(&request); err == nil {
		t.Fatal("normalizeAssessmentJobRequest() accepted conflicting idempotency key")
	}
}

func TestStartPlatformJobRecoveryIncludesAssessmentLoop(t *testing.T) {
	store := &assessmentRuntimeStore{a2ATestJobStore: newA2ATestJobStore()}
	app := &App{}
	app.services.jobs = platformjobs.New(store)
	app.services.assessments = complianceassessment.NewAssessmentService(store, &assessmentRuntimeLog{}, app.services.jobs, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := app.StartPlatformJobRecovery(ctx, nil)
	select {
	case <-done:
		cancel()
		t.Fatal("platform recovery stopped while assessment recovery was active")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("platform recovery did not stop after cancellation")
	}
}

func TestStartPlatformJobRecoveryDoesNotBlockOnProjectionReplay(t *testing.T) {
	started := make(chan struct{})
	store := &assessmentRuntimeStore{a2ATestJobStore: newA2ATestJobStore()}
	log := &blockingAssessmentRuntimeLog{started: started}
	app := &App{}
	app.services.jobs = platformjobs.New(store)
	app.services.assessments = complianceassessment.NewAssessmentService(
		store,
		log,
		app.services.jobs,
		nil,
	).WithEventReplayPager(log)
	ctx, cancel := context.WithCancel(context.Background())
	done := app.StartPlatformJobRecovery(ctx, nil)

	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("projection replay did not start asynchronously")
	}
	select {
	case <-done:
		cancel()
		t.Fatal("platform recovery stopped while projection replay was active")
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("platform recovery did not stop after projection replay cancellation")
	}
}

func TestStartPlatformJobRecoveryRetriesProjectionReplayBeforeContinuousRecovery(t *testing.T) {
	recovered := make(chan struct{})
	log := &retryingAssessmentRuntimeLog{recovered: recovered}
	store := &assessmentRuntimeStore{a2ATestJobStore: newA2ATestJobStore()}
	app := &App{}
	app.services.jobs = platformjobs.New(store)
	app.services.assessments = complianceassessment.NewAssessmentService(store, log, app.services.jobs, nil).WithEventReplayPager(log)
	ctx, cancel := context.WithCancel(context.Background())
	logged := make(chan string, 1)
	done := app.startPlatformJobRecovery(ctx, func(format string, args ...any) {
		logged <- fmt.Sprintf(format, args...)
	}, time.Millisecond)

	select {
	case <-recovered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("projection replay was not retried")
	}
	select {
	case message := <-logged:
		if !strings.Contains(message, "temporary replay failure") {
			cancel()
			t.Fatalf("recovery log = %q, want replay failure", message)
		}
	default:
		cancel()
		t.Fatal("initial projection replay failure was not logged")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("platform recovery did not stop after retry cancellation")
	}
}

type assessmentRuntimeLog struct{}

func (*assessmentRuntimeLog) Ping(context.Context) error                             { return nil }
func (*assessmentRuntimeLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return nil }
func (*assessmentRuntimeLog) ReplayPage(context.Context, ports.ReplayRequest) (ports.ReplayPage, error) {
	return ports.ReplayPage{Complete: true}, nil
}

type blockingAssessmentRuntimeLog struct {
	started chan struct{}
}

type retryingAssessmentRuntimeLog struct {
	calls     atomic.Uint32
	recovered chan struct{}
}

func (*retryingAssessmentRuntimeLog) Ping(context.Context) error { return nil }
func (*retryingAssessmentRuntimeLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}
func (l *retryingAssessmentRuntimeLog) ReplayPage(context.Context, ports.ReplayRequest) (ports.ReplayPage, error) {
	if l.calls.Add(1) == 1 {
		return ports.ReplayPage{}, errors.New("temporary replay failure")
	}
	select {
	case <-l.recovered:
	default:
		close(l.recovered)
	}
	return ports.ReplayPage{Complete: true}, nil
}

func (*blockingAssessmentRuntimeLog) Ping(context.Context) error { return nil }
func (*blockingAssessmentRuntimeLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}
func (l *blockingAssessmentRuntimeLog) ReplayPage(ctx context.Context, _ ports.ReplayRequest) (ports.ReplayPage, error) {
	select {
	case <-l.started:
	default:
		close(l.started)
	}
	<-ctx.Done()
	return ports.ReplayPage{}, ctx.Err()
}

type assessmentRuntimeStore struct {
	*a2ATestJobStore
	runs map[string]complianceassessment.AssessmentRun
}

func (s *assessmentRuntimeStore) ApplyPlan(context.Context, string, complianceassessment.AssessmentPlanRevision, uint64) error {
	return nil
}
func (s *assessmentRuntimeStore) GetPlan(context.Context, string, string) (complianceassessment.AssessmentPlanRevision, error) {
	return complianceassessment.AssessmentPlanRevision{}, complianceassessment.ErrPlanNotFound
}
func (s *assessmentRuntimeStore) ApplyRun(_ context.Context, _ string, run complianceassessment.AssessmentRun, _ uint64) error {
	if s.runs == nil {
		s.runs = map[string]complianceassessment.AssessmentRun{}
	}
	s.runs[run.TenantID+"\x00"+run.ID] = run
	return nil
}
func (s *assessmentRuntimeStore) GetRun(_ context.Context, tenantID, id string) (complianceassessment.AssessmentRun, error) {
	run, ok := s.runs[tenantID+"\x00"+id]
	if !ok {
		return complianceassessment.AssessmentRun{}, complianceassessment.ErrRunNotFound
	}
	return run, nil
}
func (s *assessmentRuntimeStore) FindRunByIdempotency(context.Context, string, string) (complianceassessment.AssessmentRun, error) {
	return complianceassessment.AssessmentRun{}, complianceassessment.ErrRunNotFound
}
func (s *assessmentRuntimeStore) ListUnboundRuns(context.Context, uint32) ([]complianceassessment.AssessmentRun, error) {
	return nil, nil
}
func (s *assessmentRuntimeStore) ApplyResultChunk(context.Context, string, string, complianceassessment.ResultChunk) error {
	return nil
}
func (s *assessmentRuntimeStore) ListResultChunks(context.Context, string, string) ([]complianceassessment.ResultChunk, error) {
	return nil, nil
}
