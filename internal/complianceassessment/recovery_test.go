package complianceassessment

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var errTestProjectionUnavailable = errors.New("projection unavailable")

func TestValidateRecoveredAggregateRejectsOverflowVersion(t *testing.T) {
	record := &workflowevents.ComplianceAggregateRecorded{
		AggregateType:    "assessment_run",
		TenantID:         "tenant-1",
		AggregateID:      "run-1",
		AggregateVersion: math.MaxInt64,
	}
	if err := validateRecoveredAggregate(record, "assessment_run", "tenant-1", "run-1", "", uint64(math.MaxInt64)+1); err == nil {
		t.Fatal("validateRecoveredAggregate() error = nil, want overflow rejection")
	}
}

func TestProjectEventRejectsResultChunkDigestThatDoesNotBindResults(t *testing.T) {
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	results := validResults(now, 1)
	chunk := ResultChunk{
		RunID: "run-1", Sequence: 1, FirstResultID: results[0].ID, LastResultID: results[0].ID,
		Count: 1, Digest: "sha256:" + strings.Repeat("a", 64), Results: results,
	}
	payload, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceResultChunkRecorded, TenantID: "tenant-1",
		AggregateType: "assessment_result_chunk", AggregateID: chunk.RunID,
		AggregateVersion: int64(chunk.Sequence), Operation: "result_chunk_recorded",
		ContentDigest: chunk.Digest, PayloadJSON: string(payload), ActorID: "assessor-1",
		RecordedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewAssessmentService(newRunStore(), &runLog{}, nil, nil)
	if projected, err := service.ProjectEvent(context.Background(), event); err == nil || projected {
		t.Fatalf("ProjectEvent() = (%v, %v), want digest rejection", projected, err)
	}
}

func TestRecoverProjectionsRebindsAndRunsAppendedRequest(t *testing.T) {
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	baseStore := newRunStore()
	store := &failRunProjectionOnceStore{runStore: baseStore, fail: true}
	log := &runLog{}
	jobs := platformjobs.New(newRunJobStore(now))
	service := NewAssessmentService(store, log, jobs, nil)
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)

	_, _, err := service.RequestRun(context.Background(), RunRequest{
		TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID,
		PeriodStart: now.Add(-time.Hour), PeriodEnd: now,
		IdempotencyKey: "recover-request", RequestedBy: "assessor-1",
	})
	if !errors.Is(err, errTestProjectionUnavailable) {
		t.Fatalf("RequestRun() error = %v, want projection failure", err)
	}
	if len(baseStore.runs) != 0 {
		t.Fatalf("runs after projection failure = %d, want 0", len(baseStore.runs))
	}

	log.mu.Lock()
	events := append([]*cerebrov1.EventEnvelope(nil), log.events...)
	log.mu.Unlock()
	service.WithEventReplayPager(&assessmentEventPager{events: events})
	processed, err := service.RecoverProjections(context.Background(), 2)
	if err != nil {
		t.Fatalf("RecoverProjections() error = %v", err)
	}
	if processed != len(events) {
		t.Fatalf("RecoverProjections() processed = %d, want %d", processed, len(events))
	}
	bound, err := service.ReconcileUnboundRuns(context.Background(), 10)
	if err != nil || bound != 1 {
		t.Fatalf("ReconcileUnboundRuns() = (%d, %v), want (1, nil)", bound, err)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	runs, err := baseStore.ListUnboundRuns(context.Background(), 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("ListUnboundRuns() = (%#v, %v), want empty", runs, err)
	}
	baseStore.mu.Lock()
	var recovered AssessmentRun
	for _, candidate := range baseStore.runs {
		recovered = candidate
		break
	}
	baseStore.mu.Unlock()
	read, err := baseStore.GetRun(context.Background(), recovered.TenantID, recovered.ID)
	if err != nil {
		t.Fatalf("GetRun() error = %v", err)
	}
	if read.State != RunFailed || read.FailureCode != "collector_unavailable" || read.JobID == "" {
		t.Fatalf("recovered run = %#v", read)
	}
}

type failRunProjectionOnceStore struct {
	*runStore
	fail bool
}

func (s *failRunProjectionOnceStore) ApplyRun(ctx context.Context, eventID string, run AssessmentRun, expected uint64) error {
	if s.fail {
		s.fail = false
		return errTestProjectionUnavailable
	}
	return s.runStore.ApplyRun(ctx, eventID, run, expected)
}

type assessmentEventPager struct {
	events []*cerebrov1.EventEnvelope
}

func (p *assessmentEventPager) ReplayPage(_ context.Context, request ports.ReplayRequest) (ports.ReplayPage, error) {
	end := len(p.events)
	if request.Cursor != "" {
		parsed, err := strconv.Atoi(request.Cursor)
		if err != nil || parsed < 0 || parsed > len(p.events) {
			return ports.ReplayPage{}, ports.ErrReplayCursorNotFound
		}
		end = parsed
	}
	limit := int(request.Limit)
	if limit <= 0 {
		limit = len(p.events)
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	page := ports.ReplayPage{Events: append([]*cerebrov1.EventEnvelope(nil), p.events[start:end]...), Complete: start == 0}
	if !page.Complete {
		page.NextCursor = strconv.Itoa(start)
	}
	return page, nil
}
