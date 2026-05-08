package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func TestAppendOrchestratorRunBoundsForeverHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 3; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, true)
	}
	if len(runs) != 1 || runs[0].Iteration != 3 {
		t.Fatalf("forever runs = %#v, want only latest iteration", runs)
	}
}

func TestAppendOrchestratorRunPreservesFiniteHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 2; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, false)
	}
	if len(runs) != 2 || runs[0].Iteration != 1 || runs[1].Iteration != 2 {
		t.Fatalf("finite runs = %#v, want all iterations", runs)
	}
}

func TestShouldPrintOrchestratorResultSkipsNilStartupFailure(t *testing.T) {
	if shouldPrintOrchestratorResult(nil) {
		t.Fatal("shouldPrintOrchestratorResult(nil) = true, want false")
	}
	if !shouldPrintOrchestratorResult(&orchestratorResult{}) {
		t.Fatal("shouldPrintOrchestratorResult(non-nil) = false, want true")
	}
}

func TestParseOrchestratorOptionsRejectsZeroLimit(t *testing.T) {
	if _, err := parseOrchestratorOptions([]string{"limit=0"}); err == nil {
		t.Fatal("parseOrchestratorOptions(limit=0) error = nil, want error")
	}
}

func TestParseOrchestratorOptionsAcceptsRuntimeID(t *testing.T) {
	options, err := parseOrchestratorOptions([]string{"runtime_id=writer-okta-audit"})
	if err != nil {
		t.Fatalf("parseOrchestratorOptions(runtime_id) error = %v", err)
	}
	if got := options.Filter.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("runtime filter = %q, want writer-okta-audit", got)
	}
}

func TestOrchestratorShutdownSignalsIncludeSIGTERM(t *testing.T) {
	signals := orchestratorShutdownSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("orchestratorShutdownSignals() = %#v, want interrupt and SIGTERM", signals)
	}
}

func TestRunOrchestratorIterationStopsAfterSyncFailure(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	if result.Runtimes[0].FindingRules != "" || result.Runtimes[0].GraphIngest != "" {
		t.Fatalf("downstream stages ran after sync failure: %#v", result.Runtimes[0])
	}
	if store.leaseID != "runtime-1" || store.releaseID != "runtime-1" {
		t.Fatalf("lease/release = %q/%q, want runtime-1/runtime-1", store.leaseID, store.releaseID)
	}
}

func TestRunOrchestratorIterationPreservesGraphCountersOnPartialFailure(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry(orchestratorNoopRule{})
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{
			Id:       "runtime-1",
			SourceId: "github",
			TenantId: "writer",
		},
		acquired: true,
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := &failingCompletedIngestGraphStore{graphTestStore: newGraphTestStore()}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry),
		graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore),
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want graph ingest completion failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	runtimeResult := result.Runtimes[0]
	if runtimeResult.GraphIngest != "failed" {
		t.Fatalf("graph ingest status = %q, want failed", runtimeResult.GraphIngest)
	}
	if runtimeResult.EntitiesProjected != 6 || runtimeResult.LinksProjected != 6 {
		t.Fatalf("graph counters = %d/%d, want 6/6", runtimeResult.EntitiesProjected, runtimeResult.LinksProjected)
	}
}

func TestAcquireOrchestratorRuntimeLeaseClaimsRuntime(t *testing.T) {
	store := &leaseRuntimeStore{acquired: true}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}

	acquired, err := acquireOrchestratorRuntimeLease(context.Background(), store, runtime, "owner-1")
	if err != nil {
		t.Fatalf("acquireOrchestratorRuntimeLease() error = %v", err)
	}
	if !acquired {
		t.Fatal("acquireOrchestratorRuntimeLease() = false, want true")
	}
	if store.leaseID != "runtime-1" || store.leaseOwner != "owner-1" || store.leaseTTL != defaultSourceRuntimeLeaseTTL {
		t.Fatalf("lease = (%q, %q, %s), want runtime-1 owner-1 %s", store.leaseID, store.leaseOwner, store.leaseTTL, defaultSourceRuntimeLeaseTTL)
	}
}

func TestReleaseOrchestratorRuntimeLeaseIgnoresCancellation(t *testing.T) {
	store := &leaseRuntimeStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := releaseOrchestratorRuntimeLease(ctx, store, runtime, "owner-1"); err != nil {
		t.Fatalf("releaseOrchestratorRuntimeLease() error = %v", err)
	}
	if store.releaseContextErr != nil {
		t.Fatalf("release context err = %v, want nil", store.releaseContextErr)
	}
	if !store.releaseHasDeadline {
		t.Fatal("release context has no deadline")
	}
	if time.Until(store.releaseDeadline) > sourceRuntimeLeaseReleaseTimeout {
		t.Fatalf("release deadline = %s, want within %s", store.releaseDeadline, sourceRuntimeLeaseReleaseTimeout)
	}
}

func TestSourceRuntimeLeaseRenewalIntervalUsesHalfTTL(t *testing.T) {
	if got := sourceRuntimeLeaseRenewalInterval(30 * time.Minute); got != 15*time.Minute {
		t.Fatalf("sourceRuntimeLeaseRenewalInterval() = %s, want 15m", got)
	}
}

func TestOrchestratorListFilterRequestsAllByDefault(t *testing.T) {
	if got := orchestratorListFilter(ports.SourceRuntimeFilter{}).Limit; got != ^uint32(0) {
		t.Fatalf("orchestratorListFilter(default).Limit = %d, want max uint32", got)
	}
}

func TestOrchestratorListFilterPreservesRuntimeID(t *testing.T) {
	filter := orchestratorListFilter(ports.SourceRuntimeFilter{RuntimeID: "writer-okta-audit", Limit: 1})
	if got := filter.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("orchestratorListFilter().RuntimeID = %q, want writer-okta-audit", got)
	}
}

func TestLeaseRenewalFailureCancelsRuntimeWork(t *testing.T) {
	store := &leaseRuntimeStore{renewed: false}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}
	workCtx, cancelWork := context.WithCancel(context.Background())
	stopRenewal := startOrchestratorRuntimeLeaseRenewalWithTTL(context.Background(), store, runtime, "owner-1", cancelWork, time.Millisecond)

	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime work context was not canceled after lease renewal failed")
	}
	if err := stopRenewal(); err == nil {
		t.Fatal("stopRenewal() error = nil, want lease lost error")
	}
}

func TestRunOrchestratorIterationSkipsLockedRuntime(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: false,
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{},
		1,
	)
	if err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v", err)
	}
	if got := result.Runtimes[0].Sync; got != "skipped" {
		t.Fatalf("runtime sync status = %q, want skipped", got)
	}
}

func TestRunOrchestratorIterationContinuesPastLockedRuntimeWithLimit(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtimes: []*cerebrov1.SourceRuntime{
			{Id: "locked-runtime", SourceId: "missing-source"},
			{Id: "unlocked-runtime", SourceId: "missing-source"},
		},
		acquiredByID: map[string]bool{
			"locked-runtime":   false,
			"unlocked-runtime": true,
		},
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{Filter: ports.SourceRuntimeFilter{Limit: 1}},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want unlocked runtime sync failure")
	}
	if store.listFilter.Limit != 1+sourceRuntimeLeaseOverscanLimit {
		t.Fatalf("list limit = %d, want overscan limit", store.listFilter.Limit)
	}
	if got := len(result.Runtimes); got != 2 {
		t.Fatalf("runtime result count = %d, want locked skip plus unlocked attempt", got)
	}
	if result.Runtimes[0].RuntimeID != "locked-runtime" || result.Runtimes[0].Sync != "skipped" {
		t.Fatalf("first runtime result = %#v, want locked skip", result.Runtimes[0])
	}
	if result.Runtimes[1].RuntimeID != "unlocked-runtime" {
		t.Fatalf("second runtime id = %q, want unlocked-runtime", result.Runtimes[1].RuntimeID)
	}
}

func TestRunOrchestratorIterationStopsBeforeRuntimeWhenContextCanceled(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := runOrchestratorIteration(
		ctx,
		store,
		store,
		"test-owner",
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want context cancellation")
	}
	if got := len(result.Runtimes); got != 0 {
		t.Fatalf("runtime result count = %d, want 0", got)
	}
}

type leaseRuntimeStore struct {
	leaseID            string
	leaseOwner         string
	leaseTTL           time.Duration
	releaseContextErr  error
	releaseHasDeadline bool
	releaseDeadline    time.Time
	acquired           bool
	renewed            bool
}

func (s *leaseRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	s.leaseID = runtimeID
	s.leaseOwner = owner
	s.leaseTTL = ttl
	return s.acquired, nil
}

func (s *leaseRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return s.renewed, nil
}

func (s *leaseRuntimeStore) ReleaseSourceRuntimeLease(ctx context.Context, _ string, _ string) error {
	s.releaseContextErr = ctx.Err()
	s.releaseDeadline, s.releaseHasDeadline = ctx.Deadline()
	return nil
}

type orchestratorRuntimeStore struct {
	runtime      *cerebrov1.SourceRuntime
	runtimes     []*cerebrov1.SourceRuntime
	acquired     bool
	acquiredByID map[string]bool
	listFilter   ports.SourceRuntimeFilter
	leaseID      string
	releaseID    string
}

func (s *orchestratorRuntimeStore) Ping(context.Context) error { return nil }

func (s *orchestratorRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *orchestratorRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	for _, runtime := range s.runtimes {
		if runtime.GetId() == id {
			return runtime, nil
		}
	}
	return s.runtime, nil
}

func (s *orchestratorRuntimeStore) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	s.listFilter = filter
	if len(s.runtimes) > 0 {
		return s.runtimes, nil
	}
	return []*cerebrov1.SourceRuntime{s.runtime}, nil
}

func (s *orchestratorRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, _ string, _ time.Duration) (bool, error) {
	s.leaseID = runtimeID
	if s.acquiredByID != nil {
		return s.acquiredByID[runtimeID], nil
	}
	return s.acquired, nil
}

func (s *orchestratorRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (s *orchestratorRuntimeStore) ReleaseSourceRuntimeLease(_ context.Context, runtimeID string, _ string) error {
	s.releaseID = runtimeID
	return nil
}

type orchestratorTestSource struct{}

func (orchestratorTestSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"}
}

func (orchestratorTestSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (orchestratorTestSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (orchestratorTestSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{{
		Id:       "github-pr-515",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Attributes: map[string]string{
			"author":      "alice",
			"owner":       "writer",
			"pull_number": "515",
			"repository":  "writer/cerebro",
			"state":       "open",
		},
	}}}, nil
}

type orchestratorNoopRule struct{}

func (orchestratorNoopRule) Spec() *cerebrov1.RuleSpec {
	return &cerebrov1.RuleSpec{Id: "noop-rule", Name: "Noop rule"}
}

func (orchestratorNoopRule) SupportsRuntime(*cerebrov1.SourceRuntime) bool {
	return true
}

func (orchestratorNoopRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

type orchestratorEventLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *orchestratorEventLog) Ping(context.Context) error {
	return nil
}

func (l *orchestratorEventLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func (l *orchestratorEventLog) Replay(context.Context, ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	return nil, nil
}

type orchestratorFindingStore struct{}

func (s *orchestratorFindingStore) Ping(context.Context) error { return nil }

func (s *orchestratorFindingStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	return finding, nil
}

func (s *orchestratorFindingStore) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) ListFindings(context.Context, ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) UpdateFindingStatus(context.Context, ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) UpdateFindingAssignee(context.Context, ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) UpdateFindingDueDate(context.Context, ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) AddFindingNote(context.Context, ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) LinkFindingTicket(context.Context, ports.FindingTicketLink) (*ports.FindingRecord, error) {
	return nil, ports.ErrFindingNotFound
}

func (s *orchestratorFindingStore) PutFindingEvaluationRun(context.Context, *cerebrov1.FindingEvaluationRun) error {
	return nil
}

func (s *orchestratorFindingStore) GetFindingEvaluationRun(context.Context, string) (*cerebrov1.FindingEvaluationRun, error) {
	return nil, ports.ErrFindingEvaluationRunNotFound
}

func (s *orchestratorFindingStore) ListFindingEvaluationRuns(context.Context, ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) PutFindingEvidence(context.Context, *cerebrov1.FindingEvidence) error {
	return nil
}

func (s *orchestratorFindingStore) GetFindingEvidence(context.Context, string) (*cerebrov1.FindingEvidence, error) {
	return nil, ports.ErrFindingEvidenceNotFound
}

func (s *orchestratorFindingStore) ListFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	return nil, nil
}

func (s *orchestratorFindingStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	return claim, nil
}

func (s *orchestratorFindingStore) ListClaims(context.Context, ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	return nil, nil
}

type failingCompletedIngestGraphStore struct {
	*graphTestStore
}

func (s *failingCompletedIngestGraphStore) PutIngestRun(ctx context.Context, run graphstore.IngestRun) error {
	if run.Status == graphstore.IngestRunStatusCompleted {
		return errors.New("run completion failed")
	}
	return s.graphTestStore.PutIngestRun(ctx, run)
}
