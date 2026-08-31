package findings

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/panicsafe"
	"github.com/writer/cerebro/internal/ports"
)

func TestTrustedSourceResolutionKeepsStaleFindingOpenAtReplayLimit(t *testing.T) {
	t.Parallel()
	runtimeID := "runtime-okta"
	ruleID := "rule-a"
	rule, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{Id: ruleID, Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}}, triggerEventID: "different-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"stale": {ID: "stale", Fingerprint: "stale", TenantID: "tenant-1", RuntimeID: runtimeID, RuleID: ruleID, Status: findingStatusOpen, EventIDs: []string{"evaluated-event"}},
	}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{Id: "evaluated-event", TenantId: "tenant-1", SourceId: "okta", Kind: "okta.audit"}}},
		store, store, store, store, rule,
	).WithTrustedSourceResolution()

	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: runtimeID, RuleID: ruleID, EventLimit: 1, RuntimeLeaseHeld: true}); err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := store.findings["stale"].Status; got != findingStatusOpen {
		t.Fatalf("stale finding status = %q, want open when replay reaches its limit", got)
	}
}

func TestTrustedSourceResolutionKeepsEveryRuleOpenAtSharedReplayLimit(t *testing.T) {
	t.Parallel()
	runtimeID := "runtime-okta"
	registry, err := NewRegistry(
		&emittingRule{spec: &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}}, triggerEventID: "different-event"},
		&emittingRule{spec: &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"}, supportedSourceIDs: map[string]struct{}{"okta": {}}, triggerEventID: "different-event"},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"stale-a": {ID: "stale-a", Fingerprint: "stale-a", TenantID: "tenant-1", RuntimeID: runtimeID, RuleID: "rule-a", Status: findingStatusOpen, EventIDs: []string{"evaluated-event"}},
		"stale-b": {ID: "stale-b", Fingerprint: "stale-b", TenantID: "tenant-1", RuntimeID: runtimeID, RuleID: "rule-b", Status: findingStatusOpen, EventIDs: []string{"evaluated-event"}},
	}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{Id: "evaluated-event", TenantId: "tenant-1", SourceId: "okta", Kind: "okta.audit"}}},
		store, store, store, store, registry,
	).WithTrustedSourceResolution()

	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: runtimeID, EventLimit: 1, RuntimeLeaseHeld: true}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	for _, findingID := range []string{"stale-a", "stale-b"} {
		if got := store.findings[findingID].Status; got != findingStatusOpen {
			t.Fatalf("%s status = %q, want open when shared replay reaches its limit", findingID, got)
		}
	}
}

func TestTrustedFindingEvaluationRejectsRuntimeHeldBySync(t *testing.T) {
	t.Parallel()
	runtimeID := "runtime-okta"
	registry, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		available:        false,
	}
	replayer := &stubReplayer{}
	store := &stubFindingStore{}
	service := NewWithRegistry(runtimeStore, replayer, store, store, store, store, registry).WithTrustedSourceResolution()

	_, err = service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: runtimeID, RuleID: "rule-a"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want runtime unavailable while sync holds the lease", err)
	}
	if replayer.calls != 0 {
		t.Fatalf("Replay() calls = %d, want 0 without the runtime lease", replayer.calls)
	}
}

func TestTrustedFindingEvaluationHoldsRuntimeLeaseAcrossReplay(t *testing.T) {
	t.Parallel()
	runtimeID := "runtime-okta"
	registry, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		available:        true,
	}
	replayer := findingLeaseCheckingReplayer{runtimeStore: runtimeStore}
	store := &stubFindingStore{}
	service := NewWithRegistry(runtimeStore, replayer, store, store, store, store, registry).WithTrustedSourceResolution()

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: runtimeID, RuleID: "rule-a"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if runtimeStore.replayWithoutLease {
		t.Fatal("Replay() ran without the source runtime lease")
	}
	if runtimeStore.acquireCalls != 1 || runtimeStore.releaseCalls != 1 || runtimeStore.held {
		t.Fatalf("lease calls/state = acquire:%d release:%d held:%t, want 1/1/false", runtimeStore.acquireCalls, runtimeStore.releaseCalls, runtimeStore.held)
	}
	if result.Run.SourceDependencyComplete == nil || !result.Run.GetSourceDependencyComplete() {
		t.Fatal("leased evaluation did not retain a trusted source dependency envelope")
	}
}

func TestTrustedFindingEvaluationCancelsWhenRuntimeLeaseIsLost(t *testing.T) {
	t.Parallel()
	runtimeID := "runtime-okta"
	registry, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		available:        true,
		renewAvailable:   false,
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(runtimeStore, findingLeaseBlockingReplayer{}, store, store, store, store, registry).WithTrustedSourceResolution()
	service.findingEvaluationLeaseTTL = 30 * time.Millisecond

	_, err = service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: runtimeID, RuleID: "rule-a"})
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want source runtime lease loss", err)
	}
	if runtimeStore.renewCalls.Load() == 0 || runtimeStore.releaseCalls != 1 || runtimeStore.held {
		t.Fatalf("renew/release/state = %d/%d/%t, want renewal attempt, release, and no held lease", runtimeStore.renewCalls.Load(), runtimeStore.releaseCalls, runtimeStore.held)
	}
}

func TestTrustedFindingEvaluationCancelsWhenRuntimeLeaseRenewalPanics(t *testing.T) {
	runtimeID := "runtime-okta"
	registry, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"}, supportedSourceIDs: map[string]struct{}{"okta": {}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: trustedFindingRuntime(runtimeID, "okta", "audit", time.Now().UTC())}},
		available:        true,
		renewPanic:       true,
	}
	cancellationCause := make(chan error, 1)
	store := &stubFindingStore{}
	service := NewWithRegistry(runtimeStore, findingLeaseBlockingReplayer{cancellationCause: cancellationCause}, store, store, store, store, registry).WithTrustedSourceResolution()
	service.findingEvaluationLeaseTTL = 30 * time.Millisecond

	_, err = service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: runtimeID, RuleID: "rule-a"})
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, panicsafe.ErrTaskPanicked) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want lease loss preserving renewal panic", err)
	}
	select {
	case cause := <-cancellationCause:
		if !errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(cause, panicsafe.ErrTaskPanicked) {
			t.Fatalf("evaluation cancellation cause = %v, want lease loss preserving renewal panic", cause)
		}
	default:
		t.Fatal("evaluation did not observe renewal panic cancellation")
	}
	if store.upsertCount != 0 || len(store.evidence) != 0 {
		t.Fatalf("post-loss finding/evidence writes = %d/%d, want 0/0", store.upsertCount, len(store.evidence))
	}
	if runtimeStore.releaseCalls != 1 || runtimeStore.held {
		t.Fatalf("release calls/state = %d/%t, want 1/false", runtimeStore.releaseCalls, runtimeStore.held)
	}
}

func TestFindingEvaluationLeaseNormalReleaseDoesNotReportPanic(t *testing.T) {
	runtimeStore := &findingLeaseRuntimeStore{available: true, renewAvailable: true}
	service := &Service{
		runtimeStore:              runtimeStore,
		requireTrustedResolution:  true,
		findingEvaluationLeaseTTL: time.Hour,
	}
	for i := 0; i < 200; i++ {
		workCtx, release, trusted, err := service.acquireFindingEvaluationLease(context.Background(), "runtime-okta", false)
		if err != nil || !trusted {
			t.Fatalf("iteration %d: acquireFindingEvaluationLease() = (%t, %v), want true, nil", i, trusted, err)
		}
		if err := release(); err != nil {
			t.Fatalf("iteration %d: release() error = %v, want nil", i, err)
		}
		cause := context.Cause(workCtx)
		if !errors.Is(cause, context.Canceled) || errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) || errors.Is(cause, panicsafe.ErrTaskPanicked) {
			t.Fatalf("iteration %d: work cancellation cause = %v, want ordinary cancellation", i, cause)
		}
	}
}

func TestFindingEvaluationLeaseNormalReleaseSuppressesCanceledFalseRenewal(t *testing.T) {
	renewStarted := make(chan struct{}, 1)
	runtimeStore := &findingLeaseRuntimeStore{
		available:          true,
		renewStarted:       renewStarted,
		renewWaitForCancel: true,
	}
	service := &Service{
		runtimeStore:              runtimeStore,
		requireTrustedResolution:  true,
		findingEvaluationLeaseTTL: 10 * time.Millisecond,
	}
	workCtx, release, trusted, err := service.acquireFindingEvaluationLease(context.Background(), "runtime-okta", false)
	if err != nil || !trusted {
		t.Fatalf("acquireFindingEvaluationLease() = (%t, %v), want true, nil", trusted, err)
	}
	select {
	case <-renewStarted:
	case <-time.After(time.Second):
		t.Fatal("lease renewal did not start")
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v, want nil for cancellation-attributable false renewal", err)
	}
	cause := context.Cause(workCtx)
	if !errors.Is(cause, context.Canceled) || errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) || errors.Is(cause, panicsafe.ErrTaskPanicked) {
		t.Fatalf("work cancellation cause = %v, want ordinary cancellation", cause)
	}
}

func TestGraphEvaluationLeasesEverySourceDependency(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	okta := trustedFindingRuntime("runtime-okta", "okta", "user", now)
	github := trustedFindingRuntime("runtime-github", "github", "audit", now)
	rule := &sourceSnapshotGraphRule{
		multiSourceStubGraphRule: multiSourceStubGraphRule{
			stubGraphRule: stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "cross-source-rule"}}, supportedSources: []string{"okta", "github"},
		},
		definition: RuleDefinition{ID: "cross-source-rule", EventKinds: []string{"okta.user", "github.audit"}},
	}
	tests := []struct {
		name          string
		unavailableID string
		wantErr       bool
	}{
		{name: "all dependencies available"},
		{name: "dependency syncing", unavailableID: github.GetId(), wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtimeStore := &findingLeaseRuntimeStore{
				stubRuntimeStore:     &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{okta.GetId(): okta, github.GetId(): github}},
				available:            true,
				renewAvailable:       true,
				unavailableRuntimeID: test.unavailableID,
			}
			service := &Service{runtimeStore: runtimeStore, requireTrustedResolution: true}
			_, release, runtimes, trusted, err := service.acquireGraphEvaluationDependencyLeases(context.Background(), okta, []GraphRule{rule})
			if test.wantErr {
				if !errors.Is(err, ErrRuntimeUnavailable) || trusted || release == nil {
					t.Fatalf("dependency lease = (%v, %v), want runtime unavailable", trusted, err)
				}
				return
			}
			if err != nil || !trusted || len(runtimes) != 2 {
				t.Fatalf("dependency lease = (%d runtimes, %v, %v), want two trusted runtimes", len(runtimes), trusted, err)
			}
			if err := release(); err != nil {
				t.Fatalf("release() error = %v", err)
			}
			if len(runtimeStore.acquiredRuntimeIDs) != 1 || runtimeStore.acquiredRuntimeIDs[0] != github.GetId() {
				t.Fatalf("acquired runtime ids = %#v, want non-trigger dependency %q", runtimeStore.acquiredRuntimeIDs, github.GetId())
			}
		})
	}
}

func TestGraphEvaluationLeasesRuntimeThatDoesNotTriggerRule(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	okta := trustedFindingRuntime("runtime-okta", "okta", "user", now)
	awsAsset := trustedFindingRuntime("runtime-aws-asset", "aws", "asset_metadata", now)
	rule, ok := asGraphRule(newIdentityPrivilegedNoMFAAccessRule())
	if !ok {
		t.Fatal("identity privileged no-MFA rule is not a graph rule")
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{okta.GetId(): okta, awsAsset.GetId(): awsAsset}},
		available:        true,
		renewAvailable:   true,
	}
	service := &Service{runtimeStore: runtimeStore, requireTrustedResolution: true}

	_, release, runtimes, trusted, err := service.acquireGraphEvaluationDependencyLeases(context.Background(), okta, []GraphRule{rule})
	if err != nil || !trusted || len(runtimes) != 2 {
		t.Fatalf("dependency lease = (%d runtimes, %v, %v), want identity and physical asset dependencies", len(runtimes), trusted, err)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if len(runtimeStore.acquiredRuntimeIDs) != 1 || runtimeStore.acquiredRuntimeIDs[0] != awsAsset.GetId() {
		t.Fatalf("acquired runtime ids = %#v, want physical asset dependency %q", runtimeStore.acquiredRuntimeIDs, awsAsset.GetId())
	}
}

func TestTrustedGraphEvaluationReportsSharedProjectionAsUnfenced(t *testing.T) {
	t.Parallel()
	sourceAt := time.Now().UTC().Add(-10 * time.Minute)
	runtime := trustedFindingRuntime("runtime-okta", "okta", "user", sourceAt)
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}},
		available:        true,
		renewAvailable:   true,
	}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1", RowLimit: 1},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	runStore := &sourceSnapshotGraphRunStore{runs: map[string]graphstore.IngestRun{
		runtime.GetId(): completedGraphRun("graph-okta", runtime.GetId(), "checkpoint-okta", sourceAt.Add(time.Minute)),
	}}
	service := NewWithRegistry(runtimeStore, &stubReplayer{}, store, store, store, store, registry).
		WithRawCypherQueryStore(&stubGraphStore{}).
		WithGraphIngestRunStore(runStore).
		WithTrustedSourceResolution()

	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", len(result.Evaluations))
	}
	run := result.Evaluations[0].Run
	if run.SourceDependencyComplete == nil || run.GetSourceDependencyComplete() {
		t.Fatalf("SourceDependencyComplete = %v, want false until every tenant graph writer joins one generation fence", run.SourceDependencyComplete)
	}
	if findingEvaluationSourceSnapshotsTrusted(run, true) {
		t.Fatal("unfenced shared graph evaluation qualified as trusted assessment evidence")
	}
}

type findingLeaseRuntimeStore struct {
	*stubRuntimeStore
	available            bool
	renewAvailable       bool
	renewPanic           bool
	renewStarted         chan<- struct{}
	renewWaitForCancel   bool
	unavailableRuntimeID string
	held                 bool
	replayWithoutLease   bool
	acquireCalls         int
	releaseCalls         int
	renewCalls           atomic.Int32
	acquiredRuntimeIDs   []string
}

func (s *findingLeaseRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID, _ string, _ time.Duration) (bool, error) {
	s.acquireCalls++
	s.acquiredRuntimeIDs = append(s.acquiredRuntimeIDs, runtimeID)
	available := s.available && runtimeID != s.unavailableRuntimeID
	if available {
		s.held = true
	}
	return available, nil
}

func (s *findingLeaseRuntimeStore) RenewSourceRuntimeLease(ctx context.Context, _ string, _ string, _ time.Duration) (bool, error) {
	s.renewCalls.Add(1)
	if s.renewStarted != nil {
		select {
		case s.renewStarted <- struct{}{}:
		default:
		}
	}
	if s.renewWaitForCancel {
		<-ctx.Done()
		return false, nil
	}
	if s.renewPanic {
		panic("finding evaluation lease renewal panic")
	}
	return s.renewAvailable, nil
}

func (s *findingLeaseRuntimeStore) ReleaseSourceRuntimeLease(context.Context, string, string) error {
	s.releaseCalls++
	s.held = false
	return nil
}

type findingLeaseCheckingReplayer struct{ runtimeStore *findingLeaseRuntimeStore }

func (r findingLeaseCheckingReplayer) Replay(context.Context, ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if r.runtimeStore == nil || !r.runtimeStore.held {
		r.runtimeStore.replayWithoutLease = true
	}
	return nil, nil
}

type findingLeaseBlockingReplayer struct {
	cancellationCause chan<- error
}

func (r findingLeaseBlockingReplayer) Replay(ctx context.Context, _ ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	<-ctx.Done()
	if r.cancellationCause != nil {
		r.cancellationCause <- context.Cause(ctx)
	}
	return nil, ctx.Err()
}
