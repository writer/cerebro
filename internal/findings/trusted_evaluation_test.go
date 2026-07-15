package findings

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want runtime unavailable after lease loss", err)
	}
	if runtimeStore.renewCalls.Load() == 0 || runtimeStore.releaseCalls != 1 || runtimeStore.held {
		t.Fatalf("renew/release/state = %d/%d/%t, want renewal attempt, release, and no held lease", runtimeStore.renewCalls.Load(), runtimeStore.releaseCalls, runtimeStore.held)
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

func TestGraphEvaluationLeasesCrossSourceAssetDependency(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	trigger := trustedFindingRuntime("runtime-okta", "okta", "user", now)
	assetMetadata := trustedFindingRuntime("runtime-aws-asset-metadata", "aws", "asset_metadata", now)
	rule := &sourceSnapshotGraphRule{
		multiSourceStubGraphRule: multiSourceStubGraphRule{
			stubGraphRule: stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "cross-source-asset-rule"}}, supportedSources: []string{"okta"},
		},
		definition: RuleDefinition{ID: "cross-source-asset-rule", EventKinds: []string{"okta.user", "asset.data_sensitivity", "asset.crown_jewel"}},
	}
	runtimeStore := &findingLeaseRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			trigger.GetId():       trigger,
			assetMetadata.GetId(): assetMetadata,
		}},
		available:      true,
		renewAvailable: true,
	}
	service := &Service{runtimeStore: runtimeStore, requireTrustedResolution: true}
	_, release, runtimes, trusted, err := service.acquireGraphEvaluationDependencyLeases(context.Background(), trigger, []GraphRule{rule})
	if err != nil || !trusted || len(runtimes) != 2 {
		t.Fatalf("dependency lease = (%d runtimes, %v, %v), want trigger and trusted asset metadata", len(runtimes), trusted, err)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if len(runtimeStore.acquiredRuntimeIDs) != 1 || runtimeStore.acquiredRuntimeIDs[0] != assetMetadata.GetId() {
		t.Fatalf("acquired runtime ids = %#v, want cross-source dependency %q", runtimeStore.acquiredRuntimeIDs, assetMetadata.GetId())
	}
}

type findingLeaseRuntimeStore struct {
	*stubRuntimeStore
	available            bool
	renewAvailable       bool
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

func (s *findingLeaseRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	s.renewCalls.Add(1)
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

type findingLeaseBlockingReplayer struct{}

func (findingLeaseBlockingReplayer) Replay(ctx context.Context, _ ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
