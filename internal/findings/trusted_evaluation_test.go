package findings

import (
	"context"
	"errors"
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

type findingLeaseRuntimeStore struct {
	*stubRuntimeStore
	available          bool
	held               bool
	replayWithoutLease bool
	acquireCalls       int
	releaseCalls       int
}

func (s *findingLeaseRuntimeStore) AcquireSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	s.acquireCalls++
	if s.available {
		s.held = true
	}
	return s.available, nil
}

func (s *findingLeaseRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return s.available, nil
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
