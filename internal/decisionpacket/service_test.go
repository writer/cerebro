package decisionpacket

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type stubResolver struct {
	facts ResolvedFacts
	err   error
	seen  AuthorizedTenant
}

func (r *stubResolver) Resolve(_ context.Context, tenant AuthorizedTenant, _ Request) (ResolvedFacts, error) {
	r.seen = tenant
	return r.facts, r.err
}

func TestServiceBuildsSupportedContentAddressedPacket(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	resolver := &stubResolver{facts: ResolvedFacts{
		Evidence:    []EvidenceReference{{ID: "evidence-1", Kind: "finding", ObservedAt: now.Add(-time.Minute)}},
		Affected:    []SubjectReference{{URN: "urn:cerebro:tenant-1:asset:1", Kind: "asset"}},
		ResolverIDs: []string{"finding-store"}, SourceIDs: []string{"source-1"},
		Rationale: "Current evidence supports the requested conclusion.",
	}}
	service := NewService(resolver, fixedClock{now: now})
	request := Request{Workflow: "triage", Question: "Is this finding current?", ScopeURN: "urn:cerebro:tenant-1:finding:1"}
	packet, err := service.Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1", Scopes: []string{agentplatform.ScopeCosmoSecurityRead}}, request)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if resolver.seen.ID != "tenant-1" || packet.Scope.TenantID != "tenant-1" || packet.Scope.ActorID != "actor-1" {
		t.Fatalf("forced scope = %+v, resolver tenant = %+v", packet.Scope, resolver.seen)
	}
	if packet.Decision.State != DecisionSupported || packet.Confidence.Level != ConfidenceHigh {
		t.Fatalf("decision = %+v confidence = %+v", packet.Decision, packet.Confidence)
	}
	if !strings.HasPrefix(packet.ID, "dpr_") || packet.Claim.Verdict != agentplatform.ClaimVerdictSupported {
		t.Fatalf("packet id = %q claim = %+v", packet.ID, packet.Claim)
	}
	second, err := service.Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1", Scopes: []string{agentplatform.ScopeCosmoSecurityRead}}, request)
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if second.ID != packet.ID {
		t.Fatalf("same facts and clock produced ids %q and %q", packet.ID, second.ID)
	}
}

func TestServiceMakesCoverageAndTruncationVisible(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	evidence := make([]EvidenceReference, 0, 3)
	for _, id := range []string{"evidence-3", "evidence-1", "evidence-2"} {
		evidence = append(evidence, EvidenceReference{ID: id, Kind: "finding", ObservedAt: now})
	}
	resolver := &stubResolver{facts: ResolvedFacts{
		Evidence:     evidence,
		CoverageGaps: []CoverageGap{{ID: "coverage:source-1:users:stale", SourceID: "source-1", Dimension: "users", State: CoverageStale, Required: true, CouldChangeConclusion: true, Reason: "required source is stale"}},
	}}
	service := NewService(resolver, fixedClock{now: now})
	packet, err := service.Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1", Scopes: []string{agentplatform.ScopeCosmoSecurityRead}}, Request{
		Workflow: "triage", Question: "Is this finding current?", Budgets: Budgets{Evidence: 2},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if packet.Decision.State != DecisionSupportedWithGaps || packet.Confidence.Level != ConfidenceLow {
		t.Fatalf("decision = %+v confidence = %+v", packet.Decision, packet.Confidence)
	}
	if !packet.Limits.Evidence.Truncated || packet.Limits.Evidence.TotalKnown != 3 || len(packet.Evidence) != 2 {
		t.Fatalf("evidence limit = %+v evidence = %+v", packet.Limits.Evidence, packet.Evidence)
	}
	if packet.Freshness.State != "stale" || !packet.Freshness.RequiredStale {
		t.Fatalf("freshness = %+v", packet.Freshness)
	}
}

func TestServiceKeepsUnknownEvidenceFreshnessVisible(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	resolver := &stubResolver{facts: ResolvedFacts{Evidence: []EvidenceReference{{ID: "evidence-1", Kind: "finding"}}}}
	packet, err := NewService(resolver, fixedClock{now: now}).Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1"}, Request{Workflow: "triage", Question: "Is this finding current?"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if packet.Freshness.State != "unknown" || packet.Claim.FreshnessState != "unknown" || packet.Claim.Verdict != agentplatform.ClaimVerdictWeaklySupported || packet.Decision.State != DecisionSupportedWithGaps {
		t.Fatalf("freshness = %+v claim = %+v decision = %+v", packet.Freshness, packet.Claim, packet.Decision)
	}
}

func TestServiceBlocksPrimaryContradictionAndDowngradesActions(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	base := ClaimObservation{TenantID: "tenant-1", SubjectURN: "urn:cerebro:tenant-1:asset:1", Predicate: "public", ValidFrom: now.Add(-time.Hour), PrimaryClaim: true}
	left := base
	left.Value, left.Evidence = "true", EvidenceReference{ID: "evidence-1", Kind: "claim"}
	right := base
	right.Value, right.Evidence = "false", EvidenceReference{ID: "evidence-2", Kind: "claim"}
	resolver := &stubResolver{facts: ResolvedFacts{
		Evidence: []EvidenceReference{left.Evidence, right.Evidence}, Observations: []ClaimObservation{left, right},
		Actions: []ActionProposal{{ID: "preview:action", ActionID: "action", State: ActionApprovalRequired, ApprovalRequirements: []string{"human_approval"}}},
	}}
	packet, err := NewService(resolver, fixedClock{now: now}).Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1", Scopes: []string{agentplatform.ScopeCosmoSecurityRead}}, Request{Workflow: "triage", Question: "Is this asset public?"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if packet.Decision.State != DecisionBlocked || len(packet.Contradictions) != 1 {
		t.Fatalf("decision = %+v contradictions = %+v", packet.Decision, packet.Contradictions)
	}
	if len(packet.Actions) != 1 || packet.Actions[0].State != ActionInformational || len(packet.Actions[0].ApprovalRequirements) != 0 {
		t.Fatalf("blocked action = %+v", packet.Actions)
	}
}

func TestServiceDoesNotResolveCrossTenantScope(t *testing.T) {
	resolver := &stubResolver{}
	_, err := NewService(resolver, fixedClock{now: time.Now()}).Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1"}, Request{
		Workflow: "triage", Question: "Review", ScopeURN: "urn:cerebro:other:finding:1",
	})
	if !errors.Is(err, ErrProtectedReference) {
		t.Fatalf("Build() error = %v, want ErrProtectedReference", err)
	}
	if resolver.seen.ID != "" {
		t.Fatal("resolver was called for a cross-tenant scope")
	}
}

func TestServicePropagatesRequiredResolverFailure(t *testing.T) {
	want := errors.New("store unavailable")
	resolver := &stubResolver{err: want}
	_, err := NewService(resolver, fixedClock{now: time.Now()}).Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1"}, Request{Workflow: "triage", Question: "Review"})
	if !errors.Is(err, want) {
		t.Fatalf("Build() error = %v, want %v", err, want)
	}
}

func TestServiceRejectsForeignResolvedFactsAndExecutionStates(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		facts ResolvedFacts
	}{
		{name: "foreign evidence", facts: ResolvedFacts{Evidence: []EvidenceReference{{ID: "evidence-1", Kind: "finding", URN: "urn:cerebro:other:evidence:1"}}}},
		{name: "foreign audit packet", facts: ResolvedFacts{AuditPackets: []AuditPacketReference{{ID: "audit-1", ScopeURN: "urn:cerebro:other:scope:1"}}}},
		{name: "executed action", facts: ResolvedFacts{Actions: []ActionProposal{{ID: "action-1", State: "executed"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(&stubResolver{facts: tt.facts}, fixedClock{now: now}).Build(context.Background(), AuthorizedTenant{ID: "tenant-1"}, AuthorizedActor{ID: "actor-1"}, Request{Workflow: "triage", Question: "Review"})
			if err == nil {
				t.Fatal("Build() error = nil, want fail-closed validation")
			}
		})
	}
}
