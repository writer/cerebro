package findings

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *stubRuntimeStore) Ping(context.Context) error { return nil }

func (s *stubRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

type stubReplayer struct {
	request ports.ReplayRequest
	events  []*cerebrov1.EventEnvelope
}

func (s *stubReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	s.request = request
	events := make([]*cerebrov1.EventEnvelope, 0, len(s.events))
	for _, event := range s.events {
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	}
	return events, nil
}

type stubFindingStore struct {
	findings         map[string]*ports.FindingRecord
	request          ports.ListFindingsRequest
	claims           map[string]*ports.ClaimRecord
	claimListRequest ports.ListClaimsRequest
	runs             map[string]*cerebrov1.FindingEvaluationRun
	putRunCalls      int
	putRunErr        error
	putRunErrOnCall  int
	runList          ports.ListFindingEvaluationRunsRequest
	evidence         map[string]*cerebrov1.FindingEvidence
	evidenceList     ports.ListFindingEvidenceRequest
}

func (s *stubFindingStore) Ping(context.Context) error { return nil }

func (s *stubFindingStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	cloned := cloneFinding(finding)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.request = request
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func (s *stubFindingStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if claim == nil {
		return nil, errors.New("claim is required")
	}
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	cloned := cloneClaim(claim)
	s.claims[cloned.ID] = cloned
	return cloneClaim(cloned), nil
}

func (s *stubFindingStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	s.claimListRequest = request
	claims := []*ports.ClaimRecord{}
	for _, claim := range s.claims {
		if !claimMatches(request, claim) {
			continue
		}
		claims = append(claims, cloneClaim(claim))
	}
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i]
		right := claims[j]
		switch {
		case left.ObservedAt.Equal(right.ObservedAt):
			return left.ID < right.ID
		case left.ObservedAt.IsZero():
			return false
		case right.ObservedAt.IsZero():
			return true
		default:
			return left.ObservedAt.After(right.ObservedAt)
		}
	})
	if request.Limit != 0 && len(claims) > int(request.Limit) {
		claims = claims[:int(request.Limit)]
	}
	return claims, nil
}

func (s *stubFindingStore) PutFindingEvaluationRun(_ context.Context, run *cerebrov1.FindingEvaluationRun) error {
	if run == nil {
		return errors.New("finding evaluation run is required")
	}
	s.putRunCalls++
	if s.putRunErr != nil && s.putRunCalls == s.putRunErrOnCall {
		return s.putRunErr
	}
	if s.runs == nil {
		s.runs = make(map[string]*cerebrov1.FindingEvaluationRun)
	}
	s.runs[run.GetId()] = cloneFindingEvaluationRun(run)
	return nil
}

func (s *stubFindingStore) GetFindingEvaluationRun(_ context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	run, ok := s.runs[id]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	return cloneFindingEvaluationRun(run), nil
}

func (s *stubFindingStore) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	s.runList = request
	runs := make([]*cerebrov1.FindingEvaluationRun, 0, len(s.runs))
	for _, run := range s.runs {
		if !findingEvaluationRunMatches(request, run) {
			continue
		}
		runs = append(runs, cloneFindingEvaluationRun(run))
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		switch {
		case left.GetStartedAt().AsTime().Equal(right.GetStartedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetStartedAt().AsTime().After(right.GetStartedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(runs) > int(request.Limit) {
		runs = runs[:int(request.Limit)]
	}
	return runs, nil
}

func (s *stubFindingStore) PutFindingEvidence(_ context.Context, evidence *cerebrov1.FindingEvidence) error {
	if evidence == nil {
		return errors.New("finding evidence is required")
	}
	if s.evidence == nil {
		s.evidence = make(map[string]*cerebrov1.FindingEvidence)
	}
	clone := cloneFindingEvidence(evidence)
	if existing, ok := s.evidence[evidence.GetId()]; ok && existing.GetCreatedAt() != nil {
		clone.CreatedAt = proto.Clone(existing.GetCreatedAt()).(*timestamppb.Timestamp)
	}
	s.evidence[evidence.GetId()] = clone
	return nil
}

func (s *stubFindingStore) GetFindingEvidence(_ context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	evidence, ok := s.evidence[id]
	if !ok {
		return nil, ports.ErrFindingEvidenceNotFound
	}
	return cloneFindingEvidence(evidence), nil
}

func (s *stubFindingStore) ListFindingEvidence(_ context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	s.evidenceList = request
	evidence := make([]*cerebrov1.FindingEvidence, 0, len(s.evidence))
	for _, record := range s.evidence {
		if !findingEvidenceMatches(request, record) {
			continue
		}
		evidence = append(evidence, cloneFindingEvidence(record))
	}
	sort.Slice(evidence, func(i, j int) bool {
		left := evidence[i]
		right := evidence[j]
		switch {
		case left.GetCreatedAt().AsTime().Equal(right.GetCreatedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetCreatedAt().AsTime().After(right.GetCreatedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(evidence) > int(request.Limit) {
		evidence = evidence[:int(request.Limit)]
	}
	return evidence, nil
}

type emittingRule struct {
	spec               *cerebrov1.RuleSpec
	supportedSourceIDs map[string]struct{}
	triggerEventID     string
}

func (r *emittingRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *emittingRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	_, ok := r.supportedSourceIDs[runtime.GetSourceId()]
	return ok
}

func (r *emittingRule) Evaluate(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || event == nil || strings.TrimSpace(event.GetId()) != strings.TrimSpace(r.triggerEventID) {
		return nil, nil
	}
	observedAt := event.GetOccurredAt().AsTime().UTC()
	id := strings.TrimSpace(r.spec.GetId()) + "-" + strings.TrimSpace(event.GetId())
	return []*ports.FindingRecord{
		{
			ID:              id,
			Fingerprint:     id,
			TenantID:        strings.TrimSpace(event.GetTenantId()),
			RuntimeID:       strings.TrimSpace(runtime.GetId()),
			RuleID:          strings.TrimSpace(r.spec.GetId()),
			Title:           firstNonEmpty(r.spec.GetName(), strings.TrimSpace(r.spec.GetId())),
			Severity:        "MEDIUM",
			Status:          "open",
			Summary:         strings.TrimSpace(r.spec.GetId()) + " summary",
			ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			EventIDs:        []string{strings.TrimSpace(event.GetId())},
			FirstObservedAt: observedAt,
			LastObservedAt:  observedAt,
		},
	}, nil
}

func TestEvaluateSourceRuntimeFindingsReplaysOktaPolicyRuleLifecycleTampering(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-1", "user.session.start", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				Predicate:     "status",
				ObjectValue:   "updated",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	service := New(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}, replayer, store, store, store, store)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result.Runtime.GetId() != "writer-okta-audit" {
		t.Fatalf("Runtime.ID = %q, want writer-okta-audit", result.Runtime.GetId())
	}
	if result.Rule.GetId() != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Rule.ID = %q, want %q", result.Rule.GetId(), oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if result.EventsEvaluated != 2 {
		t.Fatalf("EventsEvaluated = %d, want 2", result.EventsEvaluated)
	}
	if got := replayer.request.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("Replay().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := replayer.request.Limit; got != 25 {
		t.Fatalf("Replay().Limit = %d, want 25", got)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.RuleID != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", finding.RuleID, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Finding.Severity = %q, want HIGH", finding.Severity)
	}
	if finding.Status != "open" {
		t.Fatalf("Finding.Status = %q, want open", finding.Status)
	}
	if finding.Summary != "admin@writer.com performed policy.rule.update on pol-1" {
		t.Fatalf("Finding.Summary = %q, want admin@writer.com performed policy.rule.update on pol-1", finding.Summary)
	}
	if len(finding.ResourceURNs) != 2 {
		t.Fatalf("len(Finding.ResourceURNs) = %d, want 2", len(finding.ResourceURNs))
	}
	if finding.ResourceURNs[0] != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("Finding.ResourceURNs[0] = %q, want policy rule urn", finding.ResourceURNs[0])
	}
	if finding.ResourceURNs[1] != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("Finding.ResourceURNs[1] = %q, want actor urn", finding.ResourceURNs[1])
	}
	if finding.Attributes["primary_actor_urn"] != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("Finding.Attributes[primary_actor_urn] = %q, want actor urn", finding.Attributes["primary_actor_urn"])
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("Finding.Attributes[primary_resource_urn] = %q, want resource urn", finding.Attributes["primary_resource_urn"])
	}
	if len(store.findings) != 1 {
		t.Fatalf("len(store.findings) = %d, want 1", len(store.findings))
	}
	if got := result.Run.GetStatus(); got != "completed" {
		t.Fatalf("Run.Status = %q, want completed", got)
	}
	if got := result.Run.GetRuleId(); got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Run.RuleId = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if got := result.Run.GetFindingsUpserted(); got != 1 {
		t.Fatalf("Run.FindingsUpserted = %d, want 1", got)
	}
	if got := len(result.Evidence); got != 1 {
		t.Fatalf("len(Evidence) = %d, want 1", got)
	}
	if got := result.Evidence[0].GetFindingId(); got != finding.ID {
		t.Fatalf("Evidence[0].FindingId = %q, want %q", got, finding.ID)
	}
	if got := result.Evidence[0].GetRunId(); got != result.Run.GetId() {
		t.Fatalf("Evidence[0].RunId = %q, want %q", got, result.Run.GetId())
	}
	if got := len(result.Evidence[0].GetClaimIds()); got != 1 {
		t.Fatalf("len(Evidence[0].ClaimIds) = %d, want 1", got)
	}
	if got := result.Evidence[0].GetClaimIds()[0]; got != "claim-1" {
		t.Fatalf("Evidence[0].ClaimIds[0] = %q, want claim-1", got)
	}
}

func TestEvaluateSourceRuntimeFindingsDeduplicatesEvidenceByID(t *testing.T) {
	registry, err := NewRegistry(&stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-duplicate"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		evaluate: func(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
			return []*ports.FindingRecord{
				{
					ID:              "finding-duplicate",
					Fingerprint:     "fingerprint-duplicate",
					RuntimeID:       runtime.GetId(),
					TenantID:        runtime.GetTenantId(),
					RuleID:          "rule-duplicate",
					Title:           "Duplicate finding",
					Severity:        "MEDIUM",
					Status:          "open",
					Summary:         "duplicate finding",
					ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:rule:pol-1"},
					EventIDs:        []string{event.GetId()},
					FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
					LastObservedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-1", "policy.rule.update", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}, replayer, store, store, store, store, registry)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "rule-duplicate",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 2 {
		t.Fatalf("len(Findings) = %d, want 2", got)
	}
	if got := len(result.Evidence); got != 1 {
		t.Fatalf("len(Evidence) = %d, want 1", got)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("len(store.evidence) = %d, want 1", got)
	}
	if got := result.Evidence[0].GetEventIds(); len(got) != 1 || got[0] != "okta-audit-2" {
		t.Fatalf("Evidence[0].EventIds = %v, want [okta-audit-2]", got)
	}
	stored := store.evidence[result.Evidence[0].GetId()]
	if stored == nil {
		t.Fatalf("stored evidence %q = nil", result.Evidence[0].GetId())
	}
	if !proto.Equal(result.Evidence[0].GetCreatedAt(), stored.GetCreatedAt()) {
		t.Fatalf("Evidence[0].CreatedAt = %v, want persisted %v", result.Evidence[0].GetCreatedAt(), stored.GetCreatedAt())
	}
}

func TestEvaluateSourceRuntimeFindingsKeepsDistinctEvidenceForCollidingLegacyIDs(t *testing.T) {
	registry, err := NewRegistry(&stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-collision"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		evaluate: func(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
			findingID := ""
			switch event.GetId() {
			case "okta-audit-1":
				findingID = "finding-a_b"
			case "okta-audit-2":
				findingID = "finding-a-b"
			default:
				return nil, nil
			}
			return []*ports.FindingRecord{
				{
					ID:              findingID,
					Fingerprint:     findingID,
					RuntimeID:       runtime.GetId(),
					TenantID:        runtime.GetTenantId(),
					RuleID:          "rule-collision",
					Title:           findingID,
					Severity:        "MEDIUM",
					Status:          "open",
					Summary:         findingID,
					ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:rule:pol-1"},
					EventIDs:        []string{event.GetId()},
					FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
					LastObservedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-1", "policy.rule.update", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}, replayer, store, store, store, store, registry)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "rule-collision",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Evidence); got != 2 {
		t.Fatalf("len(Evidence) = %d, want 2", got)
	}
	if got := len(store.evidence); got != 2 {
		t.Fatalf("len(store.evidence) = %d, want 2", got)
	}
	firstID := result.Evidence[0].GetId()
	secondID := result.Evidence[1].GetId()
	if firstID == secondID {
		t.Fatalf("evidence ids = %q and %q, want distinct ids", firstID, secondID)
	}
	if got := store.evidence[firstID].GetFindingId(); got != "finding-a_b" {
		t.Fatalf("store.evidence[%q].FindingId = %q, want finding-a_b", firstID, got)
	}
	if got := store.evidence[secondID].GetFindingId(); got != "finding-a-b" {
		t.Fatalf("store.evidence[%q].FindingId = %q, want finding-a-b", secondID, got)
	}
}

func TestEvaluateSourceRuntimeFindingsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestEvaluateSourceRuntimeFindingsStoresNormalizedEventLimit(t *testing.T) {
	replayer := &stubReplayer{}
	store := &stubFindingStore{}
	service := New(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}, replayer, store, store, store, store)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := replayer.request.Limit; got != defaultEventLimit {
		t.Fatalf("Replay().Limit = %d, want %d", got, defaultEventLimit)
	}
	if got := result.Run.GetEventLimit(); got != defaultEventLimit {
		t.Fatalf("Run.EventLimit = %d, want %d", got, defaultEventLimit)
	}
}

func TestListRulesReturnsBuiltinCatalog(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	response := service.ListRules()
	if got := len(response.GetRules()); got != 1 {
		t.Fatalf("len(ListRules().Rules) = %d, want 1", got)
	}
	if got := response.GetRules()[0].GetId(); got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("ListRules().Rules[0].Id = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
}

func TestEvaluateSourceRuntimeFindingsSelectsRequestedRule(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		replayer,
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		RuleID:     oktaPolicyRuleLifecycleTamperingRuleID,
		EventLimit: 10,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := result.Rule.GetId(); got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("EvaluateSourceRuntime().Rule.ID = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntime().Findings) = %d, want 1", got)
	}
}

func TestEvaluateSourceRuntimeFindingsFailedRunCountsOnlyEvaluatedEvents(t *testing.T) {
	evaluationErr := errors.New("rule evaluation failed")
	evaluations := 0
	registry, err := NewRegistry(&stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-fail"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		evaluate: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
			evaluations++
			if evaluations == 2 {
				return nil, evaluationErr
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newAuditEvent("okta-audit-1", "user.session.start", "SUCCESS"),
				newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
			},
		},
		store,
		store,
		store,
		store,
		registry,
	)

	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "rule-fail",
	}); !errors.Is(err, evaluationErr) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, evaluationErr)
	}
	if len(store.runs) != 1 {
		t.Fatalf("len(store.runs) = %d, want 1", len(store.runs))
	}
	for _, run := range store.runs {
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("Run.Status = %q, want failed", got)
		}
		if got := run.GetEventsEvaluated(); got != 1 {
			t.Fatalf("Run.EventsEvaluated = %d, want 1", got)
		}
	}
}

func TestEvaluateSourceRuntimeFindingsRejectsUnknownRule(t *testing.T) {
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
	)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "rule-does-not-exist",
	}); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuleNotFound)
	}
}

func TestEvaluateSourceRuntimeFindingsRequiresRuleIDWhenMultipleRulesSupportRuntime(t *testing.T) {
	registry, err := NewRegistry(
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		registry,
	)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
	}); !errors.Is(err, ErrRuleSelectionRequired) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuleSelectionRequired)
	}
}

func TestEvaluateSourceRuntimeFindingsRejectsUnsupportedRule(t *testing.T) {
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-github-audit": {
					Id:       "writer-github-audit",
					SourceId: "github",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
	)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-github-audit",
		RuleID:    oktaPolicyRuleLifecycleTamperingRuleID,
	}); !errors.Is(err, ErrRuleUnsupported) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuleUnsupported)
	}
}

func TestEvaluateSourceRuntimeRulesReplaysOnceAcrossMultipleRules(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec: &cerebrov1.RuleSpec{
				Id:   "rule-a",
				Name: "Rule A",
			},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-2",
		},
		&emittingRule{
			spec: &cerebrov1.RuleSpec{
				Id:   "rule-b",
				Name: "Rule B",
			},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-3",
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
			newAuditEvent("okta-audit-3", "policy.rule.delete", "SUCCESS"),
		},
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
			"claim-2": {
				ID:            "claim-2",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-3",
				ObservedAt:    time.Date(2026, 4, 23, 12, 1, 0, 0, time.UTC),
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)
	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID:  "writer-okta-audit",
		EventLimit: 2,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if got := result.EventsEvaluated; got != 2 {
		t.Fatalf("EvaluateSourceRuntimeRules().EventsEvaluated = %d, want 2", got)
	}
	if got := replayer.request.Limit; got != 2 {
		t.Fatalf("Replay().Limit = %d, want 2", got)
	}
	if got := len(result.Evaluations); got != 2 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations) = %d, want 2", got)
	}
	if got := result.Evaluations[0].Rule.GetId(); got != "rule-a" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Rule.Id = %q, want rule-a", got)
	}
	if got := result.Evaluations[1].Rule.GetId(); got != "rule-b" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[1].Rule.Id = %q, want rule-b", got)
	}
	if got := len(result.Evaluations[0].Findings); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations[0].Findings) = %d, want 1", got)
	}
	if got := len(result.Evaluations[1].Findings); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations[1].Findings) = %d, want 1", got)
	}
	if got := result.Evaluations[0].Run.GetStatus(); got != "completed" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Run.Status = %q, want completed", got)
	}
	if got := result.Evaluations[1].Run.GetStatus(); got != "completed" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[1].Run.Status = %q, want completed", got)
	}
	if got := len(result.Evaluations[0].Evidence); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations[0].Evidence) = %d, want 1", got)
	}
	if got := len(result.Evaluations[1].Evidence); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations[1].Evidence) = %d, want 1", got)
	}
	if got := result.Evaluations[0].Evidence[0].GetClaimIds()[0]; got != "claim-1" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Evidence[0].ClaimIds[0] = %q, want claim-1", got)
	}
	if got := result.Evaluations[1].Evidence[0].GetClaimIds()[0]; got != "claim-2" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[1].Evidence[0].ClaimIds[0] = %q, want claim-2", got)
	}
	if got := len(store.evidence); got != 2 {
		t.Fatalf("len(store.evidence) = %d, want 2", got)
	}
}

func TestEvaluateSourceRuntimeRulesFailedRunCountsOnlyEvaluatedEvents(t *testing.T) {
	evaluationErr := errors.New("rule evaluation failed")
	evaluations := 0
	registry, err := NewRegistry(&stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-fail"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		evaluate: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
			evaluations++
			if evaluations == 2 {
				return nil, evaluationErr
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
				newAuditEvent("okta-audit-3", "policy.rule.delete", "SUCCESS"),
			},
		},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: "writer-okta-audit",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if got := result.EventsEvaluated; got != 2 {
		t.Fatalf("EvaluateSourceRuntimeRules().EventsEvaluated = %d, want 2", got)
	}
	if got := result.Evaluations[0].Run.GetStatus(); got != "failed" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Run.Status = %q, want failed", got)
	}
	if got := result.Evaluations[0].Run.GetEventsEvaluated(); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Run.EventsEvaluated = %d, want 1", got)
	}
}

func TestEvaluateSourceRuntimeRulesDeduplicatesEvidenceByID(t *testing.T) {
	registry, err := NewRegistry(&stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-duplicate"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		evaluate: func(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
			observedAt := event.GetOccurredAt().AsTime().UTC()
			return []*ports.FindingRecord{
				{
					ID:              "finding-duplicate",
					Fingerprint:     "finding-duplicate",
					TenantID:        event.GetTenantId(),
					RuntimeID:       runtime.GetId(),
					RuleID:          "rule-duplicate",
					Title:           "Duplicate Finding",
					Severity:        "MEDIUM",
					Status:          "open",
					Summary:         "duplicate summary",
					ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
					EventIDs:        []string{event.GetId()},
					FirstObservedAt: observedAt,
					LastObservedAt:  observedAt,
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-2": {
				ID:            "claim-2",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
			"claim-3": {
				ID:            "claim-3",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-3",
				ObservedAt:    time.Date(2026, 4, 23, 12, 1, 0, 0, time.UTC),
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
				newAuditEvent("okta-audit-3", "policy.rule.delete", "SUCCESS"),
			},
		},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: "writer-okta-audit",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if got := len(result.Evaluations[0].Evidence); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations[0].Evidence) = %d, want 1", got)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("len(store.evidence) = %d, want 1", got)
	}
	evidence := result.Evaluations[0].Evidence[0]
	if got := evidence.GetEventIds(); len(got) != 1 || got[0] != "okta-audit-3" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Evidence[0].EventIds = %v, want [okta-audit-3]", got)
	}
	if got := evidence.GetClaimIds(); len(got) != 1 || got[0] != "claim-3" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Evidence[0].ClaimIds = %v, want [claim-3]", got)
	}
}

func TestEvaluateSourceRuntimeRulesMarksStartedRunsFailedWhenLaterRunPersistFails(t *testing.T) {
	persistErr := errors.New("persist run failed")
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		putRunErr:       persistErr,
		putRunErrOnCall: 2,
	}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: "writer-okta-audit",
	}); !errors.Is(err, persistErr) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want %v", err, persistErr)
	}
	if len(store.runs) != 1 {
		t.Fatalf("len(store.runs) = %d, want 1", len(store.runs))
	}
	for _, run := range store.runs {
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("Run.Status = %q, want failed", got)
		}
		if run.GetFinishedAt() == nil {
			t.Fatal("Run.FinishedAt = nil, want timestamp")
		}
		if run.GetError() == "" {
			t.Fatal("Run.Error = empty, want failure detail")
		}
	}
}

func TestEvaluateSourceRuntimeRulesSelectsExplicitRules(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-2",
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-3",
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-2": {
				ID:            "claim-2",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-3",
				ObservedAt:    time.Date(2026, 4, 23, 12, 1, 0, 0, time.UTC),
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
				newAuditEvent("okta-audit-3", "policy.rule.delete", "SUCCESS"),
			},
		},
		store,
		store,
		store,
		store,
		registry,
	)
	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: "writer-okta-audit",
		RuleIDs:   []string{"rule-b"},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeRules().Evaluations) = %d, want 1", got)
	}
	if got := result.Evaluations[0].Rule.GetId(); got != "rule-b" {
		t.Fatalf("EvaluateSourceRuntimeRules().Evaluations[0].Rule.Id = %q, want rule-b", got)
	}
}

func TestListFindingsReturnsFilteredPersistedFindings(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				RuntimeID:      "writer-okta-audit",
				RuleID:         oktaPolicyRuleLifecycleTamperingRuleID,
				Severity:       "HIGH",
				Status:         "open",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				EventIDs:       []string{"okta-audit-2"},
				LastObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
			"finding-2": {
				ID:             "finding-2",
				RuntimeID:      "writer-okta-audit",
				RuleID:         oktaPolicyRuleLifecycleTamperingRuleID,
				Severity:       "MEDIUM",
				Status:         "resolved",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_resource:policyrule:pol-2"},
				EventIDs:       []string{"okta-audit-3"},
				LastObservedAt: time.Date(2026, 4, 23, 11, 0, 0, 0, time.UTC),
			},
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		store,
		store,
		store,
		store,
	)

	result, err := service.ListFindings(context.Background(), ListRequest{
		RuntimeID:   "writer-okta-audit",
		RuleID:      oktaPolicyRuleLifecycleTamperingRuleID,
		Severity:    "HIGH",
		Status:      "open",
		ResourceURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		EventID:     "okta-audit-2",
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(ListFindings().Findings) = %d, want 1", got)
	}
	if got := result.Findings[0].ID; got != "finding-1" {
		t.Fatalf("ListFindings().Findings[0].ID = %q, want finding-1", got)
	}
	if got := store.request.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("ListFindings().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := store.request.RuleID; got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("ListFindings().RuleID = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if got := store.request.Severity; got != "HIGH" {
		t.Fatalf("ListFindings().Severity = %q, want HIGH", got)
	}
	if got := store.request.Status; got != "open" {
		t.Fatalf("ListFindings().Status = %q, want open", got)
	}
	if got := store.request.ResourceURN; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("ListFindings().ResourceURN = %q, want policy rule urn", got)
	}
	if got := store.request.EventID; got != "okta-audit-2" {
		t.Fatalf("ListFindings().EventID = %q, want okta-audit-2", got)
	}
	if got := store.request.Limit; got != 1 {
		t.Fatalf("ListFindings().Limit = %d, want 1", got)
	}
}

func TestListFindingsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.ListFindings(context.Background(), ListRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ListFindings() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestListEvaluationRunsReturnsFilteredRuns(t *testing.T) {
	store := &stubFindingStore{
		runs: map[string]*cerebrov1.FindingEvaluationRun{
			"run-1": {
				Id:         "run-1",
				RuntimeId:  "writer-okta-audit",
				RuleId:     oktaPolicyRuleLifecycleTamperingRuleID,
				Status:     "completed",
				StartedAt:  timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
				FinishedAt: timestamppb.New(time.Date(2026, 4, 24, 12, 1, 0, 0, time.UTC)),
			},
			"run-2": {
				Id:         "run-2",
				RuntimeId:  "writer-okta-audit",
				RuleId:     oktaPolicyRuleLifecycleTamperingRuleID,
				Status:     "failed",
				StartedAt:  timestamppb.New(time.Date(2026, 4, 24, 11, 0, 0, 0, time.UTC)),
				FinishedAt: timestamppb.New(time.Date(2026, 4, 24, 11, 1, 0, 0, time.UTC)),
			},
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		store,
		store,
		store,
		store,
	)
	result, err := service.ListEvaluationRuns(context.Background(), ListEvaluationRunsRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    oktaPolicyRuleLifecycleTamperingRuleID,
		Status:    "completed",
		Limit:     1,
	})
	if err != nil {
		t.Fatalf("ListEvaluationRuns() error = %v", err)
	}
	if got := len(result.Runs); got != 1 {
		t.Fatalf("len(ListEvaluationRuns().Runs) = %d, want 1", got)
	}
	if got := result.Runs[0].GetId(); got != "run-1" {
		t.Fatalf("ListEvaluationRuns().Runs[0].Id = %q, want run-1", got)
	}
	if got := store.runList.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("ListEvaluationRuns().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := store.runList.RuleID; got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("ListEvaluationRuns().RuleID = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if got := store.runList.Status; got != "completed" {
		t.Fatalf("ListEvaluationRuns().Status = %q, want completed", got)
	}
}

func TestGetEvaluationRunReturnsPersistedRun(t *testing.T) {
	store := &stubFindingStore{
		runs: map[string]*cerebrov1.FindingEvaluationRun{
			"run-1": {
				Id:        "run-1",
				RuntimeId: "writer-okta-audit",
				RuleId:    oktaPolicyRuleLifecycleTamperingRuleID,
				Status:    "completed",
				StartedAt: timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	run, err := service.GetEvaluationRun(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("GetEvaluationRun() error = %v", err)
	}
	if got := run.GetRuleId(); got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("GetEvaluationRun().RuleId = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
}

func TestListEvaluationRunsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.ListEvaluationRuns(context.Background(), ListEvaluationRunsRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ListEvaluationRuns() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestGetEvaluationRunRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.GetEvaluationRun(context.Background(), "run-1"); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetEvaluationRun() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestListEvidenceReturnsFilteredRecords(t *testing.T) {
	store := &stubFindingStore{
		evidence: map[string]*cerebrov1.FindingEvidence{
			"finding-evidence-1": {
				Id:            "finding-evidence-1",
				RuntimeId:     "writer-okta-audit",
				RuleId:        oktaPolicyRuleLifecycleTamperingRuleID,
				FindingId:     "finding-1",
				RunId:         "run-1",
				ClaimIds:      []string{"claim-1"},
				EventIds:      []string{"okta-audit-2"},
				GraphRootUrns: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				CreatedAt:     timestamppb.New(time.Date(2026, 4, 24, 12, 2, 0, 0, time.UTC)),
			},
			"finding-evidence-2": {
				Id:            "finding-evidence-2",
				RuntimeId:     "writer-okta-audit",
				RuleId:        oktaPolicyRuleLifecycleTamperingRuleID,
				FindingId:     "finding-2",
				RunId:         "run-2",
				ClaimIds:      []string{"claim-2"},
				EventIds:      []string{"okta-audit-3"},
				GraphRootUrns: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-2"},
				CreatedAt:     timestamppb.New(time.Date(2026, 4, 24, 12, 1, 0, 0, time.UTC)),
			},
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		store,
		store,
		store,
		store,
	)
	result, err := service.ListEvidence(context.Background(), ListEvidenceRequest{
		RuntimeID:    "writer-okta-audit",
		FindingID:    "finding-1",
		RunID:        "run-1",
		RuleID:       oktaPolicyRuleLifecycleTamperingRuleID,
		ClaimID:      "claim-1",
		EventID:      "okta-audit-2",
		GraphRootURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		Limit:        1,
	})
	if err != nil {
		t.Fatalf("ListEvidence() error = %v", err)
	}
	if got := len(result.Evidence); got != 1 {
		t.Fatalf("len(ListEvidence().Evidence) = %d, want 1", got)
	}
	if got := result.Evidence[0].GetId(); got != "finding-evidence-1" {
		t.Fatalf("ListEvidence().Evidence[0].Id = %q, want finding-evidence-1", got)
	}
	if got := store.evidenceList.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("ListEvidence().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := store.evidenceList.FindingID; got != "finding-1" {
		t.Fatalf("ListEvidence().FindingID = %q, want finding-1", got)
	}
	if got := store.evidenceList.RunID; got != "run-1" {
		t.Fatalf("ListEvidence().RunID = %q, want run-1", got)
	}
	if got := store.evidenceList.ClaimID; got != "claim-1" {
		t.Fatalf("ListEvidence().ClaimID = %q, want claim-1", got)
	}
	if got := store.evidenceList.EventID; got != "okta-audit-2" {
		t.Fatalf("ListEvidence().EventID = %q, want okta-audit-2", got)
	}
	if got := store.evidenceList.GraphRootURN; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("ListEvidence().GraphRootURN = %q, want policy rule urn", got)
	}
}

func TestGetEvidenceReturnsPersistedRecord(t *testing.T) {
	store := &stubFindingStore{
		evidence: map[string]*cerebrov1.FindingEvidence{
			"finding-evidence-1": {
				Id:        "finding-evidence-1",
				RuntimeId: "writer-okta-audit",
				RuleId:    oktaPolicyRuleLifecycleTamperingRuleID,
				FindingId: "finding-1",
				RunId:     "run-1",
				CreatedAt: timestamppb.New(time.Date(2026, 4, 24, 12, 2, 0, 0, time.UTC)),
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	evidence, err := service.GetEvidence(context.Background(), "finding-evidence-1")
	if err != nil {
		t.Fatalf("GetEvidence() error = %v", err)
	}
	if got := evidence.GetFindingId(); got != "finding-1" {
		t.Fatalf("GetEvidence().FindingId = %q, want finding-1", got)
	}
}

func TestListEvidenceRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.ListEvidence(context.Background(), ListEvidenceRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ListEvidence() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestGetEvidenceRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.GetEvidence(context.Background(), "finding-evidence-1"); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetEvidence() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func newAuditEvent(id string, eventType string, outcome string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/audit/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"event_type":                        eventType,
			"resource_id":                       "pol-1",
			"resource_type":                     "PolicyRule",
			"actor_id":                          "00u2",
			"actor_type":                        "User",
			"actor_alternate_id":                "admin@writer.com",
			"actor_display_name":                "Admin Example",
			"outcome_result":                    outcome,
			ports.EventAttributeSourceRuntimeID: "writer-okta-audit",
		},
	}
}

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := make([]string, len(finding.ResourceURNs))
	copy(resourceURNs, finding.ResourceURNs)
	eventIDs := make([]string, len(finding.EventIDs))
	copy(eventIDs, finding.EventIDs)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:              finding.ID,
		Fingerprint:     finding.Fingerprint,
		TenantID:        finding.TenantID,
		RuntimeID:       finding.RuntimeID,
		RuleID:          finding.RuleID,
		Title:           finding.Title,
		Severity:        finding.Severity,
		Status:          finding.Status,
		Summary:         finding.Summary,
		ResourceURNs:    resourceURNs,
		EventIDs:        eventIDs,
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func cloneClaim(claim *ports.ClaimRecord) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            claim.ID,
		RuntimeID:     claim.RuntimeID,
		TenantID:      claim.TenantID,
		SubjectURN:    claim.SubjectURN,
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectURN:     claim.ObjectURN,
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventID: claim.SourceEventID,
		ObservedAt:    claim.ObservedAt,
		ValidFrom:     claim.ValidFrom,
		ValidTo:       claim.ValidTo,
		Attributes:    attributes,
	}
}

func cloneFindingEvaluationRun(run *cerebrov1.FindingEvaluationRun) *cerebrov1.FindingEvaluationRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.FindingEvaluationRun)
}

func cloneFindingEvidence(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if evidence == nil {
		return nil
	}
	return proto.Clone(evidence).(*cerebrov1.FindingEvidence)
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(finding.ID) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(finding.RuleID) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Severity != "" && strings.TrimSpace(finding.Severity) != strings.TrimSpace(request.Severity) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(finding.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.ResourceURN != "" && !containsTrimmed(finding.ResourceURNs, request.ResourceURN) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(finding.EventIDs, request.EventID) {
		return false
	}
	return true
}

func containsTrimmed(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}

func claimMatches(request ports.ListClaimsRequest, claim *ports.ClaimRecord) bool {
	if claim == nil {
		return false
	}
	if strings.TrimSpace(claim.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.ClaimID != "" && strings.TrimSpace(claim.ID) != strings.TrimSpace(request.ClaimID) {
		return false
	}
	if request.SubjectURN != "" && strings.TrimSpace(claim.SubjectURN) != strings.TrimSpace(request.SubjectURN) {
		return false
	}
	if request.Predicate != "" && strings.TrimSpace(claim.Predicate) != strings.TrimSpace(request.Predicate) {
		return false
	}
	if request.ObjectURN != "" && strings.TrimSpace(claim.ObjectURN) != strings.TrimSpace(request.ObjectURN) {
		return false
	}
	if request.ObjectValue != "" && strings.TrimSpace(claim.ObjectValue) != strings.TrimSpace(request.ObjectValue) {
		return false
	}
	if request.ClaimType != "" && strings.TrimSpace(claim.ClaimType) != strings.TrimSpace(request.ClaimType) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(claim.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.SourceEventID != "" && strings.TrimSpace(claim.SourceEventID) != strings.TrimSpace(request.SourceEventID) {
		return false
	}
	return true
}

func findingEvaluationRunMatches(request ports.ListFindingEvaluationRunsRequest, run *cerebrov1.FindingEvaluationRun) bool {
	if run == nil {
		return false
	}
	if strings.TrimSpace(run.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(run.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(run.GetStatus()) != strings.TrimSpace(request.Status) {
		return false
	}
	return true
}

func findingEvidenceMatches(request ports.ListFindingEvidenceRequest, evidence *cerebrov1.FindingEvidence) bool {
	if evidence == nil {
		return false
	}
	if strings.TrimSpace(evidence.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(evidence.GetFindingId()) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RunID != "" && strings.TrimSpace(evidence.GetRunId()) != strings.TrimSpace(request.RunID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(evidence.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.ClaimID != "" && !containsTrimmed(evidence.GetClaimIds(), request.ClaimID) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(evidence.GetEventIds(), request.EventID) {
		return false
	}
	if request.GraphRootURN != "" && !containsTrimmed(evidence.GetGraphRootUrns(), request.GraphRootURN) {
		return false
	}
	return true
}

func cloneEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return proto.Clone(ref).(*cerebrov1.EntityRef)
}
