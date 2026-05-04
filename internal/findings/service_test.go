package findings

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
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

type recordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return nil }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

type stubFindingStore struct {
	findings         map[string]*ports.FindingRecord
	request          ports.ListFindingsRequest
	claims           map[string]*ports.ClaimRecord
	claimListRequest ports.ListClaimsRequest
	runs             map[string]*cerebrov1.FindingEvaluationRun
	runList          ports.ListFindingEvaluationRunsRequest
	runPutCount      int
	failRunPutOn     int
	failRunPutErr    error
	failRunPutByCall map[int]error
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
	if existing, ok := s.findings[cloned.ID]; ok {
		cloned = preserveFindingWorkflow(existing, cloned)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) GetFinding(_ context.Context, id string) (*ports.FindingRecord, error) {
	finding, ok := s.findings[id]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	return cloneFinding(finding), nil
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

func (s *stubFindingStore) UpdateFindingStatus(_ context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Status = strings.TrimSpace(request.Status)
	cloned.StatusReason = strings.TrimSpace(request.Reason)
	cloned.StatusUpdatedAt = request.UpdatedAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) UpdateFindingAssignee(_ context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Assignee = strings.TrimSpace(request.Assignee)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) UpdateFindingDueDate(_ context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.DueAt = request.DueAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) AddFindingNote(_ context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Notes = append(cloned.Notes, request.Note)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) LinkFindingTicket(_ context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	exists := false
	for _, ticket := range cloned.Tickets {
		if strings.TrimSpace(ticket.URL) == strings.TrimSpace(request.Ticket.URL) {
			exists = true
			break
		}
	}
	if !exists {
		cloned.Tickets = append(cloned.Tickets, request.Ticket)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

type stubGraphStore struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (s *stubGraphStore) Ping(context.Context) error { return nil }

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, _ int) (*ports.EntityNeighborhood, error) {
	entity, ok := s.entities[rootURN]
	if !ok || entity == nil {
		return nil, ports.ErrGraphEntityNotFound
	}
	return &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{
			URN:        entity.URN,
			EntityType: entity.EntityType,
			Label:      entity.Label,
		},
	}, nil
}

func (s *stubGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	s.entities[entity.URN] = &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
	return nil
}

func (s *stubGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	s.links[key] = &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
	return nil
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
	s.runPutCount++
	if err, ok := s.failRunPutByCall[s.runPutCount]; ok {
		if err != nil {
			return err
		}
		return errors.New("put finding evaluation run failed")
	}
	if s.failRunPutOn != 0 && s.runPutCount == s.failRunPutOn {
		if s.failRunPutErr != nil {
			return s.failRunPutErr
		}
		return errors.New("put finding evaluation run failed")
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
	s.evidence[evidence.GetId()] = cloneFindingEvidence(evidence)
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

type failingRule struct {
	spec               *cerebrov1.RuleSpec
	supportedSourceIDs map[string]struct{}
	err                error
}

func (r *failingRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *failingRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	_, ok := r.supportedSourceIDs[runtime.GetSourceId()]
	return ok
}

func (r *failingRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, r.err
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
		RuleID:     oktaPolicyRuleLifecycleTamperingRuleID,
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
	if finding.PolicyID != "pol-1" {
		t.Fatalf("Finding.PolicyID = %q, want pol-1", finding.PolicyID)
	}
	if finding.PolicyName != "pol-1" {
		t.Fatalf("Finding.PolicyName = %q, want pol-1", finding.PolicyName)
	}
	if len(finding.ObservedPolicyIDs) != 1 || finding.ObservedPolicyIDs[0] != "pol-1" {
		t.Fatalf("Finding.ObservedPolicyIDs = %#v, want [pol-1]", finding.ObservedPolicyIDs)
	}
	if finding.CheckID != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("Finding.CheckID = %q, want identity-okta-policy-rule-lifecycle-tampering-30d", finding.CheckID)
	}
	if finding.CheckName != "Okta Policy Rule Lifecycle Tampering (30 days)" {
		t.Fatalf("Finding.CheckName = %q, want check name", finding.CheckName)
	}
	if len(finding.ControlRefs) != 2 {
		t.Fatalf("len(Finding.ControlRefs) = %d, want 2", len(finding.ControlRefs))
	}
	if got := finding.ControlRefs[0].FrameworkName; got != "SOC 2" {
		t.Fatalf("Finding.ControlRefs[0].FrameworkName = %q, want SOC 2", got)
	}
	if got := finding.ControlRefs[0].ControlID; got != "CC6.2" {
		t.Fatalf("Finding.ControlRefs[0].ControlID = %q, want CC6.2", got)
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

func TestEvaluateSourceRuntimeFindingsReusesLegacyOktaTamperingID(t *testing.T) {
	eventID := "okta-audit-2"
	legacyID := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, eventID)
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent(eventID, "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			legacyID: {
				ID:           legacyID,
				Fingerprint:  legacyID,
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       oktaPolicyRuleLifecycleTamperingRuleID,
				Title:        oktaPolicyRuleLifecycleTamperingTitle,
				Severity:     "HIGH",
				Status:       findingStatusSuppressed,
				Summary:      "legacy finding",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				EventIDs:     []string{eventID},
				FindingWorkflow: ports.FindingWorkflow{
					StatusReason:    "accepted risk",
					StatusUpdatedAt: time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC),
				},
				FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
				LastObservedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
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
		RuntimeID: "writer-okta-audit",
		RuleID:    oktaPolicyRuleLifecycleTamperingRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if got := finding.ID; got != legacyID {
		t.Fatalf("Finding.ID = %q, want legacy id %q", got, legacyID)
	}
	if got := finding.Fingerprint; got != legacyID {
		t.Fatalf("Finding.Fingerprint = %q, want legacy fingerprint %q", got, legacyID)
	}
	if got := finding.Status; got != findingStatusSuppressed {
		t.Fatalf("Finding.Status = %q, want suppressed", got)
	}
	if got := finding.StatusReason; got != "accepted risk" {
		t.Fatalf("Finding.StatusReason = %q, want accepted risk", got)
	}
	if len(store.findings) != 1 {
		t.Fatalf("len(store.findings) = %d, want 1", len(store.findings))
	}
	if got := result.Evidence[0].GetFindingId(); got != legacyID {
		t.Fatalf("Evidence[0].FindingId = %q, want legacy id %q", got, legacyID)
	}
}

func TestOktaPolicyRuleLifecycleTamperingRequiresSuccessfulOutcome(t *testing.T) {
	missingOutcome := newAuditEvent("okta-audit-2", "policy.rule.update", "")
	delete(missingOutcome.Attributes, "outcome_result")
	if matchesOktaPolicyRuleLifecycleTampering(missingOutcome) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for missing outcome, want false")
	}
	failedOutcome := newAuditEvent("okta-audit-3", "policy.rule.update", "FAILURE")
	if matchesOktaPolicyRuleLifecycleTampering(failedOutcome) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for failed outcome, want false")
	}
	successOutcome := newAuditEvent("okta-audit-4", "policy.rule.update", "SUCCESS")
	if !matchesOktaPolicyRuleLifecycleTampering(successOutcome) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = false for success outcome, want true")
	}
}

func TestEvaluateSourceRuntimeFindingsReplaysGitHubDependabotAlert(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newGitHubDependabotAlertEvent("github-dependabot-alert-7", "open"),
			newGitHubDependabotAlertEvent("github-dependabot-alert-8", "fixed"),
		},
	}
	store := &stubFindingStore{}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-github": {
					Id:       "writer-github",
					SourceId: "github",
					TenantId: "writer",
				},
			},
		},
		replayer,
		store,
		store,
		store,
		store,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-github",
		RuleID:     githubDependabotOpenAlertRuleID,
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := result.EventsEvaluated; got != 2 {
		t.Fatalf("EventsEvaluated = %d, want 2", got)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1", got)
	}
	finding := result.Findings[0]
	if got := finding.RuleID; got != githubDependabotOpenAlertRuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", got, githubDependabotOpenAlertRuleID)
	}
	if got := finding.Severity; got != "HIGH" {
		t.Fatalf("Finding.Severity = %q, want HIGH", got)
	}
	if got := finding.PolicyID; got != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("Finding.PolicyID = %q, want GHSA", got)
	}
	if got := finding.Attributes["rule_tags"]; got != "github,dependabot,vulnerability,supply-chain,attack.initial-access" {
		t.Fatalf("Finding rule tags = %q, want github Dependabot tags", got)
	}
	if got := finding.Attributes["rule_required_attributes"]; got != "repository,alert_number,state" {
		t.Fatalf("Finding rule required attributes = %q, want repository,alert_number,state", got)
	}
	primaryResourceURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	if got := finding.Attributes["primary_resource_urn"]; got != primaryResourceURN {
		t.Fatalf("Finding primary resource urn = %q, want %q", got, primaryResourceURN)
	}
	if !slices.Contains(finding.ResourceURNs, primaryResourceURN) {
		t.Fatalf("Finding.ResourceURNs missing %q: %#v", primaryResourceURN, finding.ResourceURNs)
	}
	if got := len(result.Evidence); got != 1 {
		t.Fatalf("len(Evidence) = %d, want 1", got)
	}
}

func TestEvaluateSourceRuntimeFindingsProjectsRecordedFindingToGraph(t *testing.T) {
	store := &stubFindingStore{}
	graph := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-github": {
					Id:       "writer-github",
					SourceId: "github",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newGitHubDependabotAlertEvent("github-dependabot-alert-7", "open"),
			},
		},
		store,
		store,
		store,
		store,
	).WithGraphStore(graph).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-github",
		RuleID:    githubDependabotOpenAlertRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1", got)
	}
	finding := result.Findings[0]
	findingURN := "urn:cerebro:writer:finding:" + finding.ID
	primaryResourceURN := finding.Attributes["primary_resource_urn"]
	if _, ok := graph.entities[findingURN]; !ok {
		t.Fatalf("graph finding entity %q missing", findingURN)
	}
	if _, ok := graph.links[primaryResourceURN+"|has_finding|"+findingURN]; !ok {
		t.Fatalf("graph has_finding link missing for %s -> %s", primaryResourceURN, findingURN)
	}
	if got := len(appendLog.events); got != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", got)
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindFindingRecorded {
		t.Fatalf("appendLog.events[0].Kind = %q, want %q", got, workflowevents.EventKindFindingRecorded)
	}
}

func TestEvaluateSourceRuntimeFindingsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestEvaluateSourceRuntimeFindingsPersistsNormalizedFailedRun(t *testing.T) {
	registry, err := NewRegistry(&failingRule{
		spec: &cerebrov1.RuleSpec{
			Id:   "failing-rule",
			Name: "Failing Rule",
		},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		err:                errors.New("rule failed"),
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

	_, err = service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		RuleID:     "failing-rule",
		EventLimit: maxEventLimit + 1,
	})
	if err == nil {
		t.Fatal("EvaluateSourceRuntime() error = nil, want non-nil")
	}
	if got := replayer.request.Limit; got != maxEventLimit {
		t.Fatalf("Replay().Limit = %d, want %d", got, maxEventLimit)
	}
	if got := len(store.runs); got != 1 {
		t.Fatalf("len(store.runs) = %d, want 1", got)
	}
	for _, run := range store.runs {
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("Run.Status = %q, want failed", got)
		}
		if got := run.GetEventLimit(); got != maxEventLimit {
			t.Fatalf("Run.EventLimit = %d, want %d", got, maxEventLimit)
		}
		if got := run.GetEventsEvaluated(); got != 0 {
			t.Fatalf("Run.EventsEvaluated = %d, want 0", got)
		}
	}
}

func TestEvaluateSourceRuntimeFindingsDeduplicatesEvidencePerRun(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-2",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
			},
		},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit", RuleID: "rule-a"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Evidence); got != 1 {
		t.Fatalf("len(Evidence) = %d, want 1", got)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("len(store.evidence) = %d, want 1", got)
	}
}

func TestListRulesReturnsBuiltinCatalog(t *testing.T) {
	service := New(nil, nil, nil, nil, nil, nil)
	response := service.ListRules()
	if got := len(response.GetRules()); got < 10 {
		t.Fatalf("len(ListRules().Rules) = %d, want at least 10", got)
	}
	ruleIDs := make([]string, 0, len(response.GetRules()))
	for _, rule := range response.GetRules() {
		ruleIDs = append(ruleIDs, rule.GetId())
	}
	if !slices.Contains(ruleIDs, githubDependabotOpenAlertRuleID) {
		t.Fatalf("ListRules().Rules missing %q: %#v", githubDependabotOpenAlertRuleID, ruleIDs)
	}
	if !slices.Contains(ruleIDs, githubSecretScanningDisabledRuleID) {
		t.Fatalf("ListRules().Rules missing %q: %#v", githubSecretScanningDisabledRuleID, ruleIDs)
	}
	if !slices.Contains(ruleIDs, oktaPolicyRuleLifecycleTamperingRuleID) {
		t.Fatalf("ListRules().Rules missing %q: %#v", oktaPolicyRuleLifecycleTamperingRuleID, ruleIDs)
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

func TestEvaluateSourceRuntimeRulesMarksStartedRunsFailedWhenLaterRunStartFails(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-1",
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-1",
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutOn:  2,
		failRunPutErr: errors.New("run store unavailable"),
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want non-nil")
	}
	if got := len(store.runs); got != 1 {
		t.Fatalf("len(store.runs) = %d, want 1 started run", got)
	}
	for _, run := range store.runs {
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("started run status = %q, want failed", got)
		}
		if got := run.GetError(); !strings.Contains(got, "run store unavailable") {
			t.Fatalf("started run error = %q, want run store unavailable", got)
		}
		if run.GetFinishedAt() == nil {
			t.Fatal("started run finished_at = nil, want populated")
		}
	}
}

func TestEvaluateSourceRuntimeRulesAttemptsAllStartedRunFailuresWhenCleanupFails(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-c", Name: "Rule C"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutByCall: map[int]error{
			3: errors.New("run start failed"),
			4: errors.New("rule-a failure update failed"),
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want non-nil")
	}
	message := err.Error()
	for _, want := range []string{"run start failed", "rule-a failure update failed"} {
		if !strings.Contains(message, want) {
			t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want to contain %q", err, want)
		}
	}
	if got := store.runPutCount; got != 5 {
		t.Fatalf("store.runPutCount = %d, want 5", got)
	}
	ruleBRun, ok := runForRule(store.runs, "rule-b")
	if !ok {
		t.Fatal("rule-b run missing")
	}
	if got := ruleBRun.GetStatus(); got != "failed" {
		t.Fatalf("rule-b run status = %q, want failed", got)
	}
	if got := ruleBRun.GetError(); !strings.Contains(got, "run start failed") {
		t.Fatalf("rule-b run error = %q, want run start failed", got)
	}
}

func TestEvaluateSourceRuntimeRulesMarksUnfinishedRunsFailedWhenCompletionFails(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutByCall: map[int]error{
			3: errors.New("run completion failed"),
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want non-nil")
	}
	message := err.Error()
	if !strings.Contains(message, "run completion failed") {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want run completion failed", err)
	}
	if got := store.runPutCount; got != 5 {
		t.Fatalf("store.runPutCount = %d, want 5", got)
	}
	for _, ruleID := range []string{"rule-a", "rule-b"} {
		run, ok := runForRule(store.runs, ruleID)
		if !ok {
			t.Fatalf("%s run missing", ruleID)
		}
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("%s run status = %q, want failed", ruleID, got)
		}
	}
}

func TestEvaluateSourceRuntimeRulesPreservesEarlierFailureWhenCompletionCleanupRuns(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-1",
		},
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                errors.New("rule-b exploded"),
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutByCall: map[int]error{
			4: errors.New("run completion failed"),
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.update", "SUCCESS")}},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want non-nil")
	}
	ruleBRun, ok := runForRule(store.runs, "rule-b")
	if !ok {
		t.Fatal("rule-b run missing")
	}
	if got := ruleBRun.GetStatus(); got != "failed" {
		t.Fatalf("rule-b run status = %q, want failed", got)
	}
	if got := ruleBRun.GetError(); !strings.Contains(got, "rule-b exploded") {
		t.Fatalf("rule-b run error = %q, want rule-b exploded", got)
	}
	if got := ruleBRun.GetError(); strings.Contains(got, "run completion failed") {
		t.Fatalf("rule-b run error = %q, should preserve original rule failure", got)
	}
}

func TestEvaluateSourceRuntimeRulesReturnsEvaluationAndRunFailureCauses(t *testing.T) {
	registry, err := NewRegistry(&failingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		err:                errors.New("rule exploded"),
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutOn:  2,
		failRunPutErr: errors.New("run update failed"),
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.update", "SUCCESS")}},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want non-nil")
	}
	message := err.Error()
	for _, want := range []string{"evaluate finding rule", "rule exploded", "run update failed"} {
		if !strings.Contains(message, want) {
			t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want to contain %q", err, want)
		}
	}
}

func TestEvaluateSourceRuntimeRulesDeduplicatesEvidencePerRun(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-2",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
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
	service := NewWithRegistry(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
			},
		},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	if got := len(result.Evaluations[0].Evidence); got != 1 {
		t.Fatalf("len(Evaluation.Evidence) = %d, want 1", got)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("len(store.evidence) = %d, want 1", got)
	}
}

func TestFindingEvidenceIDIncludesEventIDs(t *testing.T) {
	first := findingEvidenceID("runtime", "finding", "run", []string{"event-1"})
	second := findingEvidenceID("runtime", "finding", "run", []string{"event-2"})
	if first == second {
		t.Fatalf("findingEvidenceID() = %q for distinct events, want unique IDs", first)
	}
	reordered := findingEvidenceID("runtime", "finding", "run", []string{"event-2", "event-1"})
	sorted := findingEvidenceID("runtime", "finding", "run", []string{"event-1", "event-2"})
	if reordered != sorted {
		t.Fatalf("findingEvidenceID() depends on event order: %q != %q", reordered, sorted)
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

func TestEvaluateSourceRuntimeRulesReplaysGitHubAuditSOTASignals(t *testing.T) {
	ruleIDs := []string{
		githubSecretScanningDisabledRuleID,
		githubPushProtectionDisabledRuleID,
		githubBranchProtectionDisabledRuleID,
		githubRepositoryMadePublicRuleID,
		githubSecretScanningAlertCreatedRuleID,
		githubSelfHostedRunnerChangeRuleID,
		githubRepositoryCollaboratorAddedRuleID,
		githubOrganizationOwnerAddedRuleID,
		githubCodeSecurityControlsDisabledRuleID,
		githubOrgAuthControlModifiedRuleID,
		githubOrgIPAllowListModifiedRuleID,
		githubAppIntegrationInstalledRuleID,
		githubPersonalAccessTokenCreatedRuleID,
		githubProtectedBranchPolicyOverrideRuleID,
		githubRepositoryRulesetModifiedRuleID,
		githubCriticalResourceDeletedRuleID,
		githubWebhookModifiedRuleID,
		githubPrivateRepositoryForkingEnabledRuleID,
	}
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
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newGitHubAuditSignalEvent("github-audit-secret-scanning-disabled", map[string]string{"action": "repository_secret_scanning.disable", "repo": "writer/cerebro", "resource_type": "repository_secret_scanning"}),
				newGitHubAuditSignalEvent("github-audit-push-protection-disabled", map[string]string{"action": "org.secret_scanning_push_protection_disable", "resource_id": "writer", "resource_type": "org"}),
				newGitHubAuditSignalEvent("github-audit-branch-protection-disabled", map[string]string{"action": "protected_branch.destroy", "repo": "writer/cerebro", "resource_type": "protected_branch"}),
				newGitHubAuditSignalEvent("github-audit-repo-made-public", map[string]string{"action": "repo.access", "repo": "writer/cerebro", "previous_visibility": "private", "visibility": "public", "resource_type": "repo"}),
				newGitHubAuditSignalEvent("github-audit-secret-alert-created", map[string]string{"action": "secret_scanning_alert.create", "repo": "writer/cerebro", "number": "12", "resource_type": "secret_scanning_alert"}),
				newGitHubAuditSignalEvent("github-audit-runner-registered", map[string]string{"action": "repo.register_self_hosted_runner", "repo": "writer/cerebro", "resource_type": "repo"}),
				newGitHubAuditSignalEvent("github-audit-collaborator-added", map[string]string{"action": "repo.add_member", "repo": "writer/cerebro", "resource_type": "repo", "user": "octocat"}),
				newGitHubAuditSignalEvent("github-audit-owner-added", map[string]string{"action": "org.add_member", "resource_id": "writer", "resource_type": "org", "permission": "admin", "user": "octocat"}),
				newGitHubAuditSignalEvent("github-audit-code-security-disabled", map[string]string{"action": "dependabot_alerts.disable", "repo": "writer/cerebro", "resource_type": "dependabot_alerts"}),
				newGitHubAuditSignalEvent("github-audit-org-auth-modified", map[string]string{"action": "org.disable_two_factor_requirement", "resource_id": "writer", "resource_type": "org"}),
				newGitHubAuditSignalEvent("github-audit-ip-allow-list-disabled", map[string]string{"action": "ip_allow_list.disable", "resource_id": "writer", "resource_type": "ip_allow_list"}),
				newGitHubAuditSignalEvent("github-audit-app-installed", map[string]string{"action": "integration_installation.create", "name": "ci-deployer", "resource_id": "writer", "resource_type": "integration_installation"}),
				newGitHubAuditSignalEvent("github-audit-pat-created", map[string]string{"action": "personal_access_token.access_granted", "operation_type": "create", "resource_id": "octocat", "resource_type": "personal_access_token", "user": "octocat"}),
				newGitHubAuditSignalEvent("github-audit-branch-policy-override", map[string]string{"action": "protected_branch.policy_override", "branch": "main", "repo": "writer/cerebro", "resource_type": "protected_branch"}),
				newGitHubAuditSignalEvent("github-audit-ruleset-modified", map[string]string{"action": "repository_ruleset.destroy", "repo": "writer/cerebro", "resource_type": "repository_ruleset", "ruleset_id": "42", "ruleset_name": "main protections"}),
				newGitHubAuditSignalEvent("github-audit-repo-destroyed", map[string]string{"action": "repo.destroy", "repo": "writer/cerebro", "resource_type": "repo"}),
				newGitHubAuditSignalEvent("github-audit-hook-created", map[string]string{"action": "hook.create", "hook_id": "99", "repo": "writer/cerebro", "resource_type": "hook"}),
				newGitHubAuditSignalEvent("github-audit-private-forking-enabled", map[string]string{"action": "private_repository_forking.enable", "resource_id": "writer", "resource_type": "org"}),
			},
		},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
		&stubFindingStore{},
	)
	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID:  "writer-github-audit",
		RuleIDs:    ruleIDs,
		EventLimit: 20,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	findingsByRule := map[string]*ports.FindingRecord{}
	for _, evaluation := range result.Evaluations {
		if len(evaluation.Findings) == 1 {
			findingsByRule[evaluation.Rule.GetId()] = evaluation.Findings[0]
		}
	}
	for _, ruleID := range ruleIDs {
		if findingsByRule[ruleID] == nil {
			t.Fatalf("EvaluateSourceRuntimeRules() missing finding for %q", ruleID)
		}
		primaryResourceURN := findingsByRule[ruleID].Attributes["primary_resource_urn"]
		if primaryResourceURN == "" {
			t.Fatalf("finding %q missing primary_resource_urn", ruleID)
		}
		if !slices.Contains(findingsByRule[ruleID].ResourceURNs, primaryResourceURN) {
			t.Fatalf("finding %q ResourceURNs missing primary resource %q: %#v", ruleID, primaryResourceURN, findingsByRule[ruleID].ResourceURNs)
		}
	}
	if got := findingsByRule[githubRepositoryMadePublicRuleID].Summary; got != "admin changed writer/cerebro visibility from private to public" {
		t.Fatalf("repository public summary = %q", got)
	}
	if got := findingsByRule[githubOrganizationOwnerAddedRuleID].Severity; got != "HIGH" {
		t.Fatalf("organization owner severity = %q, want HIGH", got)
	}
}

func TestListFindingsReturnsFilteredPersistedFindings(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       "writer",
				RuntimeID:      "writer-okta-audit",
				RuleID:         oktaPolicyRuleLifecycleTamperingRuleID,
				Severity:       "HIGH",
				Status:         "open",
				PolicyID:       "pol-1",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				EventIDs:       []string{"okta-audit-2"},
				LastObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
			"finding-2": {
				ID:             "finding-2",
				TenantID:       "writer",
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
		PolicyID:    "pol-1",
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
	if got := store.request.TenantID; got != "writer" {
		t.Fatalf("ListFindings().TenantID = %q, want writer", got)
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
	if got := store.request.PolicyID; got != "pol-1" {
		t.Fatalf("ListFindings().PolicyID = %q, want pol-1", got)
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

func TestFindingValidationErrorsAreInvalidRequests(t *testing.T) {
	store := &stubFindingStore{}
	service := New(&stubRuntimeStore{}, &stubReplayer{}, store, store, store, store)
	for _, tt := range []struct {
		name string
		call func() error
	}{
		{name: "evaluate missing runtime", call: func() error {
			_, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{})
			return err
		}},
		{name: "evaluate rules missing runtime", call: func() error {
			_, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{})
			return err
		}},
		{name: "list findings missing runtime", call: func() error {
			_, err := service.ListFindings(context.Background(), ListRequest{})
			return err
		}},
		{name: "get finding missing id", call: func() error {
			_, err := service.GetFinding(context.Background(), "")
			return err
		}},
		{name: "resolve missing id", call: func() error {
			_, err := service.ResolveFinding(context.Background(), "", "")
			return err
		}},
		{name: "assign missing id", call: func() error {
			_, err := service.AssignFinding(context.Background(), "", "alice")
			return err
		}},
		{name: "due date missing", call: func() error {
			_, err := service.SetFindingDueDate(context.Background(), "finding-1", time.Time{})
			return err
		}},
		{name: "note missing", call: func() error {
			_, err := service.AddFindingNote(context.Background(), "finding-1", "")
			return err
		}},
		{name: "ticket url missing", call: func() error {
			_, err := service.LinkFindingTicket(context.Background(), "finding-1", "", "", "")
			return err
		}},
		{name: "ticket url invalid", call: func() error {
			_, err := service.LinkFindingTicket(context.Background(), "finding-1", "://bad", "", "")
			return err
		}},
		{name: "list runs missing runtime", call: func() error {
			_, err := service.ListEvaluationRuns(context.Background(), ListEvaluationRunsRequest{})
			return err
		}},
		{name: "get run missing id", call: func() error {
			_, err := service.GetEvaluationRun(context.Background(), "")
			return err
		}},
		{name: "list evidence missing runtime", call: func() error {
			_, err := service.ListEvidence(context.Background(), ListEvidenceRequest{})
			return err
		}},
		{name: "get evidence missing id", call: func() error {
			_, err := service.GetEvidence(context.Background(), "")
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestGetFindingReturnsPersistedFinding(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:     "finding-1",
				Status: "open",
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	finding, err := service.GetFinding(context.Background(), "finding-1")
	if err != nil {
		t.Fatalf("GetFinding() error = %v", err)
	}
	if got := finding.ID; got != "finding-1" {
		t.Fatalf("GetFinding().ID = %q, want finding-1", got)
	}
}

func TestResolveFindingUpdatesPersistedWorkflow(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {ID: "finding-1", Status: "open"},
		},
	}
	service := New(nil, nil, store, store, store, store)
	finding, err := service.ResolveFinding(context.Background(), "finding-1", "verified remediation")
	if err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}
	if got := finding.Status; got != "resolved" {
		t.Fatalf("ResolveFinding().Status = %q, want resolved", got)
	}
	if got := finding.StatusReason; got != "verified remediation" {
		t.Fatalf("ResolveFinding().StatusReason = %q, want verified remediation", got)
	}
	if finding.StatusUpdatedAt.IsZero() {
		t.Fatal("ResolveFinding().StatusUpdatedAt = zero, want non-zero")
	}
}

func TestResolveFindingBridgesDecisionAndOutcomeWhenGraphConfigured(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Title:        "Okta Policy Rule Lifecycle Tampering",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_actor:user:00u1", "urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	graphStore := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_actor:user:00u1": {
				URN:        "urn:cerebro:writer:okta_actor:user:00u1",
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.actor",
				Label:      "admin@writer.com",
			},
			"urn:cerebro:writer:okta_resource:policyrule:pol-1": {
				URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithGraphQueryStore(graphStore).WithAppendLog(appendLog)
	finding, err := service.ResolveFinding(context.Background(), "finding-1", "verified remediation")
	if err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}
	if got := finding.Status; got != "resolved" {
		t.Fatalf("ResolveFinding().Status = %q, want resolved", got)
	}
	decisionCount := 0
	outcomeCount := 0
	for _, entity := range graphStore.entities {
		if entity == nil {
			continue
		}
		switch entity.EntityType {
		case "decision":
			decisionCount++
		case "outcome":
			outcomeCount++
		}
	}
	if decisionCount != 1 {
		t.Fatalf("decision entity count = %d, want 1", decisionCount)
	}
	if outcomeCount != 1 {
		t.Fatalf("outcome entity count = %d, want 1", outcomeCount)
	}
	if len(appendLog.events) != 3 {
		t.Fatalf("len(appendLog.events) = %d, want 3", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindFindingStatusChanged {
		t.Fatalf("first append event kind = %q, want %q", got, workflowevents.EventKindFindingStatusChanged)
	}
}

func TestAssignFindingUpdatesPersistedWorkflow(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {ID: "finding-1", Status: "open"},
		},
	}
	service := New(nil, nil, store, store, store, store)
	finding, err := service.AssignFinding(context.Background(), "finding-1", "secops")
	if err != nil {
		t.Fatalf("AssignFinding() error = %v", err)
	}
	if got := finding.Assignee; got != "secops" {
		t.Fatalf("AssignFinding().Assignee = %q, want secops", got)
	}
}

func TestSetFindingDueDateUpdatesPersistedWorkflow(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {ID: "finding-1", Status: "open"},
		},
	}
	service := New(nil, nil, store, store, store, store)
	dueAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	finding, err := service.SetFindingDueDate(context.Background(), "finding-1", dueAt)
	if err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if got := finding.DueAt; !got.Equal(dueAt) {
		t.Fatalf("SetFindingDueDate().DueAt = %v, want %v", got, dueAt)
	}
}

func TestAddFindingNoteUpdatesPersistedWorkflow(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				Title:        "Okta Policy Rule Lifecycle Tampering",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	graphStore := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(appendLog)
	finding, err := service.AddFindingNote(context.Background(), "finding-1", "Escalate to identity engineering.")
	if err != nil {
		t.Fatalf("AddFindingNote() error = %v", err)
	}
	if got := len(finding.Notes); got != 1 {
		t.Fatalf("len(AddFindingNote().Notes) = %d, want 1", got)
	}
	if got := finding.Notes[0].Body; got != "Escalate to identity engineering." {
		t.Fatalf("AddFindingNote().Notes[0].Body = %q, want note body", got)
	}
	if finding.Notes[0].CreatedAt.IsZero() {
		t.Fatal("AddFindingNote().Notes[0].CreatedAt = zero, want non-zero")
	}
	annotationURN := "urn:cerebro:writer:annotation:finding-note:finding-1:" + finding.Notes[0].ID
	if _, ok := graphStore.entities[annotationURN]; !ok {
		t.Fatalf("graph annotation %q missing", annotationURN)
	}
	if _, ok := graphStore.entities["urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("graph finding anchor missing")
	}
	if _, ok := graphStore.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|annotated_with|"+annotationURN]; !ok {
		t.Fatal("resource annotation link missing")
	}
	if _, ok := graphStore.links["urn:cerebro:writer:finding:finding-1|annotated_with|"+annotationURN]; !ok {
		t.Fatal("finding annotation link missing")
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindFindingNoteAdded {
		t.Fatalf("append event kind = %q, want %q", got, workflowevents.EventKindFindingNoteAdded)
	}
}

func TestLinkFindingTicketUpdatesPersistedWorkflow(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				Title:        "Okta Policy Rule Lifecycle Tampering",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	graphStore := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(appendLog)
	finding, err := service.LinkFindingTicket(
		context.Background(),
		"finding-1",
		"https://jira.writer.com/browse/ENG-123",
		"ENG-123",
		"ENG-123",
	)
	if err != nil {
		t.Fatalf("LinkFindingTicket() error = %v", err)
	}
	if got := len(finding.Tickets); got != 1 {
		t.Fatalf("len(LinkFindingTicket().Tickets) = %d, want 1", got)
	}
	if got := finding.Tickets[0].URL; got != "https://jira.writer.com/browse/ENG-123" {
		t.Fatalf("LinkFindingTicket().Tickets[0].URL = %q, want ticket url", got)
	}
	if finding.Tickets[0].LinkedAt.IsZero() {
		t.Fatal("LinkFindingTicket().Tickets[0].LinkedAt = zero, want non-zero")
	}
	ticketURN := findingGraphTicketURN("writer", finding.Tickets[0].URL)
	if _, ok := graphStore.entities[ticketURN]; !ok {
		t.Fatalf("graph ticket %q missing", ticketURN)
	}
	if _, ok := graphStore.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|tracked_by|"+ticketURN]; !ok {
		t.Fatal("resource ticket link missing")
	}
	if _, ok := graphStore.links["urn:cerebro:writer:finding:finding-1|tracked_by|"+ticketURN]; !ok {
		t.Fatal("finding ticket link missing")
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindFindingTicketLinked {
		t.Fatalf("append event kind = %q, want %q", got, workflowevents.EventKindFindingTicketLinked)
	}
}

func TestEvaluateSourceRuntimePreservesManualWorkflowFields(t *testing.T) {
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
				SourceEventID: "okta-audit-2",
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

	first, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		RuleID:     oktaPolicyRuleLifecycleTamperingRuleID,
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("first EvaluateSourceRuntime() error = %v", err)
	}
	findingID := first.Findings[0].ID
	dueAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if _, err := service.AssignFinding(context.Background(), findingID, "secops"); err != nil {
		t.Fatalf("AssignFinding() error = %v", err)
	}
	if _, err := service.SetFindingDueDate(context.Background(), findingID, dueAt); err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if _, err := service.AddFindingNote(context.Background(), findingID, "Escalate to identity engineering."); err != nil {
		t.Fatalf("AddFindingNote() error = %v", err)
	}
	if _, err := service.LinkFindingTicket(context.Background(), findingID, "https://jira.writer.com/browse/ENG-123", "ENG-123", "ENG-123"); err != nil {
		t.Fatalf("LinkFindingTicket() error = %v", err)
	}
	if _, err := service.ResolveFinding(context.Background(), findingID, "triaged"); err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}

	second, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		RuleID:     oktaPolicyRuleLifecycleTamperingRuleID,
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("second EvaluateSourceRuntime() error = %v", err)
	}
	if got := second.Findings[0].Status; got != "resolved" {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].Status = %q, want resolved", got)
	}
	if got := second.Findings[0].Assignee; got != "secops" {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].Assignee = %q, want secops", got)
	}
	if got := second.Findings[0].DueAt; !got.Equal(dueAt) {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].DueAt = %v, want %v", got, dueAt)
	}
	if got := len(second.Findings[0].Notes); got != 1 {
		t.Fatalf("len(second EvaluateSourceRuntime().Findings[0].Notes) = %d, want 1", got)
	}
	if got := second.Findings[0].Notes[0].Body; got != "Escalate to identity engineering." {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].Notes[0].Body = %q, want note body", got)
	}
	if got := len(second.Findings[0].Tickets); got != 1 {
		t.Fatalf("len(second EvaluateSourceRuntime().Findings[0].Tickets) = %d, want 1", got)
	}
	if got := second.Findings[0].Tickets[0].URL; got != "https://jira.writer.com/browse/ENG-123" {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].Tickets[0].URL = %q, want ticket url", got)
	}
	if got := second.Findings[0].StatusReason; got != "triaged" {
		t.Fatalf("second EvaluateSourceRuntime().Findings[0].StatusReason = %q, want triaged", got)
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

func newGitHubDependabotAlertEvent(id string, state string) *cerebrov1.EventEnvelope {
	alertNumber := "7"
	if strings.Contains(id, "8") {
		alertNumber = "8"
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.dependabot_alert",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "github/dependabot_alert/v1",
		Attributes: map[string]string{
			"advisory_cve_id":                   "CVE-2026-0001",
			"advisory_ghsa_id":                  "GHSA-xxxx-yyyy-zzzz",
			"advisory_severity":                 "high",
			"alert_number":                      alertNumber,
			"ecosystem":                         "go",
			"family":                            "dependabot_alert",
			"first_patched_version":             "0.31.0",
			"html_url":                          "https://github.com/writer/cerebro/security/dependabot/" + alertNumber,
			"owner":                             "writer",
			"package":                           "golang.org/x/crypto",
			"repo":                              "cerebro",
			"repository":                        "writer/cerebro",
			"severity":                          "high",
			"state":                             state,
			"vulnerability_severity":            "high",
			"vulnerable_version_range":          "< 0.31.0",
			ports.EventAttributeSourceRuntimeID: "writer-github",
		},
	}
}

func newGitHubAuditSignalEvent(id string, attributes map[string]string) *cerebrov1.EventEnvelope {
	eventAttributes := map[string]string{
		"actor":                             "admin",
		"family":                            "audit",
		"operation_type":                    "modify",
		"org":                               "writer",
		"resource_id":                       firstNonEmpty(attributes["repo"], "writer"),
		ports.EventAttributeSourceRuntimeID: "writer-github-audit",
	}
	for key, value := range attributes {
		eventAttributes[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "github/audit/v1",
		Attributes: eventAttributes,
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
	observedPolicyIDs := make([]string, len(finding.ObservedPolicyIDs))
	copy(observedPolicyIDs, finding.ObservedPolicyIDs)
	controlRefs := make([]ports.FindingControlRef, len(finding.ControlRefs))
	copy(controlRefs, finding.ControlRefs)
	notes := make([]ports.FindingNote, len(finding.Notes))
	copy(notes, finding.Notes)
	tickets := make([]ports.FindingTicket, len(finding.Tickets))
	copy(tickets, finding.Tickets)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantID:          finding.TenantID,
		RuntimeID:         finding.RuntimeID,
		RuleID:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            finding.Status,
		Summary:           finding.Summary,
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func preserveFindingWorkflow(existing *ports.FindingRecord, incoming *ports.FindingRecord) *ports.FindingRecord {
	if existing == nil || incoming == nil {
		return incoming
	}
	if strings.TrimSpace(existing.Assignee) != "" && strings.TrimSpace(incoming.Assignee) == "" {
		incoming.Assignee = strings.TrimSpace(existing.Assignee)
	}
	if !existing.DueAt.IsZero() && incoming.DueAt.IsZero() {
		incoming.DueAt = existing.DueAt
	}
	if len(existing.Notes) != 0 && len(incoming.Notes) == 0 {
		incoming.Notes = append([]ports.FindingNote(nil), existing.Notes...)
	}
	if len(existing.Tickets) != 0 && len(incoming.Tickets) == 0 {
		incoming.Tickets = append([]ports.FindingTicket(nil), existing.Tickets...)
	}
	if strings.TrimSpace(incoming.Status) == "open" {
		switch strings.TrimSpace(existing.Status) {
		case "resolved", "suppressed":
			incoming.Status = strings.TrimSpace(existing.Status)
			incoming.StatusReason = strings.TrimSpace(existing.StatusReason)
			incoming.StatusUpdatedAt = existing.StatusUpdatedAt
		}
	}
	return incoming
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
	if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
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
	if request.PolicyID != "" && strings.TrimSpace(finding.PolicyID) != strings.TrimSpace(request.PolicyID) {
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

func runForRule(runs map[string]*cerebrov1.FindingEvaluationRun, ruleID string) (*cerebrov1.FindingEvaluationRun, bool) {
	for _, run := range runs {
		if strings.TrimSpace(run.GetRuleId()) == strings.TrimSpace(ruleID) {
			return run, true
		}
	}
	return nil, false
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

func TestFindingEvaluationRunIDIsUniqueAcrossSameNanosecond(t *testing.T) {
	t.Parallel()
	startedAt := time.Unix(0, 1700000000000000000).UTC()
	first := findingEvaluationRunID("writer-jira", "rule-a", startedAt)
	second := findingEvaluationRunID("writer-jira", "rule-a", startedAt)
	if first == second {
		t.Fatalf("findingEvaluationRunID() = %q, want unique random suffix between calls", first)
	}
	collidingFirst := findingEvaluationRunID("writer-jira", "rule_a", startedAt)
	collidingNormalized := findingEvaluationRunID("writer-jira", "rule-a", startedAt)
	if strings.HasPrefix(collidingFirst, "finding-evaluation-run-writer-jira-rule-a-") &&
		strings.HasPrefix(collidingNormalized, "finding-evaluation-run-writer-jira-rule-a-") {
		// Strip the random suffix and ensure the deterministic hash differs so callers
		// distinguishing by raw rule id do not collide on normalization alone.
		firstHash := strings.Split(collidingFirst, "-")[7]
		secondHash := strings.Split(collidingNormalized, "-")[7]
		if firstHash == secondHash {
			t.Fatalf("findingEvaluationRunID() hash suffix collides for normalized rule ids: %s vs %s", collidingFirst, collidingNormalized)
		}
	}
}

func TestFindingEvidenceIDDistinguishesNormalizationCollisions(t *testing.T) {
	t.Parallel()
	first := findingEvidenceID("rt:a", "finding_x", "run-1", []string{"event-1"})
	second := findingEvidenceID("rt-a", "finding-x", "run-1", []string{"event-1"})
	if first == second {
		t.Fatalf("findingEvidenceID() = %q, want distinct ids for raw inputs that normalize alike", first)
	}
}
