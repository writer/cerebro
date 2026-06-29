package findings

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findingevidence"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
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
	calls   int
	err     error
}

func (s *stubReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	s.calls++
	s.request = request
	if s.err != nil {
		return nil, s.err
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(s.events))
	for _, event := range s.events {
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	}
	return events, nil
}

type recordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
	err    error
}

func (s *recordingAppendLog) Ping(context.Context) error { return nil }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

type stubFindingStore struct {
	findings                  map[string]*ports.FindingRecord
	request                   ports.ListFindingsRequest
	listFindingsRequests      []ports.ListFindingsRequest
	listFindingsErr           error
	claims                    map[string]*ports.ClaimRecord
	claimListRequest          ports.ListClaimsRequest
	runs                      map[string]*cerebrov1.FindingEvaluationRun
	runList                   ports.ListFindingEvaluationRunsRequest
	runPutCount               int
	failRunPutOn              int
	failRunPutErr             error
	failRunPutByCall          map[int]error
	evidence                  map[string]*cerebrov1.FindingEvidence
	evidenceList              ports.ListFindingEvidenceRequest
	putEvidenceErr            error
	candidateState            stubFindingCandidateState
	dropReturnedGraphEvidence bool
	upsertCount               int
	updateRiskCount           int
	markRiskProjectedCount    int
	markRiskProjectedErr      error
	backfillState             stubFindingBackfillState
	updateStatusCallCount     int
	updateStatusCalls         []ports.FindingStatusUpdate
}

type stubFindingCandidateState struct {
	runs               map[string]*ports.FindingCandidateRun
	candidates         map[string]*ports.FindingCandidateRecord
	listRequest        ports.ListFindingCandidatesRequest
	expirationRequest  ports.FindingCandidateExpiration
	upsertCount        int
	expireCount        int
	markPromotedCount  int
	markRejectedCount  int
	beforeMarkPromote  func()
	beforeMarkReject   func()
	riskScoringConfigs map[string]*ports.RiskScoringConfig
}

type stubFindingBackfillState struct {
	results            []*ports.FindingRecord
	err                error
	includeUnprojected bool
}

func (s *stubFindingStore) Ping(context.Context) error { return nil }

func (s *stubFindingStore) PutRiskScoringConfig(_ context.Context, config *ports.RiskScoringConfig) error {
	if config == nil {
		return errors.New("risk scoring config is required")
	}
	if s.candidateState.riskScoringConfigs == nil {
		s.candidateState.riskScoringConfigs = map[string]*ports.RiskScoringConfig{}
	}
	s.candidateState.riskScoringConfigs[strings.TrimSpace(config.TenantID)] = cloneRiskScoringConfig(config)
	return nil
}

func (s *stubFindingStore) GetRiskScoringConfig(_ context.Context, tenantID string) (*ports.RiskScoringConfig, error) {
	if s.candidateState.riskScoringConfigs == nil {
		return nil, ports.ErrRiskScoringConfigNotFound
	}
	config, ok := s.candidateState.riskScoringConfigs[strings.TrimSpace(tenantID)]
	if !ok {
		return nil, ports.ErrRiskScoringConfigNotFound
	}
	return cloneRiskScoringConfig(config), nil
}

func (s *stubFindingStore) DeleteRiskScoringConfig(_ context.Context, tenantID string) error {
	delete(s.candidateState.riskScoringConfigs, strings.TrimSpace(tenantID))
	return nil
}

func (s *stubFindingStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	s.upsertCount++
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	cloned := cloneFinding(finding)
	if existing, ok := s.findings[cloned.ID]; ok {
		cloned = preserveFindingWorkflow(existing, cloned)
		// Mirror the postgres ON CONFLICT clause (`runtime_id = findings.runtime_id`) so
		// stub-store tests catch regressions in the runtime-pinning contract; without this
		// the stub would silently let graph-rule findings flip between triggering runtimes.
		if existingRuntimeID := strings.TrimSpace(existing.RuntimeID); existingRuntimeID != "" {
			cloned.RuntimeID = existingRuntimeID
		}
	}
	s.findings[cloned.ID] = cloned
	returned := cloneFinding(cloned)
	if s.dropReturnedGraphEvidence {
		returned.GraphEvidenceRows = nil
	}
	return returned, nil
}

func (s *stubFindingStore) UpdateFindingRisk(_ context.Context, request ports.FindingRiskUpdate) (*ports.FindingRecord, error) {
	s.updateRiskCount++
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	updated := cloneFinding(finding)
	updated.FindingRisk = request.FindingRisk
	if updated.Attributes == nil {
		updated.Attributes = map[string]string{}
	}
	for key, value := range request.Attributes {
		updated.Attributes[key] = value
	}
	s.findings[updated.ID] = updated
	return cloneFinding(updated), nil
}

func (s *stubFindingStore) MarkFindingRiskProjected(_ context.Context, request ports.FindingRiskUpdate) (*ports.FindingRecord, error) {
	s.markRiskProjectedCount++
	if s.markRiskProjectedErr != nil {
		return nil, s.markRiskProjectedErr
	}
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	updated := cloneFinding(finding)
	if updated.RiskScore != request.RiskScore || strings.TrimSpace(updated.RiskModelVersion) != strings.TrimSpace(request.RiskModelVersion) {
		return nil, ports.ErrFindingNotFound
	}
	if updated.Attributes == nil {
		updated.Attributes = map[string]string{}
	}
	for key, value := range request.Attributes {
		updated.Attributes[key] = value
	}
	s.findings[updated.ID] = updated
	return cloneFinding(updated), nil
}

func (s *stubFindingStore) BackfillFindingRisk(_ context.Context, includeUnprojected bool) ([]*ports.FindingRecord, error) {
	s.backfillState.includeUnprojected = includeUnprojected
	if s.backfillState.err != nil {
		return nil, s.backfillState.err
	}
	results := make([]*ports.FindingRecord, 0, len(s.backfillState.results))
	for _, finding := range s.backfillState.results {
		results = append(results, cloneFinding(finding))
	}
	return results, nil
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
	s.listFindingsRequests = append(s.listFindingsRequests, request)
	if s.listFindingsErr != nil {
		return nil, s.listFindingsErr
	}
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
	if expected := strings.TrimSpace(request.ExpectedStatus); expected != "" && strings.TrimSpace(finding.Status) != expected {
		return nil, ports.ErrFindingStatusPreconditionFailed
	}
	if cutoff := request.LastObservedBefore.UTC(); !cutoff.IsZero() && !finding.LastObservedAt.Before(cutoff) {
		return nil, ports.ErrFindingStatusPreconditionFailed
	}
	s.updateStatusCallCount++
	s.updateStatusCalls = append(s.updateStatusCalls, request)
	cloned := cloneFinding(finding)
	cloned.Status = strings.TrimSpace(request.Status)
	cloned.StatusReason = strings.TrimSpace(request.Reason)
	cloned.StatusUpdatedAt = request.UpdatedAt.UTC()
	if len(request.EventIDs) != 0 {
		cloned.EventIDs = uniqueTrimmedStringsPreserveOrder(append(append([]string(nil), cloned.EventIDs...), request.EventIDs...))
	}
	if request.Tombstone != nil {
		t := request.Tombstone
		tombstonedAt := t.TombstonedAt.UTC()
		if tombstonedAt.IsZero() {
			tombstonedAt = cloned.StatusUpdatedAt
		}
		cloned.Tombstoned = true
		cloned.TombstonedAt = tombstonedAt
		cloned.TombstonedBy = strings.TrimSpace(t.By)
		cloned.TombstonedReason = strings.TrimSpace(t.Reason)
		cloned.TombstonedRunID = strings.TrimSpace(t.RunID)
		cloned.PriorStatus = strings.TrimSpace(t.PriorStatus)
	}
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

func (s *stubFindingStore) LinkFindingExternalRef(_ context.Context, request ports.FindingExternalRefLink) (*ports.FindingRecord, error) {
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	replaced := false
	for index, ref := range cloned.ExternalRefs {
		if externalRefKey(ref) == externalRefKey(request.ExternalRef) {
			cloned.ExternalRefs[index] = request.ExternalRef
			replaced = true
			break
		}
	}
	if !replaced {
		cloned.ExternalRefs = append(cloned.ExternalRefs, request.ExternalRef)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func externalRefKey(ref ports.FindingExternalRef) string {
	return strings.TrimSpace(ref.System) + "|" + strings.TrimSpace(ref.Kind) + "|" + strings.TrimSpace(ref.ExternalID)
}

type stubGraphStore struct {
	entities   map[string]*ports.ProjectedEntity
	links      map[string]*ports.ProjectedLink
	cypherRows []ports.CypherRow
	cypherErr  error
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

func (s *stubGraphStore) ExecuteReadCypher(_ context.Context, _ ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	if s.cypherErr != nil {
		return nil, s.cypherErr
	}
	return s.cypherRows, nil
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

func (s *stubGraphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	delete(s.entities, urn)
	for key, link := range s.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(s.links, key)
		}
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
	if s.putEvidenceErr != nil {
		return s.putEvidenceErr
	}
	if evidence == nil {
		return errors.New("finding evidence is required")
	}
	if s.evidence == nil {
		s.evidence = make(map[string]*cerebrov1.FindingEvidence)
	}
	cloned := findingevidence.Normalize(evidence)
	if existing := s.evidence[evidence.GetId()]; existing != nil {
		cloned = findingevidence.Merge(existing, cloned)
	}
	if cloned.GetLastObservedAt() == nil || cloned.GetLastObservedAt().AsTime().IsZero() {
		cloned.LastObservedAt = cloned.GetCreatedAt()
	}
	s.evidence[evidence.GetId()] = cloned
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

func (s *stubFindingStore) PutFindingCandidateRun(_ context.Context, run *ports.FindingCandidateRun) error {
	if run == nil {
		return errors.New("finding candidate run is required")
	}
	if s.candidateState.runs == nil {
		s.candidateState.runs = make(map[string]*ports.FindingCandidateRun)
	}
	cloned := *run
	s.candidateState.runs[cloned.ID] = &cloned
	return nil
}

func (s *stubFindingStore) GetFindingCandidateRun(_ context.Context, id string) (*ports.FindingCandidateRun, error) {
	run, ok := s.candidateState.runs[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	cloned := *run
	return &cloned, nil
}

func (s *stubFindingStore) ListFindingCandidateRuns(_ context.Context, request ports.ListFindingCandidatesRequest) ([]*ports.FindingCandidateRun, error) {
	runs := make([]*ports.FindingCandidateRun, 0, len(s.candidateState.runs))
	for _, run := range s.candidateState.runs {
		if strings.TrimSpace(request.RuntimeID) != "" && strings.TrimSpace(run.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
			continue
		}
		if strings.TrimSpace(request.RuleID) != "" && strings.TrimSpace(run.RuleID) != strings.TrimSpace(request.RuleID) {
			continue
		}
		if strings.TrimSpace(request.Status) != "" && strings.TrimSpace(run.Status) != strings.TrimSpace(request.Status) {
			continue
		}
		cloned := *run
		runs = append(runs, &cloned)
	}
	return runs, nil
}

func (s *stubFindingStore) UpsertFindingCandidate(_ context.Context, candidate *ports.FindingCandidateRecord) (*ports.FindingCandidateRecord, error) {
	if candidate == nil {
		return nil, errors.New("finding candidate is required")
	}
	s.candidateState.upsertCount++
	if s.candidateState.candidates == nil {
		s.candidateState.candidates = make(map[string]*ports.FindingCandidateRecord)
	}
	cloned := cloneFindingCandidate(candidate)
	if existing := s.candidateState.candidates[cloned.ID]; existing != nil {
		cloned.ObservationCount += existing.ObservationCount
		switch existing.Status {
		case findingCandidateStatusPromoted:
			cloned.Status = existing.Status
			cloned.PromotedFindingID = existing.PromotedFindingID
			cloned.DecisionID = existing.DecisionID
			cloned.PromotedBy = existing.PromotedBy
			cloned.PromotionRationale = existing.PromotionRationale
			cloned.ChangeTicket = existing.ChangeTicket
			cloned.PromotedAt = existing.PromotedAt
		case findingCandidateStatusRejected:
			cloned.Status = existing.Status
			cloned.DecisionID = existing.DecisionID
			cloned.RejectedBy = existing.RejectedBy
			cloned.RejectionRationale = existing.RejectionRationale
			cloned.RejectedAt = existing.RejectedAt
		}
	}
	s.candidateState.candidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
}

func (s *stubFindingStore) GetFindingCandidate(_ context.Context, id string) (*ports.FindingCandidateRecord, error) {
	candidate, ok := s.candidateState.candidates[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	return cloneFindingCandidate(candidate), nil
}

func (s *stubFindingStore) ListFindingCandidates(_ context.Context, request ports.ListFindingCandidatesRequest) ([]*ports.FindingCandidateRecord, error) {
	s.candidateState.listRequest = request
	candidates := make([]*ports.FindingCandidateRecord, 0, len(s.candidateState.candidates))
	for _, candidate := range s.candidateState.candidates {
		if strings.TrimSpace(request.RuntimeID) != "" && strings.TrimSpace(candidate.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
			continue
		}
		if strings.TrimSpace(request.RuleID) != "" && strings.TrimSpace(candidate.RuleID) != strings.TrimSpace(request.RuleID) {
			continue
		}
		if strings.TrimSpace(request.Status) != "" && strings.TrimSpace(candidate.Status) != strings.TrimSpace(request.Status) {
			continue
		}
		if strings.TrimSpace(request.CandidateID) != "" && strings.TrimSpace(candidate.ID) != strings.TrimSpace(request.CandidateID) {
			continue
		}
		if strings.TrimSpace(request.Fingerprint) != "" && strings.TrimSpace(candidate.Fingerprint) != strings.TrimSpace(request.Fingerprint) {
			continue
		}
		candidates = append(candidates, cloneFindingCandidate(candidate))
	}
	return candidates, nil
}

func (s *stubFindingStore) ExpireStaleFindingCandidates(_ context.Context, request ports.FindingCandidateExpiration) (int, error) {
	s.candidateState.expireCount++
	s.candidateState.expirationRequest = request
	eventIDs := map[string]struct{}{}
	for _, eventID := range request.EvaluatedEventIDs {
		if eventID = strings.TrimSpace(eventID); eventID != "" {
			eventIDs[eventID] = struct{}{}
		}
	}
	if len(eventIDs) == 0 {
		return 0, nil
	}
	expired := 0
	for id, candidate := range s.candidateState.candidates {
		if strings.TrimSpace(candidate.TenantID) != strings.TrimSpace(request.TenantID) ||
			strings.TrimSpace(candidate.RuntimeID) != strings.TrimSpace(request.RuntimeID) ||
			strings.TrimSpace(candidate.RuleID) != strings.TrimSpace(request.RuleID) ||
			strings.TrimSpace(candidate.Status) != findingCandidateStatusCandidate ||
			strings.TrimSpace(candidate.LastRunID) == strings.TrimSpace(request.RunID) ||
			(!candidate.UpdatedAt.IsZero() && !candidate.UpdatedAt.Before(request.RunStartedAt)) ||
			!candidateFindingOverlapsEvaluatedEvent(candidate.Finding, eventIDs) {
			continue
		}
		cloned := cloneFindingCandidate(candidate)
		cloned.Status = findingCandidateStatusExpired
		cloned.UpdatedAt = time.Now().UTC()
		s.candidateState.candidates[id] = cloned
		expired++
	}
	return expired, nil
}

func candidateFindingOverlapsEvaluatedEvent(finding *ports.FindingRecord, eventIDs map[string]struct{}) bool {
	if finding == nil {
		return false
	}
	for _, eventID := range finding.EventIDs {
		if _, ok := eventIDs[strings.TrimSpace(eventID)]; ok {
			return true
		}
	}
	return false
}

func (s *stubFindingStore) MarkFindingCandidatePromoted(_ context.Context, promotion ports.FindingCandidatePromotion) (*ports.FindingCandidateRecord, error) {
	s.candidateState.markPromotedCount++
	if s.candidateState.beforeMarkPromote != nil {
		s.candidateState.beforeMarkPromote()
	}
	candidate, ok := s.candidateState.candidates[strings.TrimSpace(promotion.CandidateID)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned := cloneFindingCandidate(candidate)
	if cloned.Status != findingCandidateStatusCandidate {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned.Status = findingCandidateStatusPromoted
	cloned.PromotedFindingID = strings.TrimSpace(promotion.PromotedFindingID)
	cloned.DecisionID = strings.TrimSpace(promotion.DecisionID)
	cloned.PromotedBy = strings.TrimSpace(promotion.PromotedBy)
	cloned.PromotionRationale = strings.TrimSpace(promotion.Rationale)
	cloned.ChangeTicket = strings.TrimSpace(promotion.ChangeTicket)
	cloned.PromotedAt = promotion.PromotedAt.UTC()
	s.candidateState.candidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
}

func (s *stubFindingStore) MarkFindingCandidateRejected(_ context.Context, rejection ports.FindingCandidateRejection) (*ports.FindingCandidateRecord, error) {
	s.candidateState.markRejectedCount++
	if s.candidateState.beforeMarkReject != nil {
		s.candidateState.beforeMarkReject()
	}
	candidate, ok := s.candidateState.candidates[strings.TrimSpace(rejection.CandidateID)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned := cloneFindingCandidate(candidate)
	if cloned.Status != findingCandidateStatusCandidate {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned.Status = findingCandidateStatusRejected
	cloned.DecisionID = strings.TrimSpace(rejection.DecisionID)
	cloned.RejectedBy = strings.TrimSpace(rejection.RejectedBy)
	cloned.RejectionRationale = strings.TrimSpace(rejection.Rationale)
	cloned.RejectedAt = rejection.RejectedAt.UTC()
	s.candidateState.candidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
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

type metadataStubRule struct {
	*stubRule
	definition RuleDefinition
}

func (r *metadataStubRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func TestReplayExactKindFiltersForRulesIntersectRuntimeKind(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-okta-policy-rule",
		SourceId: "okta",
		Config:   map[string]string{"family": "policy_rule"},
	}
	rules := []Rule{
		&metadataStubRule{
			stubRule: &stubRule{
				spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
				supportedSourceIDs: map[string]struct{}{"okta": {}},
			},
			definition: RuleDefinition{EventKinds: []string{"okta.audit", "okta.policy_rule"}},
		},
		&metadataStubRule{
			stubRule: &stubRule{
				spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
				supportedSourceIDs: map[string]struct{}{"okta": {}},
			},
			definition: RuleDefinition{EventKinds: []string{"okta.policy_rule"}},
		},
		&metadataStubRule{
			stubRule: &stubRule{
				spec:               &cerebrov1.RuleSpec{Id: "rule-c"},
				supportedSourceIDs: map[string]struct{}{"github": {}},
			},
			definition: RuleDefinition{EventKinds: []string{"github.audit"}},
		},
	}

	request := replayRequestForRules(runtime, runtime.GetId(), 25, rules, true)
	if !request.ExactKindFilters {
		t.Fatal("ExactKindFilters = false, want true")
	}
	if got, want := request.KindPrefixes, []string{"okta.policy_rule"}; !slices.Equal(got, want) {
		t.Fatalf("KindPrefixes = %#v, want %#v", got, want)
	}
	if got := request.RuntimeID; got != runtime.GetId() {
		t.Fatalf("RuntimeID = %q, want %q", got, runtime.GetId())
	}
	if got := request.Limit; got != uint32(25) {
		t.Fatalf("Limit = %d, want 25", got)
	}
	if !request.RequireRuntimeIndex {
		t.Fatal("RequireRuntimeIndex = false, want true")
	}
}

func TestReplayExactKindFiltersForRulesRequireSupportingRuleCoverage(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-okta-policy-rule",
		SourceId: "okta",
		Config:   map[string]string{"family": "policy_rule"},
	}
	covered := &metadataStubRule{
		stubRule: &stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "covered"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		definition: RuleDefinition{EventKinds: []string{"okta.policy_rule"}},
	}
	opaque := &stubRule{
		spec:               &cerebrov1.RuleSpec{Id: "opaque"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
	}
	if got := replayExactKindFiltersForRules(runtime, []Rule{covered, opaque}); len(got) != 0 {
		t.Fatalf("replayExactKindFiltersForRules() with opaque supporting rule = %#v, want nil", got)
	}

	mismatched := &metadataStubRule{
		stubRule: &stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "mismatched"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		definition: RuleDefinition{EventKinds: []string{"okta.audit"}},
	}
	if got := replayExactKindFiltersForRules(runtime, []Rule{covered, mismatched}); len(got) != 0 {
		t.Fatalf("replayExactKindFiltersForRules() with uncovered metadata rule = %#v, want nil", got)
	}
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

type counterAnchorRule struct {
	spec       *cerebrov1.RuleSpec
	definition RuleDefinition
	sourceID   string
}

var _ CounterEventRule = (*counterAnchorRule)(nil)

func newCounterAnchorRule(ruleID string) *counterAnchorRule {
	definition := RuleDefinition{
		ID:          strings.TrimSpace(ruleID),
		Name:        "Counter Anchor Rule",
		SourceID:    "github",
		EventKinds:  []string{"github.audit"},
		OutputKind:  "finding",
		Severity:    "HIGH",
		Status:      "active",
		Maturity:    "experimental",
		Lifecycle:   Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
		ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}},
	}
	return &counterAnchorRule{
		spec:       &cerebrov1.RuleSpec{Id: strings.TrimSpace(ruleID), Name: definition.Name},
		definition: definition,
		sourceID:   definition.SourceID,
	}
}

func (r *counterAnchorRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.spec).(*cerebrov1.RuleSpec)
}

func (r *counterAnchorRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), strings.TrimSpace(r.sourceID))
}

func (r *counterAnchorRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *counterAnchorRule) Evaluate(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || event == nil || strings.TrimSpace(event.GetAttributes()["action"]) != "open" {
		return nil, nil
	}
	anchor := r.OpenAnchor(event.GetAttributes())
	if anchor == "" {
		return nil, nil
	}
	observedAt := event.GetOccurredAt().AsTime().UTC()
	findingIDReplacer := strings.NewReplacer("|", "-", "/", "-")
	findingID := strings.TrimSpace(r.spec.GetId()) + "-" + findingIDReplacer.Replace(anchor)
	return []*ports.FindingRecord{
		{
			ID:              findingID,
			Fingerprint:     findingID,
			TenantID:        strings.TrimSpace(event.GetTenantId()),
			RuntimeID:       strings.TrimSpace(runtime.GetId()),
			RuleID:          strings.TrimSpace(r.spec.GetId()),
			Title:           r.spec.GetName(),
			Severity:        "HIGH",
			Status:          findingStatusOpen,
			Summary:         "counter anchor rule open finding",
			ResourceURNs:    []string{"urn:cerebro:writer:github_code_repository:" + strings.TrimSpace(event.GetAttributes()["repo"])},
			EventIDs:        []string{strings.TrimSpace(event.GetId())},
			ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
			Attributes:      map[string]string{"repo": strings.TrimSpace(event.GetAttributes()["repo"]), "user": strings.TrimSpace(event.GetAttributes()["user"])},
			FirstObservedAt: observedAt,
			LastObservedAt:  observedAt,
		},
	}, nil
}

func (r *counterAnchorRule) OpenAnchor(attributes map[string]string) string {
	return counterRuleAnchor(attributes)
}

func (r *counterAnchorRule) CloseOnEvent(event *cerebrov1.EventEnvelope) (string, bool) {
	if event == nil || strings.TrimSpace(event.GetAttributes()["action"]) != "close" {
		return "", false
	}
	anchor := counterRuleAnchor(event.GetAttributes())
	return anchor, anchor != ""
}

type nonCounterAnchorRule struct {
	spec       *cerebrov1.RuleSpec
	definition RuleDefinition
	sourceID   string
}

func newNonCounterAnchorRule(ruleID string) *nonCounterAnchorRule {
	counter := newCounterAnchorRule(ruleID)
	return &nonCounterAnchorRule{
		spec:       counter.spec,
		definition: counter.definition,
		sourceID:   counter.sourceID,
	}
}

func (r *nonCounterAnchorRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.spec).(*cerebrov1.RuleSpec)
}

func (r *nonCounterAnchorRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), strings.TrimSpace(r.sourceID))
}

func (r *nonCounterAnchorRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *nonCounterAnchorRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func counterRuleAnchor(attributes map[string]string) string {
	repo := strings.TrimSpace(attributes["repo"])
	user := strings.TrimSpace(attributes["user"])
	if repo == "" || user == "" {
		return ""
	}
	return repo + "|" + user
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
			newOktaPolicyRuleEvent("okta-policy-rule-active", "ACTIVE"),
			newOktaPolicyRuleEvent("okta-policy-rule-inactive", "INACTIVE"),
		},
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-policy-rule",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1",
				Predicate:     "status",
				ObjectValue:   "INACTIVE",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "okta-policy-rule-inactive",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	service := New(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"family": "policy_rule"},
			},
		},
	}, replayer, store, store, store, store)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-policy-rule",
		RuleID:     oktaPolicyRuleLifecycleTamperingRuleID,
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result.Runtime.GetId() != "writer-okta-policy-rule" {
		t.Fatalf("Runtime.ID = %q, want writer-okta-policy-rule", result.Runtime.GetId())
	}
	if result.Rule.GetId() != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Rule.ID = %q, want %q", result.Rule.GetId(), oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if result.EventsEvaluated != 2 {
		t.Fatalf("EventsEvaluated = %d, want 2", result.EventsEvaluated)
	}
	if got := replayer.request.RuntimeID; got != "writer-okta-policy-rule" {
		t.Fatalf("Replay().RuntimeID = %q, want writer-okta-policy-rule", got)
	}
	if got := replayer.request.Limit; got != 25 {
		t.Fatalf("Replay().Limit = %d, want 25", got)
	}
	if !replayer.request.ExactKindFilters {
		t.Fatal("Replay().ExactKindFilters = false, want true")
	}
	if got, want := replayer.request.KindPrefixes, []string{"okta.policy_rule"}; !slices.Equal(got, want) {
		t.Fatalf("Replay().KindPrefixes = %#v, want %#v", got, want)
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
	if finding.Summary != "Okta policy rule Require MFA is INACTIVE" {
		t.Fatalf("Finding.Summary = %q, want Okta policy rule Require MFA is INACTIVE", finding.Summary)
	}
	if !containsTrimmed(finding.ResourceURNs, "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1") {
		t.Fatalf("Finding.ResourceURNs = %#v, missing policy rule urn", finding.ResourceURNs)
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1" {
		t.Fatalf("Finding.Attributes[primary_resource_urn] = %q, want resource urn", finding.Attributes["primary_resource_urn"])
	}
	if finding.PolicyID != "pol-1" {
		t.Fatalf("Finding.PolicyID = %q, want pol-1", finding.PolicyID)
	}
	if finding.PolicyName != "Require MFA" {
		t.Fatalf("Finding.PolicyName = %q, want Require MFA", finding.PolicyName)
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
	if got := result.Run.GetEventsProcessed(); got != 2 {
		t.Fatalf("Run.EventsProcessed = %d, want 2", got)
	}
	if got := result.Run.GetEventsMatched(); got != 1 {
		t.Fatalf("Run.EventsMatched = %d, want 1", got)
	}
	if got := result.Run.GetFindingsEmitted(); got != 1 {
		t.Fatalf("Run.FindingsEmitted = %d, want 1", got)
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

func TestEvaluateSourceRuntimeFindingsUsesDurableOktaPolicyRuleFingerprint(t *testing.T) {
	eventID := "okta-policy-rule-inactive"
	legacyID := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, eventID)
	durableID := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1")
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newOktaPolicyRuleEvent(eventID, "INACTIVE"),
		},
	}
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			legacyID: {
				ID:           legacyID,
				Fingerprint:  legacyID,
				TenantID:     "writer",
				RuntimeID:    "writer-okta-policy-rule",
				RuleID:       oktaPolicyRuleLifecycleTamperingRuleID,
				Title:        oktaPolicyRuleLifecycleTamperingTitle,
				Severity:     "HIGH",
				Status:       findingStatusSuppressed,
				Summary:      "legacy finding",
				ResourceURNs: []string{"urn:cerebro:writer:okta_policy_rule:pol-1:rul-1"},
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
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"family": "policy_rule"},
			},
		},
	}, replayer, store, store, store, store)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-policy-rule",
		RuleID:    oktaPolicyRuleLifecycleTamperingRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if got := finding.ID; got != durableID {
		t.Fatalf("Finding.ID = %q, want durable policy-rule id %q", got, durableID)
	}
	if got := finding.Fingerprint; got != durableID {
		t.Fatalf("Finding.Fingerprint = %q, want durable policy-rule fingerprint %q", got, durableID)
	}
	if got := finding.Status; got != findingStatusOpen {
		t.Fatalf("Finding.Status = %q, want open", got)
	}
	if got := finding.Attributes["okta_policy_rule_urn"]; got != "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1" {
		t.Fatalf("Finding.Attributes[okta_policy_rule_urn] = %q, want policy rule urn", got)
	}
	if _, ok := store.findings[legacyID]; !ok {
		t.Fatalf("legacy finding %q missing; durable conversion should not mutate it", legacyID)
	}
	if len(store.findings) != 2 {
		t.Fatalf("len(store.findings) = %d, want legacy row plus new durable row", len(store.findings))
	}
	if got := result.Evidence[0].GetFindingId(); got != durableID {
		t.Fatalf("Evidence[0].FindingId = %q, want durable id %q", got, durableID)
	}
}

func TestOktaPolicyRuleLifecycleTamperingMatchesProjectedStateOnly(t *testing.T) {
	auditEvent := newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS")
	auditEvent.Attributes["policy_id"] = "pol-1"
	auditEvent.Attributes["policy_rule_id"] = "rul-1"
	auditEvent.Attributes["status"] = "INACTIVE"
	if matchesOktaPolicyRuleLifecycleTampering(auditEvent) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for audit event, want false")
	}
	missingStatus := newOktaPolicyRuleEvent("okta-policy-rule-missing-status", "")
	delete(missingStatus.Attributes, "status")
	if matchesOktaPolicyRuleLifecycleTampering(missingStatus) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for missing status, want false")
	}
	active := newOktaPolicyRuleEvent("okta-policy-rule-active", "ACTIVE")
	if matchesOktaPolicyRuleLifecycleTampering(active) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for active projected state, want false")
	}
	inactive := newOktaPolicyRuleEvent("okta-policy-rule-inactive", "INACTIVE")
	if !matchesOktaPolicyRuleLifecycleTampering(inactive) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = false for inactive projected state, want true")
	}
	deleted := newOktaPolicyRuleEvent("okta-policy-rule-deleted", "DELETED_PERMANENTLY")
	if matchesOktaPolicyRuleLifecycleTampering(deleted) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering() = true for permanently deleted projected state, want false until source-backed delete synthesis exists")
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
					Config:   map[string]string{"family": "dependabot_alert"},
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
					Config:   map[string]string{"family": "dependabot_alert"},
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
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingRecorded {
		t.Fatalf("appendLog.events[0].Kind = %q, want %q", got, securityevents.FindingRecorded)
	}
}

func TestEvaluateSourceRuntimeResolvesAndPrunesStaleFindings(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec: &cerebrov1.RuleSpec{
			Id:   "routine-oauth-rule",
			Name: "Routine OAuth Rule",
		},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "different-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	staleFinding := &ports.FindingRecord{
		ID:              "stale-oauth-finding",
		Fingerprint:     "stale-oauth-finding",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "routine-oauth-rule",
		Title:           "Routine OAuth Rule",
		Severity:        "HIGH",
		Status:          "open",
		Summary:         "routine OAuth grant was previously emitted",
		ResourceURNs:    []string{"urn:cerebro:writer:okta_application:0oa-client"},
		EventIDs:        []string{"okta-oauth-grant"},
		FirstObservedAt: time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC),
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{staleFinding.ID: staleFinding}}
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:finding:stale-oauth-finding": {
				URN:        "urn:cerebro:writer:finding:stale-oauth-finding",
				TenantID:   "writer",
				SourceID:   "writer-okta-audit",
				EntityType: "finding",
				Label:      "Routine OAuth Rule",
			},
		},
		links: map[string]*ports.ProjectedLink{
			"urn:cerebro:writer:okta_application:0oa-client|has_finding|urn:cerebro:writer:finding:stale-oauth-finding": {
				TenantID: "writer",
				SourceID: "writer-okta-audit",
				FromURN:  "urn:cerebro:writer:okta_application:0oa-client",
				ToURN:    "urn:cerebro:writer:finding:stale-oauth-finding",
				Relation: "has_finding",
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "okta-oauth-grant",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.audit",
			Attributes: map[string]string{
				"event_type": "app.oauth2.token.grant.access_token",
			},
			OccurredAt: timestamppb.New(time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(graph).WithGraphQueryStore(graph)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "routine-oauth-rule",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 0 {
		t.Fatalf("len(Findings) = %d, want 0", got)
	}
	resolved := store.findings["stale-oauth-finding"]
	if got := resolved.Status; got != "resolved" {
		t.Fatalf("stale finding status = %q, want resolved", got)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:stale-oauth-finding"]; ok {
		t.Fatal("stale finding graph entity should be pruned")
	}
	if len(graph.links) != 0 {
		t.Fatalf("graph links = %#v, want stale links pruned", graph.links)
	}
	for urn, entity := range graph.entities {
		if entity.EntityType == "decision" || entity.EntityType == "outcome" {
			t.Fatalf("auto-pruned finding should not leave workflow entity %q: %#v", urn, entity)
		}
	}
}

func TestEvaluateSourceRuntimeRetiredRuleResolvesOpenFindingsOutsideReplayWindow(t *testing.T) {
	registry, err := NewRegistry(newGitHubSecretScanningDisabledRule())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	retiredFinding := &ports.FindingRecord{
		ID:              "old-github-mirror-finding",
		Fingerprint:     "old-github-mirror-finding",
		TenantID:        "writer",
		RuntimeID:       "writer-github-audit",
		RuleID:          githubSecretScanningDisabledRuleID,
		Title:           "GitHub Secret Scanning Disabled",
		Severity:        "HIGH",
		Status:          "open",
		Summary:         "secret scanning was disabled by an old audit event",
		ResourceURNs:    []string{"urn:cerebro:writer:github_code_repository:writer/cerebro"},
		EventIDs:        []string{"github-old-event-outside-replay"},
		FirstObservedAt: time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC),
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{retiredFinding.ID: retiredFinding}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github-audit": {Id: "writer-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "github-recent-event",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "repo.access",
			},
			OccurredAt: timestamppb.New(time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-github-audit",
		RuleID:    githubSecretScanningDisabledRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 0 {
		t.Fatalf("len(Findings) = %d, want 0", got)
	}
	resolved := store.findings[retiredFinding.ID]
	if got := resolved.Status; got != findingStatusResolved {
		t.Fatalf("retired finding status = %q, want %q", got, findingStatusResolved)
	}
	if got := resolved.StatusReason; got != workflowevents.FindingStatusReasonNoLongerEmitted {
		t.Fatalf("retired finding status reason = %q, want %q", got, workflowevents.FindingStatusReasonNoLongerEmitted)
	}
}

func TestCounterEventRule_AnchorClose(t *testing.T) {
	rule := newCounterAnchorRule("counter-anchor-rule")
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	openedAt := time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC)
	staleFinding := &ports.FindingRecord{
		ID:              "counter-anchor-rule-writer-cerebro-alice",
		Fingerprint:     "counter-anchor-rule-writer-cerebro-alice",
		TenantID:        "writer",
		RuntimeID:       "example-github-audit",
		RuleID:          "counter-anchor-rule",
		Title:           "Counter Anchor Rule",
		Severity:        "HIGH",
		Status:          findingStatusOpen,
		Summary:         "repository collaborator remained risky",
		ResourceURNs:    []string{"urn:cerebro:writer:github_code_repository:writer/cerebro"},
		EventIDs:        []string{"github-open-event"},
		Attributes:      map[string]string{"repo": "writer/cerebro", "user": "alice"},
		FirstObservedAt: openedAt,
		LastObservedAt:  openedAt,
	}
	tombstonedFinding := cloneFinding(staleFinding)
	tombstonedFinding.ID = "counter-anchor-rule-tombstoned"
	tombstonedFinding.Fingerprint = "counter-anchor-rule-tombstoned"
	tombstonedFinding.Tombstoned = true
	tombstonedFinding.TombstonedAt = openedAt.Add(time.Hour)
	tombstonedFinding.EventIDs = []string{"github-open-tombstoned-event"}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		staleFinding.ID:      cloneFinding(staleFinding),
		tombstonedFinding.ID: cloneFinding(tombstonedFinding),
	}}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-github-audit": {Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "github-open-same-run",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "open",
				"repo":   "writer/cerebro",
				"user":   "bob",
			},
			OccurredAt: timestamppb.New(openedAt.Add(23 * time.Hour)),
		}, {
			Id:       "github-counter-event",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "close",
				"repo":   "writer/cerebro",
				"user":   "alice",
			},
			OccurredAt: timestamppb.New(openedAt.Add(24 * time.Hour)),
		}, {
			Id:       "github-counter-same-run",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "close",
				"repo":   "writer/cerebro",
				"user":   "bob",
			},
			OccurredAt: timestamppb.New(openedAt.Add(25 * time.Hour)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "example-github-audit",
		RuleID:    "counter-anchor-rule",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1 same-run open finding before counter close", got)
	}
	if got := strings.TrimSpace(result.Findings[0].ID); got != "counter-anchor-rule-writer-cerebro-bob" {
		t.Fatalf("result finding ID = %q, want same-run bob finding", got)
	}
	if got := result.Findings[0].Status; got != findingStatusResolved {
		t.Fatalf("result same-run finding status = %q, want %q", got, findingStatusResolved)
	}
	if got := result.Findings[0].StatusReason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("result same-run finding status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if !containsTrimmed(result.Findings[0].EventIDs, "github-counter-same-run") {
		t.Fatalf("result same-run finding EventIDs = %#v, want counter event evidence", result.Findings[0].EventIDs)
	}
	resolved := store.findings[staleFinding.ID]
	if got := resolved.Status; got != findingStatusResolved {
		t.Fatalf("counter-event finding status = %q, want %q", got, findingStatusResolved)
	}
	if got := resolved.StatusReason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("counter-event finding status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if !containsTrimmed(resolved.EventIDs, "github-open-event") || !containsTrimmed(resolved.EventIDs, "github-counter-event") {
		t.Fatalf("counter-event finding EventIDs = %#v, want original and counter event IDs", resolved.EventIDs)
	}
	sameRun := store.findings["counter-anchor-rule-writer-cerebro-bob"]
	if sameRun == nil {
		t.Fatal("same-run emitted finding was not persisted")
	}
	if got := sameRun.Status; got != findingStatusResolved {
		t.Fatalf("same-run counter-event finding status = %q, want %q", got, findingStatusResolved)
	}
	if got := sameRun.StatusReason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("same-run counter-event finding status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if !containsTrimmed(sameRun.EventIDs, "github-open-same-run") || !containsTrimmed(sameRun.EventIDs, "github-counter-same-run") {
		t.Fatalf("same-run counter-event finding EventIDs = %#v, want original and counter event IDs", sameRun.EventIDs)
	}
	tombstoned := store.findings[tombstonedFinding.ID]
	if got := tombstoned.Status; got != findingStatusOpen {
		t.Fatalf("tombstoned matching finding status = %q, want open", got)
	}
	if containsTrimmed(tombstoned.EventIDs, "github-counter-event") {
		t.Fatalf("tombstoned matching finding EventIDs = %#v, want no counter event evidence", tombstoned.EventIDs)
	}
	statusEvent := findStatusChangedPayload(t, appendLog.events, staleFinding.ID)
	if got := statusEvent.Reason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("workflow status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if got := statusEvent.Source; got != workflowevents.FindingStatusSourceStaleEvaluation {
		t.Fatalf("workflow status source = %q, want %q", got, workflowevents.FindingStatusSourceStaleEvaluation)
	}
	if !containsTrimmed(statusEvent.Finding.EventIDs, "github-counter-event") {
		t.Fatalf("workflow finding event_ids = %#v, want counter event evidence", statusEvent.Finding.EventIDs)
	}
	sameRunStatusEvent := findStatusChangedPayload(t, appendLog.events, sameRun.ID)
	if !containsTrimmed(sameRunStatusEvent.Finding.EventIDs, "github-counter-same-run") {
		t.Fatalf("same-run workflow finding event_ids = %#v, want counter event evidence", sameRunStatusEvent.Finding.EventIDs)
	}
	staleEvidence, err := service.ListEvidence(context.Background(), ListEvidenceRequest{
		RuntimeID: "example-github-audit",
		FindingID: staleFinding.ID,
		EventID:   "github-counter-event",
	})
	if err != nil {
		t.Fatalf("ListEvidence(stale close event) error = %v", err)
	}
	if got := len(staleEvidence.Evidence); got == 0 {
		t.Fatalf("ListEvidence(stale close event) returned %d rows, want close-event evidence", got)
	}
	sameRunEvidence, err := service.ListEvidence(context.Background(), ListEvidenceRequest{
		RuntimeID: "example-github-audit",
		FindingID: sameRun.ID,
		EventID:   "github-counter-same-run",
	})
	if err != nil {
		t.Fatalf("ListEvidence(same-run close event) error = %v", err)
	}
	if got := len(sameRunEvidence.Evidence); got == 0 {
		t.Fatalf("ListEvidence(same-run close event) returned %d rows, want close-event evidence", got)
	}
}

func TestResolveCounterEventOpenFindings_RefreshesResults(t *testing.T) {
	_, result := evaluateCounterEventSameRunClose(t)
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1 same-run finding", got)
	}
	finding := result.Findings[0]
	if got := finding.Status; got != findingStatusResolved {
		t.Fatalf("result finding status = %q, want %q", got, findingStatusResolved)
	}
	if got := finding.StatusReason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("result finding status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if !containsTrimmed(finding.EventIDs, "github-open-same-run") || !containsTrimmed(finding.EventIDs, "github-counter-same-run") {
		t.Fatalf("result finding EventIDs = %#v, want open and close event IDs", finding.EventIDs)
	}
}

func TestResolveCounterEventOpenFindings_PersistsCloseEvidence(t *testing.T) {
	service, result := evaluateCounterEventSameRunClose(t)
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1 same-run finding", got)
	}
	finding := result.Findings[0]
	evidence, err := service.ListEvidence(context.Background(), ListEvidenceRequest{
		RuntimeID: "example-github-audit",
		FindingID: finding.ID,
		EventID:   "github-counter-same-run",
	})
	if err != nil {
		t.Fatalf("ListEvidence(close event) error = %v", err)
	}
	if got := len(evidence.Evidence); got == 0 {
		t.Fatalf("ListEvidence(close event) returned %d rows, want close-event evidence", got)
	}
	if !containsTrimmed(evidence.Evidence[0].EventIds, "github-open-same-run") || !containsTrimmed(evidence.Evidence[0].EventIds, "github-counter-same-run") {
		t.Fatalf("close evidence EventIds = %#v, want open and close event IDs", evidence.Evidence[0].EventIds)
	}
}

func evaluateCounterEventSameRunClose(t *testing.T) (*Service, *EvaluateResult) {
	t.Helper()
	rule := newCounterAnchorRule("counter-anchor-rule")
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	openedAt := time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC)
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-github-audit": {Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "github-open-same-run",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "open",
				"repo":   "writer/cerebro",
				"user":   "bob",
			},
			OccurredAt: timestamppb.New(openedAt),
		}, {
			Id:       "github-counter-same-run",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "close",
				"repo":   "writer/cerebro",
				"user":   "bob",
			},
			OccurredAt: timestamppb.New(openedAt.Add(time.Hour)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{})

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "example-github-audit",
		RuleID:    "counter-anchor-rule",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	return service, result
}

func TestCounterEventRule_OlderCloseDoesNotResolveNewerOpenFinding(t *testing.T) {
	rule := newCounterAnchorRule("counter-anchor-rule")
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	openedAt := time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC)
	newerOpenAt := openedAt.Add(2 * time.Hour)
	currentFinding := &ports.FindingRecord{
		ID:              "counter-anchor-rule-writer-cerebro-alice",
		Fingerprint:     "counter-anchor-rule-writer-cerebro-alice",
		TenantID:        "writer",
		RuntimeID:       "example-github-audit",
		RuleID:          "counter-anchor-rule",
		Title:           "Counter Anchor Rule",
		Severity:        "HIGH",
		Status:          findingStatusOpen,
		Summary:         "repository collaborator remained risky after an older close",
		ResourceURNs:    []string{"urn:cerebro:writer:github_code_repository:writer/cerebro"},
		EventIDs:        []string{"github-newer-open-event"},
		Attributes:      map[string]string{"repo": "writer/cerebro", "user": "alice"},
		FirstObservedAt: openedAt,
		LastObservedAt:  newerOpenAt,
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		currentFinding.ID: cloneFinding(currentFinding),
	}}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-github-audit": {Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "github-older-counter-event",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "close",
				"repo":   "writer/cerebro",
				"user":   "alice",
			},
			OccurredAt: timestamppb.New(openedAt.Add(time.Hour)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "example-github-audit",
		RuleID:    "counter-anchor-rule",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 0 {
		t.Fatalf("len(Findings) = %d, want 0 because replay only contains an older close", got)
	}
	unchanged := store.findings[currentFinding.ID]
	if got := unchanged.Status; got != findingStatusOpen {
		t.Fatalf("newer open finding status = %q, want %q", got, findingStatusOpen)
	}
	if unchanged.StatusReason != "" {
		t.Fatalf("newer open finding status reason = %q, want empty", unchanged.StatusReason)
	}
	if containsTrimmed(unchanged.EventIDs, "github-older-counter-event") {
		t.Fatalf("newer open finding EventIDs = %#v, want no older counter-event evidence", unchanged.EventIDs)
	}
	if store.updateStatusCallCount != 0 {
		t.Fatalf("UpdateFindingStatus calls = %d, want 0", store.updateStatusCallCount)
	}
	if len(appendLog.events) != 0 {
		t.Fatalf("append log events = %d, want 0", len(appendLog.events))
	}
}

func TestCounterEventRule_NonImplementingUnaffected(t *testing.T) {
	rule := newNonCounterAnchorRule("non-counter-anchor-rule")
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	openedAt := time.Date(2026, 5, 7, 19, 54, 0, 0, time.UTC)
	staleFinding := &ports.FindingRecord{
		ID:              "non-counter-anchor-rule-writer-cerebro-alice",
		Fingerprint:     "non-counter-anchor-rule-writer-cerebro-alice",
		TenantID:        "writer",
		RuntimeID:       "example-github-audit",
		RuleID:          "non-counter-anchor-rule",
		Title:           "Non-Counter Anchor Rule",
		Severity:        "HIGH",
		Status:          findingStatusOpen,
		Summary:         "repository collaborator remained risky",
		ResourceURNs:    []string{"urn:cerebro:writer:github_code_repository:writer/cerebro"},
		EventIDs:        []string{"github-open-event"},
		Attributes:      map[string]string{"repo": "writer/cerebro", "user": "alice"},
		FirstObservedAt: openedAt,
		LastObservedAt:  openedAt,
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		staleFinding.ID: cloneFinding(staleFinding),
	}}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-github-audit": {Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:       "github-counter-event",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"action": "close",
				"repo":   "writer/cerebro",
				"user":   "alice",
			},
			OccurredAt: timestamppb.New(openedAt.Add(24 * time.Hour)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "example-github-audit",
		RuleID:    "non-counter-anchor-rule",
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(result.Findings); got != 0 {
		t.Fatalf("len(Findings) = %d, want 0", got)
	}
	unchanged := store.findings[staleFinding.ID]
	if got := unchanged.Status; got != findingStatusOpen {
		t.Fatalf("non-counter finding status = %q, want %q", got, findingStatusOpen)
	}
	if unchanged.StatusReason != "" {
		t.Fatalf("non-counter finding status reason = %q, want empty", unchanged.StatusReason)
	}
	if containsTrimmed(unchanged.EventIDs, "github-counter-event") {
		t.Fatalf("non-counter finding EventIDs = %#v, want no counter event evidence", unchanged.EventIDs)
	}
	if store.updateStatusCallCount != 0 {
		t.Fatalf("UpdateFindingStatus calls = %d, want 0", store.updateStatusCallCount)
	}
	if len(appendLog.events) != 0 {
		t.Fatalf("append log events = %d, want 0", len(appendLog.events))
	}
}

func TestEvaluateSourceRuntimeMarksRunFailedWhenStaleCleanupFails(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "routine-oauth-rule", Name: "Routine OAuth Rule"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "different-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{listFindingsErr: errors.New("list stale candidates failed")}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:         "okta-oauth-grant",
			TenantId:   "writer",
			SourceId:   "okta",
			Kind:       "okta.audit",
			OccurredAt: timestamppb.New(time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "routine-oauth-rule",
	})
	if err == nil {
		t.Fatal("EvaluateSourceRuntime() error = nil, want stale cleanup error")
	}
	run, ok := runForRule(store.runs, "routine-oauth-rule")
	if !ok {
		t.Fatal("routine-oauth-rule run missing")
	}
	if got := run.GetStatus(); got != "failed" {
		t.Fatalf("run status = %q, want failed", got)
	}
	if got := run.GetError(); !strings.Contains(got, "list stale candidates failed") {
		t.Fatalf("run error = %q, want stale cleanup error", got)
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
			newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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

func TestEvaluateSourceRuntimeFindingsCleansUpRemainingRunsWhenFailurePersistenceFails(t *testing.T) {
	registry, err := NewRegistry(
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "a-failing-rule", Name: "A Failing Rule"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                errors.New("rule failed"),
		},
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "z-failing-rule", Name: "Z Failing Rule"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                errors.New("rule failed"),
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")},
	}
	store := &stubFindingStore{
		failRunPutByCall: map[int]error{3: errors.New("persist failed run failed")},
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

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntime() error = nil, want non-nil")
	}
	runsByRule := map[string]*cerebrov1.FindingEvaluationRun{}
	for _, run := range store.runs {
		runsByRule[run.GetRuleId()] = run
	}
	if got := runsByRule["a-failing-rule"].GetStatus(); got != "failed" {
		t.Fatalf("a-failing-rule run status = %q, want failed", got)
	}
	if got := runsByRule["z-failing-rule"].GetStatus(); got != "failed" {
		t.Fatalf("z-failing-rule run status = %q, want failed", got)
	}
	if got := runsByRule["z-failing-rule"].GetError(); !strings.Contains(got, "persist failed run failed") {
		t.Fatalf("z-failing-rule run error = %q, want cleanup error", got)
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
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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

func TestFindingEvaluationRunFinalizersEmitTelemetry(t *testing.T) {
	store := &stubFindingStore{}
	service := &Service{runStore: store}
	run := &cerebrov1.FindingEvaluationRun{
		Id:         "run-1",
		RuntimeId:  "runtime-okta",
		RuleId:     "rule-a",
		EventLimit: 25,
		StartedAt:  timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
	}

	stderr := captureFindingStderr(t, func() {
		if err := service.finishCompletedRun(context.Background(), run, 7, 3, []string{"finding-1", "finding-2"}); err != nil {
			t.Fatalf("finishCompletedRun() error = %v", err)
		}
	})
	payload := decodeTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"kind":                             "event",
		"name":                             "finding_evaluation.run",
		"run_id":                           "run-1",
		"runtime_id":                       "runtime-okta",
		"rule_id":                          "rule-a",
		"status":                           "completed",
		"finding_evaluation.stage":         "finalize_run",
		"finding_evaluation.failure_stage": "",
		"finding_evaluation.rule_type":     "event_rule",
		"event_limit":                      float64(25),
		"events_processed":                 float64(7),
		"events_matched":                   float64(3),
		"findings_emitted":                 float64(2),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry[%s] = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestFailedFindingEvaluationRunFinalizerEmitsTelemetry(t *testing.T) {
	store := &stubFindingStore{}
	service := &Service{runStore: store}
	run := &cerebrov1.FindingEvaluationRun{
		Id:         "run-1",
		RuntimeId:  "runtime-okta",
		RuleId:     "rule-a",
		EventLimit: 25,
		StartedAt:  timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
	}

	stderr := captureFindingStderr(t, func() {
		err := service.finishFailedRun(context.Background(), run, 4, 1, []string{"finding-1"}, errors.New("boom"))
		if err == nil {
			t.Fatal("finishFailedRun() error = nil, want non-nil")
		}
	})
	payload := decodeTelemetryPayload(t, stderr)
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["events_processed"]; got != float64(4) {
		t.Fatalf("telemetry events_processed = %#v, want 4; payload=%#v", got, payload)
	}
	if got := payload["findings_emitted"]; got != float64(1) {
		t.Fatalf("telemetry findings_emitted = %#v, want 1; payload=%#v", got, payload)
	}
	for key, want := range map[string]any{
		"finding_evaluation.stage":         "unknown",
		"finding_evaluation.failure_stage": "unknown",
		"finding_evaluation.rule_type":     "event_rule",
		"error_kind":                       "error",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if got, ok := payload["error_fingerprint"].(string); !ok || got == "" {
		t.Fatalf("telemetry error_fingerprint missing: %#v", payload)
	}
}

func TestEvaluateSourceRuntimeFindingsDeduplicatesEvidenceAcrossRuns(t *testing.T) {
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
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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

	first, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit", RuleID: "rule-a"})
	if err != nil {
		t.Fatalf("first EvaluateSourceRuntime() error = %v", err)
	}
	second, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit", RuleID: "rule-a"})
	if err != nil {
		t.Fatalf("second EvaluateSourceRuntime() error = %v", err)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("len(store.evidence) = %d, want 1", got)
	}
	if first.Evidence[0].GetId() != second.Evidence[0].GetId() {
		t.Fatalf("evidence ids differ across same-shape runs: %q != %q", first.Evidence[0].GetId(), second.Evidence[0].GetId())
	}
	stored := store.evidence[first.Evidence[0].GetId()]
	if got := stored.GetRunId(); got != second.Run.GetId() {
		t.Fatalf("deduped evidence RunId = %q, want latest run %q", got, second.Run.GetId())
	}
	if !stored.GetCreatedAt().AsTime().Equal(first.Evidence[0].GetCreatedAt().AsTime()) {
		t.Fatalf("deduped evidence CreatedAt = %v, want original %v", stored.GetCreatedAt().AsTime(), first.Evidence[0].GetCreatedAt().AsTime())
	}
	if stored.GetLastObservedAt() == nil || stored.GetLastObservedAt().AsTime().IsZero() {
		t.Fatalf("deduped evidence LastObservedAt missing")
	}
	if !slices.Contains(stored.GetRunIds(), first.Run.GetId()) || !slices.Contains(stored.GetRunIds(), second.Run.GetId()) {
		t.Fatalf("deduped evidence RunIds = %#v, want both evaluation runs", stored.GetRunIds())
	}
	if got := stored.GetObservationCount(); got != 2 {
		t.Fatalf("deduped evidence ObservationCount = %d, want 2", got)
	}
	if got := len(stored.GetObservations()); got != 2 {
		t.Fatalf("len(deduped evidence Observations) = %d, want 2", got)
	}
	historical, err := service.ListEvidence(context.Background(), ListEvidenceRequest{RuntimeID: "writer-okta-audit", RunID: first.Run.GetId()})
	if err != nil {
		t.Fatalf("ListEvidence(first run) error = %v", err)
	}
	if got := len(historical.Evidence); got != 1 {
		t.Fatalf("len(ListEvidence(first run).Evidence) = %d, want 1", got)
	}
}

func TestBuildFindingEvidenceIncludesAttributesGraphPathsAndObservedAt(t *testing.T) {
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "runtime-okta",
				TenantID:      "writer",
				SourceEventID: "event-1",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	service := &Service{claimStore: store}
	finding := &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "writer",
		RuntimeID:    "runtime-okta",
		RuleID:       "rule-a",
		ResourceURNs: []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
		EventIDs:     []string{"event-1"},
		Attributes: map[string]string{
			"primary_resource_urn": "urn:cerebro:writer:identity:email:alice@writer.com",
			"actor":                "alice@writer.com",
			"empty":                "",
		},
		GraphEvidenceRows: []*cerebrov1.GraphEvidenceRow{
			newGraphEvidenceRow("identity_path", map[string]string{"label": "alice"}, newGraphEvidencePath(
				"urn:cerebro:writer:github_user:alice",
				"alice",
				"github.user",
				"acted_on",
				"urn:cerebro:writer:github_code_repository:repo-1",
				"repo-1",
				"github.code.repository",
				map[string]string{"at": "2026-05-07T18:09:42Z", "event_id": "event-1"},
			)),
		},
	}
	run := &cerebrov1.FindingEvaluationRun{Id: "run-1", RuntimeId: "runtime-okta"}

	evidence, err := service.buildFindingEvidence(context.Background(), finding, run)
	if err != nil {
		t.Fatalf("buildFindingEvidence() error = %v", err)
	}
	if got := evidence.GetAttributes()["actor"]; got != "alice@writer.com" {
		t.Fatalf("Evidence.Attributes[actor] = %q, want alice@writer.com", got)
	}
	if _, ok := evidence.GetAttributes()["empty"]; ok {
		t.Fatalf("Evidence.Attributes retained empty value: %#v", evidence.GetAttributes())
	}
	if !slices.Contains(evidence.GetGraphPathUrns(), "urn:cerebro:writer:github_user:alice") || !slices.Contains(evidence.GetGraphPathUrns(), "urn:cerebro:writer:github_code_repository:repo-1") {
		t.Fatalf("Evidence.GraphPathUrns = %#v, want both path endpoints", evidence.GetGraphPathUrns())
	}
	if got := evidence.GetGraphRows()[0].GetPaths()[0].GetObservedAt(); got != "2026-05-07T18:09:42Z" {
		t.Fatalf("Evidence.GraphRows[0].Paths[0].ObservedAt = %q, want edge timestamp", got)
	}
	if evidence.GetLastObservedAt() == nil || evidence.GetLastObservedAt().AsTime().IsZero() {
		t.Fatalf("Evidence.LastObservedAt missing")
	}
	if !slices.Contains(evidence.GetRunIds(), "run-1") {
		t.Fatalf("Evidence.RunIds = %#v, want run-1", evidence.GetRunIds())
	}
	if got := evidence.GetObservationCount(); got != 1 {
		t.Fatalf("Evidence.ObservationCount = %d, want 1", got)
	}
	if got := evidence.GetObservations()[0].GetGraphRows()[0].GetPaths()[0].GetObservedAt(); got != "2026-05-07T18:09:42Z" {
		t.Fatalf("Evidence.Observations[0].GraphRows[0].Paths[0].ObservedAt = %q, want edge timestamp", got)
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
	if !slices.Contains(ruleIDs, githubSecretScanningAlertCreatedRuleID) {
		t.Fatalf("ListRules().Rules missing %q: %#v", githubSecretScanningAlertCreatedRuleID, ruleIDs)
	}
	if !slices.Contains(ruleIDs, oktaPolicyRuleLifecycleTamperingRuleID) {
		t.Fatalf("ListRules().Rules missing %q: %#v", oktaPolicyRuleLifecycleTamperingRuleID, ruleIDs)
	}
}

func TestEvaluateSourceRuntimeFindingsSelectsRequestedRule(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newOktaPolicyRuleEvent("okta-policy-rule-inactive", "INACTIVE"),
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-policy-rule": {
					Id:       "writer-okta-policy-rule",
					SourceId: "okta",
					TenantId: "writer",
					Config:   map[string]string{"family": "policy_rule"},
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
		RuntimeID:  "writer-okta-policy-rule",
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
					Config:   map[string]string{"family": "audit"},
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

func TestEvaluateSourceRuntimeFindingsAllowsExplicitUnsupportedRuleWithOpenFindings(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "old-family-rule", Name: "Old Family Rule"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "old-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"finding-old": {
			ID:        "finding-old",
			TenantID:  "writer",
			RuntimeID: "writer-aws-public-endpoint",
			RuleID:    "old-family-rule",
			Status:    findingStatusOpen,
			EventIDs:  []string{"old-event"},
		},
	}}
	replayer := &stubReplayer{err: errors.New("unexpected replay")}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws-public-endpoint": {Id: "writer-aws-public-endpoint", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-aws-public-endpoint", RuleID: "old-family-rule"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result.Rule.GetId() != "old-family-rule" {
		t.Fatalf("Rule.Id = %q, want old-family-rule", result.Rule.GetId())
	}
	if got := store.findings["finding-old"].Status; got != findingStatusResolved {
		t.Fatalf("stale finding status = %q, want %q", got, findingStatusResolved)
	}
	if replayer.calls != 0 {
		t.Fatalf("Replay() calls = %d, want 0 for unsupported stale-only cleanup", replayer.calls)
	}
}

func TestEvaluateSourceRuntimeFindingsIgnoresStaleOnlyRulesForSingleSelection(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "live-rule", Name: "Live Rule"},
			supportedSourceIDs: map[string]struct{}{"aws": {}},
			triggerEventID:     "live-event",
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "old-family-rule", Name: "Old Family Rule"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "old-event",
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"finding-old": {
			ID:        "finding-old",
			TenantID:  "writer",
			RuntimeID: "writer-aws-public-endpoint",
			RuleID:    "old-family-rule",
			Status:    findingStatusOpen,
			EventIDs:  []string{"old-event"},
		},
	}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws-public-endpoint": {Id: "writer-aws-public-endpoint", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
		}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-aws-public-endpoint"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if got := result.Rule.GetId(); got != "live-rule" {
		t.Fatalf("Rule.Id = %q, want live-rule", got)
	}
	if got := store.findings["finding-old"].Status; got != findingStatusOpen {
		t.Fatalf("stale finding status = %q, want still open", got)
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
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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

func TestEvaluateSourceRuntimeRulesPreparesReplayBeforeReplaying(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-1",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{}
	store := &stubFindingStore{}
	prepareCalls := 0
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithReplayPreparer(func(context.Context) error {
		prepareCalls++
		return nil
	})

	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if prepareCalls != 1 {
		t.Fatalf("prepare calls = %d, want 1", prepareCalls)
	}
	if replayer.calls != 1 {
		t.Fatalf("Replay() calls = %d, want 1", replayer.calls)
	}
}

func TestEvaluateSourceRuntimeRulesDoesNotReplayWhenPrepareFails(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-1",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	prepareErr := errors.New("runtime index warming")
	replayer := &stubReplayer{err: errors.New("unexpected replay")}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithReplayPreparer(func(context.Context) error {
		return prepareErr
	})

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if !errors.Is(err, prepareErr) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want %v", err, prepareErr)
	}
	if replayer.calls != 0 {
		t.Fatalf("Replay() calls = %d, want 0", replayer.calls)
	}
	if got := len(store.runs); got != 1 {
		t.Fatalf("len(store.runs) = %d, want 1 failed run", got)
	}
	for _, run := range store.runs {
		if run.GetStatus() != "failed" {
			t.Fatalf("run status = %q, want failed", run.GetStatus())
		}
	}
}

func TestEvaluateSourceRuntimeCandidateRulesDoesNotWriteProductionFindings(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-2",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS")}}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithFindingCandidateStore(store)

	result, err := service.EvaluateSourceRuntimeCandidateRules(context.Background(), EvaluateCandidateRulesRequest{
		RuntimeID:  "writer-okta-audit",
		EventLimit: 1,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() error = %v", err)
	}
	if got := result.EventsEvaluated; got != 1 {
		t.Fatalf("EventsEvaluated = %d, want 1", got)
	}
	if got := store.upsertCount; got != 0 {
		t.Fatalf("production UpsertFinding calls = %d, want 0", got)
	}
	if got := len(store.evidence); got != 0 {
		t.Fatalf("production evidence rows = %d, want 0", got)
	}
	if got := store.updateStatusCallCount; got != 0 {
		t.Fatalf("production status updates = %d, want 0", got)
	}
	if got := store.candidateState.upsertCount; got != 1 {
		t.Fatalf("candidate upserts = %d, want 1", got)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("evaluations = %d, want 1", got)
	}
	evaluation := result.Evaluations[0]
	if got := evaluation.Run.Status; got != "completed" {
		t.Fatalf("candidate run status = %q, want completed", got)
	}
	if got := len(evaluation.Candidates); got != 1 {
		t.Fatalf("candidates = %d, want 1", got)
	}
	candidate := evaluation.Candidates[0]
	if got := candidate.Status; got != findingCandidateStatusCandidate {
		t.Fatalf("candidate status = %q, want %q", got, findingCandidateStatusCandidate)
	}
	if got := candidate.Evidence[0].GetClaimIds()[0]; got != "claim-1" {
		t.Fatalf("candidate evidence claim = %q, want claim-1", got)
	}
}

func TestEvaluateSourceRuntimeCandidateRulesReturnsErrorWhenAnyRuleFails(t *testing.T) {
	ruleBErr := errors.New("candidate rule-b exploded")
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-1",
		},
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                ruleBErr,
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")}},
		store,
		store,
		store,
		store,
		registry,
	).WithFindingCandidateStore(store)

	result, err := service.EvaluateSourceRuntimeCandidateRules(context.Background(), EvaluateCandidateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeCandidateRules() error = nil, want rule failure")
	}
	if !errors.Is(err, ruleBErr) {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() error = %v, want %v", err, ruleBErr)
	}
	if result == nil || len(result.Evaluations) != 2 {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() result = %#v, want both rule evaluations returned with error", result)
	}
	ruleARun, ok := candidateRunForRule(store.candidateState.runs, "rule-a")
	if !ok {
		t.Fatal("rule-a candidate run missing")
	}
	if got := ruleARun.Status; got != "completed" {
		t.Fatalf("rule-a candidate run status = %q, want completed", got)
	}
	ruleBRun, ok := candidateRunForRule(store.candidateState.runs, "rule-b")
	if !ok {
		t.Fatal("rule-b candidate run missing")
	}
	if got := ruleBRun.Status; got != "failed" {
		t.Fatalf("rule-b candidate run status = %q, want failed", got)
	}
	if got := ruleBRun.Error; !strings.Contains(got, "candidate rule-b exploded") {
		t.Fatalf("rule-b candidate run error = %q, want candidate rule-b exploded", got)
	}
}

func TestEvaluateSourceRuntimeCandidateRulesExpiresStaleCandidates(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "okta-audit-2",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	stale := &ports.FindingCandidateRecord{
		ID:          "candidate-stale",
		TenantID:    "writer",
		RuntimeID:   "writer-okta-audit",
		RuleID:      "rule-a",
		Fingerprint: "fingerprint-stale",
		Status:      findingCandidateStatusCandidate,
		Finding: &ports.FindingRecord{
			ID:        "finding-stale",
			TenantID:  "writer",
			RuntimeID: "writer-okta-audit",
			RuleID:    "rule-a",
			EventIDs:  []string{"okta-audit-1"},
		},
		LastRunID: "candidate-run-old",
		UpdatedAt: time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC),
	}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{
		newAuditEvent("okta-audit-1", "policy.rule.activate", "SUCCESS"),
		newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
	}}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{stale.ID: cloneFindingCandidate(stale)},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithFindingCandidateStore(store)

	result, err := service.EvaluateSourceRuntimeCandidateRules(context.Background(), EvaluateCandidateRulesRequest{
		RuntimeID:  "writer-okta-audit",
		EventLimit: 2,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() error = %v", err)
	}
	if got := len(result.Evaluations[0].Candidates); got != 1 {
		t.Fatalf("new candidates = %d, want 1", got)
	}
	if got := store.candidateState.candidates[stale.ID].Status; got != findingCandidateStatusExpired {
		t.Fatalf("stale candidate status = %q, want %q", got, findingCandidateStatusExpired)
	}
	if got := store.candidateState.expireCount; got != 1 {
		t.Fatalf("expire calls = %d, want 1", got)
	}
	if got := store.candidateState.expirationRequest.EvaluatedEventIDs; !slices.Equal(got, []string{"okta-audit-1", "okta-audit-2"}) {
		t.Fatalf("expiration evaluated events = %v, want both replayed events", got)
	}
}

func TestEvaluateSourceRuntimeCandidateRulesUsesRiskScoringConfig(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "candidate-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	config := DefaultRiskScoringConfig("tenant-a")
	config.Thresholds.Critical = 95
	config.Thresholds.High = 80
	config.Thresholds.Medium = 60
	event := &cerebrov1.EventEnvelope{
		Id:         "candidate-event",
		TenantId:   "tenant-a",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/audit/v1",
		Attributes: map[string]string{
			"event_type":                        "policy.rule.deactivate",
			"outcome_result":                    "SUCCESS",
			ports.EventAttributeSourceRuntimeID: "candidate-runtime",
		},
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			riskScoringConfigs: map[string]*ports.RiskScoringConfig{"tenant-a": &config},
		},
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "candidate-runtime",
				TenantID:      "tenant-a",
				SourceEventID: "candidate-event",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"candidate-runtime": {Id: "candidate-runtime", SourceId: "okta", TenantId: "tenant-a"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{event}},
		store,
		store,
		store,
		store,
		registry,
	).WithFindingCandidateStore(store)

	result, err := service.EvaluateSourceRuntimeCandidateRules(context.Background(), EvaluateCandidateRulesRequest{
		RuntimeID:  "candidate-runtime",
		EventLimit: 1,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() error = %v", err)
	}
	candidate := result.Evaluations[0].Candidates[0].Finding
	if !strings.HasPrefix(candidate.RiskModelVersion, riskScoringConfiguredModelPrefix) {
		t.Fatalf("RiskModelVersion = %q, want tenant config model version", candidate.RiskModelVersion)
	}
	if got := candidate.Attributes["risk_model_version"]; got != candidate.RiskModelVersion {
		t.Fatalf("risk_model_version attribute = %q, want %q", got, candidate.RiskModelVersion)
	}
}

func TestPromoteFindingCandidateWritesProductionFindingEvidenceAndAudit(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Title:           "Rule A",
		Severity:        "MEDIUM",
		Status:          findingStatusOpen,
		Summary:         "candidate summary",
		ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
		EventIDs:        []string{"okta-audit-2"},
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	evidence := &cerebrov1.FindingEvidence{
		Id:             "evidence-1",
		RuntimeId:      "writer-okta-audit",
		RuleId:         "rule-a",
		FindingId:      "finding-1",
		RunId:          "candidate-run-1",
		ClaimIds:       []string{"claim-1"},
		EventIds:       []string{"okta-audit-2"},
		GraphRootUrns:  []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
		CreatedAt:      timestamppb.New(now),
		LastObservedAt: timestamppb.New(now),
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		Evidence:         []*cerebrov1.FindingEvidence{evidence},
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings: map[string]*ports.FindingRecord{},
	}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(appendLog)

	result, err := service.PromoteFindingCandidate(context.Background(), PromoteCandidateRequest{
		CandidateID:           "candidate-1",
		PromotedBy:            "analyst@example.com",
		Rationale:             "Validated against source data.",
		ChangeTicket:          "SEC-123",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	})
	if err != nil {
		t.Fatalf("PromoteFindingCandidate() error = %v", err)
	}
	if result.Finding == nil {
		t.Fatal("PromoteFindingCandidate().Finding = nil")
	}
	if got := store.upsertCount; got == 0 {
		t.Fatalf("production UpsertFinding calls = %d, want > 0", got)
	}
	if got := len(store.evidence); got != 1 {
		t.Fatalf("production evidence rows = %d, want 1", got)
	}
	if got := result.Candidate.Status; got != findingCandidateStatusPromoted {
		t.Fatalf("candidate status = %q, want promoted", got)
	}
	if got := result.Candidate.PromotedFindingID; got != "finding-1" {
		t.Fatalf("promoted finding id = %q, want finding-1", got)
	}
	if result.DecisionID == "" {
		t.Fatal("DecisionID is empty")
	}
	if got := countWorkflowEventsByKind(appendLog.events, workflowevents.EventKindKnowledgeDecisionRecorded); got != 1 {
		t.Fatalf("promotion audit events = %d, want 1", got)
	}
	if got := countWorkflowEventsByKind(appendLog.events, securityevents.FindingRecorded); got != 1 {
		t.Fatalf("finding recorded events = %d, want 1", got)
	}
}

func countWorkflowEventsByKind(events []*cerebrov1.EventEnvelope, kind string) int {
	count := 0
	for _, event := range events {
		if event.GetKind() == kind {
			count++
		}
	}
	return count
}

func TestPromoteFindingCandidateDoesNotMarkPromotedBeforeDownstreamSuccess(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Title:           "Rule A",
		Severity:        "MEDIUM",
		Status:          findingStatusOpen,
		Summary:         "candidate summary",
		ResourceURNs:    []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		Evidence:         []*cerebrov1.FindingEvidence{{Id: "evidence-1", FindingId: "finding-1"}},
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings:       map[string]*ports.FindingRecord{},
		putEvidenceErr: errors.New("evidence write failed"),
	}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(appendLog)

	_, err := service.PromoteFindingCandidate(context.Background(), PromoteCandidateRequest{
		CandidateID:           "candidate-1",
		PromotedBy:            "analyst@example.com",
		Rationale:             "Validated against source data.",
		ChangeTicket:          "SEC-123",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	})
	if err == nil {
		t.Fatal("PromoteFindingCandidate() error = nil, want downstream failure")
	}
	if got := store.candidateState.markPromotedCount; got != 0 {
		t.Fatalf("MarkFindingCandidatePromoted calls = %d, want 0", got)
	}
	if got := store.candidateState.candidates["candidate-1"].Status; got != findingCandidateStatusCandidate {
		t.Fatalf("candidate status = %q, want candidate", got)
	}
	if got := len(appendLog.events); got != 0 {
		t.Fatalf("append log events = %d, want 0", got)
	}
}

func TestPromoteFindingCandidateAlreadyPromotedReturnsExistingFinding(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Title:           "Rule A",
		Severity:        "MEDIUM",
		Status:          findingStatusOpen,
		Summary:         "candidate summary",
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:                "candidate-1",
		TenantID:          "writer",
		RuntimeID:         "writer-okta-audit",
		RuleID:            "rule-a",
		Fingerprint:       "fingerprint-1",
		Status:            findingCandidateStatusPromoted,
		Finding:           cloneFinding(finding),
		LastRunID:         "candidate-run-1",
		ObservationCount:  1,
		FirstObservedAt:   now,
		LastObservedAt:    now,
		PromotedFindingID: "finding-1",
		DecisionID:        "decision-1",
		PromotedBy:        "analyst@example.com",
		PromotedAt:        now,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings: map[string]*ports.FindingRecord{
			finding.ID: cloneFinding(finding),
		},
	}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(appendLog)

	result, err := service.PromoteFindingCandidate(context.Background(), PromoteCandidateRequest{
		CandidateID:           "candidate-1",
		PromotedBy:            "analyst@example.com",
		Rationale:             "Validated against source data.",
		ChangeTicket:          "SEC-123",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	})
	if err != nil {
		t.Fatalf("PromoteFindingCandidate() error = %v", err)
	}
	if got := result.DecisionID; got != "decision-1" {
		t.Fatalf("DecisionID = %q, want decision-1", got)
	}
	if got := result.Finding.ID; got != "finding-1" {
		t.Fatalf("Finding.ID = %q, want finding-1", got)
	}
	if got := store.upsertCount; got != 0 {
		t.Fatalf("production UpsertFinding calls = %d, want 0", got)
	}
	if got := len(store.evidence); got != 0 {
		t.Fatalf("production evidence rows = %d, want 0", got)
	}
	if got := len(appendLog.events); got != 0 {
		t.Fatalf("append log events = %d, want 0", got)
	}
}

func TestExpiredFindingCandidateCannotBePromotedOrRejected(t *testing.T) {
	candidate := &ports.FindingCandidateRecord{
		ID:        "candidate-1",
		TenantID:  "writer",
		RuntimeID: "writer-okta-audit",
		RuleID:    "rule-a",
		Status:    findingCandidateStatusExpired,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
	}
	service := New(&stubRuntimeStore{}, nil, store, store, store, store).WithFindingCandidateStore(store)

	_, promoteErr := service.PromoteFindingCandidate(context.Background(), PromoteCandidateRequest{
		CandidateID:           candidate.ID,
		PromotedBy:            "analyst@example.com",
		Rationale:             "Reviewed.",
		ChangeTicket:          "SEC-1",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	})
	if !errors.Is(promoteErr, ErrInvalidRequest) {
		t.Fatalf("PromoteFindingCandidate() error = %v, want expired candidate rejection", promoteErr)
	}
	if got := store.upsertCount; got != 0 {
		t.Fatalf("production upserts after expired promote = %d, want 0", got)
	}
	if got := store.candidateState.markPromotedCount; got != 0 {
		t.Fatalf("mark promoted calls after expired promote = %d, want 0", got)
	}

	_, rejectErr := service.RejectFindingCandidate(context.Background(), RejectCandidateRequest{
		CandidateID: candidate.ID,
		RejectedBy:  "analyst@example.com",
		Rationale:   "No longer reproduced.",
	})
	if !errors.Is(rejectErr, ErrInvalidRequest) {
		t.Fatalf("RejectFindingCandidate() error = %v, want expired candidate rejection", rejectErr)
	}
	if got := store.candidateState.markRejectedCount; got != 0 {
		t.Fatalf("mark rejected calls after expired reject = %d, want 0", got)
	}
}

func TestFindingCandidateListTelemetryCountsExcludeExpiredCandidates(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	counts := findingCandidateListTelemetryCounts([]*ports.FindingCandidateRecord{
		{Status: findingCandidateStatusCandidate, LastObservedAt: now.Add(-8 * 24 * time.Hour)},
		{Status: findingCandidateStatusCandidate, LastObservedAt: now},
		{Status: findingCandidateStatusPromoted, LastObservedAt: now.Add(-8 * 24 * time.Hour)},
		{Status: findingCandidateStatusRejected, LastObservedAt: now.Add(-8 * 24 * time.Hour)},
		{Status: findingCandidateStatusExpired, LastObservedAt: now.Add(-8 * 24 * time.Hour)},
	}, now)

	if counts.candidateCount != 5 || counts.promotedCount != 1 || counts.rejectedCount != 1 || counts.expiredCount != 1 {
		t.Fatalf("counts = %#v, want one promoted, rejected, and expired candidate among five", counts)
	}
	if got := counts.openCount(); got != 2 {
		t.Fatalf("openCount = %d, want only live candidate statuses counted open", got)
	}
	if counts.staleCount != 1 {
		t.Fatalf("staleCount = %d, want expired/promoted/rejected candidates excluded", counts.staleCount)
	}
}

func TestPromoteFindingCandidateRecoversConcurrentCompletedPromotion(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Status:          findingStatusOpen,
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		Evidence:         []*cerebrov1.FindingEvidence{{Id: "evidence-1", FindingId: "finding-1"}},
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	request := PromoteCandidateRequest{
		CandidateID:           "candidate-1",
		PromotedBy:            "analyst@example.com",
		Rationale:             "Validated against source data.",
		ChangeTicket:          "SEC-123",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	}
	decisionID := candidatePromotionDecisionID(candidate, finding, request, now)
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings: map[string]*ports.FindingRecord{},
	}
	store.candidateState.beforeMarkPromote = func() {
		updated := cloneFindingCandidate(candidate)
		updated.Status = findingCandidateStatusPromoted
		updated.PromotedFindingID = finding.ID
		updated.DecisionID = decisionID
		updated.PromotedBy = "analyst@example.com"
		updated.PromotionRationale = "Validated against source data."
		updated.ChangeTicket = "SEC-123"
		updated.PromotedAt = now
		store.candidateState.candidates[updated.ID] = updated
		winningFinding := cloneFinding(finding)
		winningFinding.Attributes = map[string]string{"promoted_by": "winner@example.com"}
		store.findings[winningFinding.ID] = winningFinding
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(&recordingAppendLog{})

	result, err := service.PromoteFindingCandidate(context.Background(), request)
	if err != nil {
		t.Fatalf("PromoteFindingCandidate() error = %v", err)
	}
	if got := result.Candidate.Status; got != findingCandidateStatusPromoted {
		t.Fatalf("candidate status = %q, want promoted", got)
	}
	if got := result.DecisionID; got != decisionID {
		t.Fatalf("decision id = %q, want recovered %q", got, decisionID)
	}
	if got := result.Finding.Attributes["promoted_by"]; got != "winner@example.com" {
		t.Fatalf("recovered finding promoted_by = %q, want winning persisted finding", got)
	}
}

func TestRejectFindingCandidateRecordsAuditWithoutProductionWrites(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Title:           "Rule A",
		Severity:        "LOW",
		Status:          findingStatusOpen,
		Summary:         "candidate summary",
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		Evidence:         []*cerebrov1.FindingEvidence{{Id: "evidence-1", FindingId: "finding-1"}},
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings: map[string]*ports.FindingRecord{},
	}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(appendLog)

	result, err := service.RejectFindingCandidate(context.Background(), RejectCandidateRequest{
		CandidateID: "candidate-1",
		RejectedBy:  "analyst@example.com",
		Rationale:   "Matched expected break-glass test account.",
	})
	if err != nil {
		t.Fatalf("RejectFindingCandidate() error = %v", err)
	}
	if got := result.Candidate.Status; got != findingCandidateStatusRejected {
		t.Fatalf("candidate status = %q, want rejected", got)
	}
	if got := result.Candidate.RejectedBy; got != "analyst@example.com" {
		t.Fatalf("RejectedBy = %q, want analyst@example.com", got)
	}
	if result.DecisionID == "" {
		t.Fatal("DecisionID is empty")
	}
	if got := store.upsertCount; got != 0 {
		t.Fatalf("production UpsertFinding calls = %d, want 0", got)
	}
	if got := len(store.evidence); got != 0 {
		t.Fatalf("production evidence rows = %d, want 0", got)
	}
	if got := len(appendLog.events); got != 1 {
		t.Fatalf("append log events = %d, want 1", got)
	}
}

func TestRejectFindingCandidateDoesNotMarkRejectedBeforeAudit(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Title:           "Rule A",
		Severity:        "LOW",
		Status:          findingStatusOpen,
		Summary:         "candidate summary",
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
	}
	appendLog := &recordingAppendLog{err: errors.New("append failed")}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		nil,
		store,
		store,
		store,
		store,
		nil,
	).WithFindingCandidateStore(store).WithAppendLog(appendLog)

	_, err := service.RejectFindingCandidate(context.Background(), RejectCandidateRequest{
		CandidateID: "candidate-1",
		RejectedBy:  "analyst@example.com",
		Rationale:   "Matched expected break-glass test account.",
	})
	if err == nil {
		t.Fatal("RejectFindingCandidate() error = nil, want audit failure")
	}
	if got := store.candidateState.markRejectedCount; got != 0 {
		t.Fatalf("MarkFindingCandidateRejected calls = %d, want 0", got)
	}
	if got := store.candidateState.candidates["candidate-1"].Status; got != findingCandidateStatusCandidate {
		t.Fatalf("candidate status = %q, want candidate", got)
	}
}

func TestRejectFindingCandidateRecoversConcurrentCompletedRejection(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	finding := &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "rule-a",
		Status:          findingStatusOpen,
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	candidate := &ports.FindingCandidateRecord{
		ID:               "candidate-1",
		TenantID:         "writer",
		RuntimeID:        "writer-okta-audit",
		RuleID:           "rule-a",
		Fingerprint:      "fingerprint-1",
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFinding(finding),
		Evidence:         []*cerebrov1.FindingEvidence{{Id: "evidence-1", FindingId: "finding-1"}},
		LastRunID:        "candidate-run-1",
		ObservationCount: 1,
		FirstObservedAt:  now,
		LastObservedAt:   now,
	}
	request := RejectCandidateRequest{
		CandidateID: "candidate-1",
		RejectedBy:  "analyst@example.com",
		Rationale:   "Confirmed false positive.",
	}
	decisionID := candidateRejectionDecisionID(candidate, request, now)
	store := &stubFindingStore{
		candidateState: stubFindingCandidateState{
			candidates: map[string]*ports.FindingCandidateRecord{candidate.ID: cloneFindingCandidate(candidate)},
		},
		findings: map[string]*ports.FindingRecord{},
	}
	store.candidateState.beforeMarkReject = func() {
		updated := cloneFindingCandidate(candidate)
		updated.Status = findingCandidateStatusRejected
		updated.DecisionID = decisionID
		updated.RejectedBy = "analyst@example.com"
		updated.RejectionRationale = "Confirmed false positive."
		updated.RejectedAt = now
		store.candidateState.candidates[updated.ID] = updated
	}
	service := NewWithRegistry(nil, nil, store, store, store, store, nil).
		WithFindingCandidateStore(store).
		WithAppendLog(&recordingAppendLog{})

	result, err := service.RejectFindingCandidate(context.Background(), request)
	if err != nil {
		t.Fatalf("RejectFindingCandidate() error = %v", err)
	}
	if got := result.Candidate.Status; got != findingCandidateStatusRejected {
		t.Fatalf("candidate status = %q, want rejected", got)
	}
	if got := result.DecisionID; got != decisionID {
		t.Fatalf("decision id = %q, want recovered %q", got, decisionID)
	}
}

func TestEvaluateSourceRuntimeRulesIncludesUnsupportedRulesWithOpenFindings(t *testing.T) {
	registry, err := NewRegistry(&emittingRule{
		spec:               &cerebrov1.RuleSpec{Id: "old-family-rule", Name: "Old Family Rule"},
		supportedSourceIDs: map[string]struct{}{"okta": {}},
		triggerEventID:     "old-event",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"finding-old": {
			ID:        "finding-old",
			TenantID:  "writer",
			RuntimeID: "writer-aws-public-endpoint",
			RuleID:    "old-family-rule",
			Status:    findingStatusOpen,
			EventIDs:  []string{"old-event"},
		},
	}}
	replayer := &stubReplayer{err: errors.New("unexpected replay")}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws-public-endpoint": {Id: "writer-aws-public-endpoint", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-aws-public-endpoint"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if len(result.Evaluations) != 1 || result.Evaluations[0].Rule.GetId() != "old-family-rule" {
		t.Fatalf("evaluations = %#v, want only old-family-rule", result.Evaluations)
	}
	if got := store.findings["finding-old"].Status; got != findingStatusResolved {
		t.Fatalf("stale finding status = %q, want %q", got, findingStatusResolved)
	}
	if replayer.calls != 0 {
		t.Fatalf("Replay() calls = %d, want 0 for unsupported stale-only cleanup", replayer.calls)
	}
}

func TestEvaluateSourceRuntimeRulesSkipsBuiltinRulesForExplicitUnmatchedFamily(t *testing.T) {
	replayer := &stubReplayer{err: errors.New("unexpected replay")}
	store := &stubFindingStore{}
	service := New(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-grc-integration": {
				Id:       "writer-grc-integration",
				SourceId: "grc",
				TenantId: "writer",
				Config:   map[string]string{"family": "integration"},
			},
		}},
		replayer,
		store,
		store,
		store,
		store,
	)

	_, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-grc-integration"})
	if !errors.Is(err, ErrRuleUnavailable) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want %v", err, ErrRuleUnavailable)
	}
	if replayer.calls != 0 {
		t.Fatalf("Replay() calls = %d, want 0 when no builtin rule can emit for explicit runtime family", replayer.calls)
	}
}

func TestEvaluateSourceRuntimeRulesProbesStaleUnsupportedRulesOnce(t *testing.T) {
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "live-rule", Name: "Live Rule"},
			supportedSourceIDs: map[string]struct{}{"aws": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "old-rule-a", Name: "Old Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "old-rule-b", Name: "Old Rule B"},
			supportedSourceIDs: map[string]struct{}{"github": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws-public-endpoint": {Id: "writer-aws-public-endpoint", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
		}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-aws-public-endpoint"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if len(result.Evaluations) != 1 || result.Evaluations[0].Rule.GetId() != "live-rule" {
		t.Fatalf("evaluations = %#v, want only live-rule", result.Evaluations)
	}
	if got := len(store.listFindingsRequests); got != 1 {
		t.Fatalf("ListFindings calls = %d, want one stale unsupported probe", got)
	}
	request := store.listFindingsRequests[0]
	if request.RuleID != "" || request.RuntimeID != "writer-aws-public-endpoint" || request.Status != findingStatusOpen {
		t.Fatalf("stale probe request = %#v, want one runtime-wide open-finding query", request)
	}
}

func TestEvaluateSourceRuntimeRulesReturnsErrorWhenAnyRuleFails(t *testing.T) {
	ruleBErr := errors.New("rule-b exploded")
	registry, err := NewRegistry(
		&emittingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			triggerEventID:     "okta-audit-1",
		},
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                ruleBErr,
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")}},
		store,
		store,
		store,
		store,
		registry,
	)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want rule failure")
	}
	if !errors.Is(err, ruleBErr) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want %v", err, ruleBErr)
	}
	if result == nil || len(result.Evaluations) != 2 {
		t.Fatalf("EvaluateSourceRuntimeRules() result = %#v, want both rule evaluations returned with error", result)
	}
	ruleARun, ok := runForRule(store.runs, "rule-a")
	if !ok {
		t.Fatal("rule-a run missing")
	}
	if got := ruleARun.GetStatus(); got != "completed" {
		t.Fatalf("rule-a run status = %q, want completed", got)
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
}

func TestEvaluateSourceRuntimeRulesPreservesEarlierErrorWhenLaterFailureUpdateFails(t *testing.T) {
	ruleAErr := errors.New("rule-a exploded")
	ruleBErr := errors.New("rule-b exploded")
	runUpdateErr := errors.New("rule-b failure update failed")
	registry, err := NewRegistry(
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a", Name: "Rule A"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                ruleAErr,
		},
		&failingRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b", Name: "Rule B"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
			err:                ruleBErr,
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubFindingStore{
		failRunPutByCall: map[int]error{
			4: runUpdateErr,
		},
	}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")}},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want joined rule and run update errors")
	}
	for _, want := range []error{ruleAErr, ruleBErr, runUpdateErr} {
		if !errors.Is(err, want) {
			t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want %v", err, want)
		}
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

func TestEvaluateSourceRuntimeRulesMarksUnfinishedRunsFailedWhenStaleCleanupFails(t *testing.T) {
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
	store := &stubFindingStore{listFindingsErr: errors.New("stale cleanup unavailable")}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{{
			Id:         "okta-audit-1",
			TenantId:   "writer",
			SourceId:   "okta",
			Kind:       "okta.audit",
			OccurredAt: timestamppb.New(time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)),
		}}},
		store,
		store,
		store,
		store,
		registry,
	)

	_, err = service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "writer-okta-audit"})
	if err == nil {
		t.Fatal("EvaluateSourceRuntimeRules() error = nil, want stale cleanup error")
	}
	for _, ruleID := range []string{"rule-a", "rule-b"} {
		run, ok := runForRule(store.runs, ruleID)
		if !ok {
			t.Fatalf("%s run missing", ruleID)
		}
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("%s run status = %q, want failed", ruleID, got)
		}
		if got := run.GetError(); !strings.Contains(got, "stale cleanup unavailable") {
			t.Fatalf("%s run error = %q, want stale cleanup unavailable", ruleID, got)
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
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")}},
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
		&stubReplayer{events: []*cerebrov1.EventEnvelope{newAuditEvent("okta-audit-1", "policy.rule.deactivate", "SUCCESS")}},
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
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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
	first := findingEvidenceID("runtime", "finding", []string{"urn:root"}, []string{"event-1"})
	second := findingEvidenceID("runtime", "finding", []string{"urn:root"}, []string{"event-2"})
	if first == second {
		t.Fatalf("findingEvidenceID() = %q for distinct events, want unique IDs", first)
	}
	reordered := findingEvidenceID("runtime", "finding", []string{"urn:root"}, []string{"event-2", "event-1"})
	sorted := findingEvidenceID("runtime", "finding", []string{"urn:root"}, []string{"event-1", "event-2"})
	if reordered != sorted {
		t.Fatalf("findingEvidenceID() depends on event order: %q != %q", reordered, sorted)
	}
	firstRoot := findingEvidenceID("runtime", "finding", []string{"urn:root:1"}, []string{"event-1"})
	secondRoot := findingEvidenceID("runtime", "finding", []string{"urn:root:2"}, []string{"event-1"})
	if firstRoot == secondRoot {
		t.Fatalf("findingEvidenceID() = %q for distinct graph roots, want unique IDs", firstRoot)
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
				newAuditEvent("okta-audit-2", "policy.rule.deactivate", "SUCCESS"),
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
	activeRuleIDs := []string{
		githubSecretScanningAlertCreatedRuleID,
		githubCodeSecurityControlsDisabledRuleID,
	}
	retiredRuleIDs := []string{
		githubRepositoryCollaboratorAddedRuleID,
		githubOrganizationOwnerAddedRuleID,
		githubOrgAuthControlModifiedRuleID,
		githubOrgIPAllowListModifiedRuleID,
		githubAppIntegrationInstalledRuleID,
		githubPersonalAccessTokenCreatedRuleID,
		githubRepositoryRulesetModifiedRuleID,
		githubWebhookModifiedRuleID,
		githubPrivateRepositoryForkingEnabledRuleID,
	}
	ruleIDs := append([]string(nil), activeRuleIDs...)
	ruleIDs = append(ruleIDs, retiredRuleIDs...)
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-github-audit": {
					Id:       "writer-github-audit",
					SourceId: "github",
					TenantId: "writer",
					Config:   map[string]string{"family": "audit"},
				},
			},
		},
		&stubReplayer{
			events: []*cerebrov1.EventEnvelope{
				newGitHubAuditSignalEvent("github-audit-secret-scanning-disabled", map[string]string{"action": "repository_secret_scanning.disable", "repo": "writer/cerebro", "resource_type": "repository_secret_scanning"}),
				newGitHubAuditSignalEvent("github-audit-push-protection-disabled", map[string]string{"action": "org.secret_scanning_push_protection_disable", "resource_id": "writer", "resource_type": "org"}),
				newGitHubAuditSignalEvent("github-audit-branch-protection-disabled", map[string]string{"action": "protected_branch.destroy", "repo": "writer/cerebro", "resource_type": "protected_branch"}),
				newGitHubAuditSignalEvent("github-audit-repo-made-public", map[string]string{"action": "repo.access", "repo": "writer/cerebro", "previous_visibility": "private", "visibility": "public", "resource_type": "repo"}),
				newGitHubAuditSignalEvent("github-audit-secret-alert-created", map[string]string{"action": "secret_scanning_alert.create", "repo": "writer/cerebro", "number": "12", "resource_type": "secret_scanning_alert", "secret_scanning_alert.state": "open"}),
				newGitHubAuditSignalEvent("github-audit-runner-registered", map[string]string{"action": "repo.register_self_hosted_runner", "repo": "writer/cerebro", "resource_type": "repo", "runner_ephemeral": "false", "runner_id": "777", "runner_registered": "true"}),
				newGitHubAuditSignalEvent("github-audit-collaborator-added", map[string]string{"action": "repo.add_member", "repo": "writer/cerebro", "resource_type": "repo", "user": "octocat"}),
				newGitHubAuditSignalEvent("github-audit-owner-added", map[string]string{"action": "org.add_member", "resource_id": "writer", "resource_type": "org", "permission": "admin", "user": "octocat"}),
				newGitHubAuditSignalEvent("github-audit-code-security-disabled", map[string]string{"action": "dependabot_alerts.disable", "dependabot_alerts_enabled": "false", "repo": "writer/cerebro", "resource_type": "dependabot_alerts"}),
				newGitHubAuditSignalEvent("github-audit-org-auth-modified", map[string]string{"action": "org.disable_two_factor_requirement", "resource_id": "writer", "resource_type": "org", "two_factor_requirement_enabled": "false"}),
				newGitHubAuditSignalEvent("github-audit-ip-allow-list-disabled", map[string]string{"action": "ip_allow_list.disable", "ip_allow_list_enabled": "false", "resource_id": "writer", "resource_type": "ip_allow_list"}),
				newGitHubAuditSignalEvent("github-audit-app-installed", map[string]string{"action": "integration_installation.create", "github_app_id": "123456", "name": "ci-deployer", "resource_id": "writer", "resource_type": "integration_installation"}),
				newGitHubAuditSignalEvent("github-audit-pat-created", map[string]string{"action": "personal_access_token.access_granted", "operation_type": "create", "resource_id": "octocat", "resource_type": "personal_access_token", "token_id": "555", "user": "octocat", "user_id": "12345"}),
				newGitHubAuditSignalEvent("github-audit-branch-policy-override", map[string]string{"action": "protected_branch.policy_override", "branch": "main", "repo": "writer/cerebro", "resource_type": "protected_branch"}),
				newGitHubAuditSignalEvent("github-audit-ruleset-modified", map[string]string{"action": "repository_ruleset.destroy", "repo": "writer/cerebro", "resource_type": "repository_ruleset", "ruleset_id": "42", "ruleset_name": "main protections"}),
				newGitHubAuditSignalEvent("github-audit-repo-destroyed", map[string]string{"action": "repo.destroy", "repo": "writer/cerebro", "resource_type": "repo"}),
				newGitHubAuditSignalEvent("github-audit-hook-created", map[string]string{"action": "hook.create", "hook_id": "99", "repo": "writer/cerebro", "resource_type": "hook"}),
				newGitHubAuditSignalEvent("github-audit-private-forking-enabled", map[string]string{"action": "private_repository_forking.enable", "private_repository_forking_enabled": "true", "resource_id": "writer", "resource_type": "org"}),
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
	findingCountByRule := map[string]int{}
	for _, evaluation := range result.Evaluations {
		ruleID := evaluation.Rule.GetId()
		findingCountByRule[ruleID] += len(evaluation.Findings)
		if len(evaluation.Findings) >= 1 {
			findingsByRule[ruleID] = evaluation.Findings[0]
		}
	}
	for _, ruleID := range activeRuleIDs {
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
	for _, ruleID := range retiredRuleIDs {
		if got := findingCountByRule[ruleID]; got != 0 {
			t.Fatalf("EvaluateSourceRuntimeRules() emitted %d findings for retired rule %q, want 0", got, ruleID)
		}
	}
	if got := findingsByRule[githubCodeSecurityControlsDisabledRuleID].Severity; got != "CRITICAL" {
		t.Fatalf("code security controls severity = %q, want CRITICAL", got)
	}
	if got := findingsByRule[githubSecretScanningAlertCreatedRuleID].Severity; got != "MEDIUM" {
		t.Fatalf("secret scanning alert severity = %q, want MEDIUM", got)
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

func TestListFindingsNormalizesUserFacingLimits(t *testing.T) {
	for _, tt := range []struct {
		name  string
		limit uint32
		want  uint32
	}{
		{name: "zero defaults", limit: 0, want: defaultListLimit},
		{name: "within limit preserved", limit: 25, want: 25},
		{name: "above max clamped", limit: maxListLimit + 1, want: maxListLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &stubFindingStore{}
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
			if _, err := service.ListFindings(context.Background(), ListRequest{RuntimeID: "writer-okta-audit", Limit: tt.limit}); err != nil {
				t.Fatalf("ListFindings() error = %v", err)
			}
			if got := store.request.Limit; got != tt.want {
				t.Fatalf("ListFindings().Limit = %d, want %d", got, tt.want)
			}
		})
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

func TestResolveFindingWithOptionsAppliesStatusPreconditions(t *testing.T) {
	observedAt := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				Status:         "open",
				LastObservedAt: observedAt,
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	finding, err := service.ResolveFindingWithOptions(context.Background(), "finding-1", "panopticon verified false positive", FindingStatusUpdateOptions{
		ExpectedStatus:     "open",
		LastObservedBefore: observedAt.Add(time.Minute),
		Source:             "panopticon",
	})
	if err != nil {
		t.Fatalf("ResolveFindingWithOptions() error = %v", err)
	}
	if got := finding.Status; got != "resolved" {
		t.Fatalf("ResolveFindingWithOptions().Status = %q, want resolved", got)
	}
	if got := len(store.updateStatusCalls); got != 1 {
		t.Fatalf("update status calls = %d, want 1", got)
	}
	call := store.updateStatusCalls[0]
	if got := call.ExpectedStatus; got != "open" {
		t.Fatalf("ExpectedStatus = %q, want open", got)
	}
	if !call.LastObservedBefore.Equal(observedAt.Add(time.Minute)) {
		t.Fatalf("LastObservedBefore = %v, want %v", call.LastObservedBefore, observedAt.Add(time.Minute))
	}
}

func TestResolveFindingWithOptionsReturnsPreconditionFailure(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:     "finding-1",
				Status: "resolved",
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	_, err := service.ResolveFindingWithOptions(context.Background(), "finding-1", "stale agent decision", FindingStatusUpdateOptions{
		ExpectedStatus: "open",
	})
	if !errors.Is(err, ports.ErrFindingStatusPreconditionFailed) {
		t.Fatalf("ResolveFindingWithOptions() error = %v, want precondition failure", err)
	}
}

func TestResolveFindingRecomputesPersistedRisk(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:       "finding-1",
				Status:   "open",
				Severity: "LOW",
				FindingRisk: ports.FindingRisk{
					RiskScore:        99,
					LikelihoodScore:  99,
					ImpactScore:      99,
					ConfidenceScore:  99,
					LikelihoodLevel:  "critical",
					ImpactLevel:      "critical",
					RiskReasons:      []string{"active", "stale_reason"},
					RiskModelVersion: defaultFindingRiskModelVersion,
				},
				Attributes:        map[string]string{"risk_score": "99", "risk_reasons": "active,stale_reason"},
				FirstObservedAt:   time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
				LastObservedAt:    time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
				ResourceURNs:      []string{"urn:cerebro:test:resource:one"},
				EventIDs:          []string{"event-1"},
				ObservedPolicyIDs: []string{"policy-1"},
			},
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
	if finding.RiskScore == 99 || finding.LikelihoodScore == 99 || finding.ImpactScore == 99 {
		t.Fatalf("ResolveFinding() kept stale risk = score %d likelihood %d impact %d", finding.RiskScore, finding.LikelihoodScore, finding.ImpactScore)
	}
	if slices.Contains(finding.RiskReasons, "active") || slices.Contains(finding.RiskReasons, "stale_reason") {
		t.Fatalf("ResolveFinding().RiskReasons = %#v, want stale reasons removed", finding.RiskReasons)
	}
	stored := store.findings["finding-1"]
	if stored == nil || stored.RiskScore != finding.RiskScore {
		t.Fatalf("stored risk score = %#v, want recomputed score %d", stored, finding.RiskScore)
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
	finding, err := service.ResolveFinding(context.Background(), "finding-1", workflowevents.FindingStatusReasonNoLongerEmitted)
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
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingStatusChanged {
		t.Fatalf("canonical status event kind = %q, want %q", got, securityevents.FindingStatusChanged)
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

func TestSetFindingDueDateRecomputesPersistedRisk(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:       "finding-1",
				Status:   "open",
				Severity: "MEDIUM",
				FindingRisk: ports.FindingRisk{
					RiskScore:        1,
					LikelihoodScore:  1,
					ImpactScore:      1,
					RiskReasons:      []string{"stale_reason"},
					RiskModelVersion: defaultFindingRiskModelVersion,
				},
				Attributes: map[string]string{"risk_score": "1", "risk_reasons": "stale_reason"},
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	dueAt := time.Now().UTC().Add(-time.Hour)
	finding, err := service.SetFindingDueDate(context.Background(), "finding-1", dueAt)
	if err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if !slices.Contains(finding.RiskReasons, "overdue") {
		t.Fatalf("SetFindingDueDate().RiskReasons = %#v, want overdue", finding.RiskReasons)
	}
	if slices.Contains(finding.RiskReasons, "stale_reason") {
		t.Fatalf("SetFindingDueDate().RiskReasons = %#v, want stale reason removed", finding.RiskReasons)
	}
	if finding.RiskScore <= 1 {
		t.Fatalf("SetFindingDueDate().RiskScore = %d, want recomputed score > 1", finding.RiskScore)
	}
}

func TestPersistFindingRiskUsesRiskOnlyUpdate(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:         "finding-1",
				Title:      "Current title",
				Summary:    "Current summary",
				Status:     "open",
				Severity:   "LOW",
				Attributes: map[string]string{"owner": "secops"},
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	staleSnapshot := cloneFinding(store.findings["finding-1"])
	staleSnapshot.Title = "Stale title"
	staleSnapshot.Summary = "Stale summary"
	stored, err := service.persistFindingRisk(context.Background(), staleSnapshot, time.Now().UTC())
	if err != nil {
		t.Fatalf("persistFindingRisk() error = %v", err)
	}
	if store.upsertCount != 0 {
		t.Fatalf("persistFindingRisk() called UpsertFinding %d times, want risk-only update", store.upsertCount)
	}
	if got := stored.Summary; got != "Current summary" {
		t.Fatalf("persistFindingRisk().Summary = %q, want current summary preserved", got)
	}
	if got := stored.Attributes["owner"]; got != "secops" {
		t.Fatalf("persistFindingRisk().Attributes[owner] = %q, want preserved", got)
	}
	if stored.RiskScore == 0 {
		t.Fatal("persistFindingRisk().RiskScore = 0, want refreshed risk")
	}
	if got, want := stored.Attributes[FindingEffectiveSeverityAttribute], EffectiveSeverityFromRiskScore(stored.RiskScore); got != want {
		t.Fatalf("persistFindingRisk().Attributes[%s] = %q, want %q", FindingEffectiveSeverityAttribute, got, want)
	}
}

func TestBackfillFindingRiskProjectsUpdatedRiskRows(t *testing.T) {
	openFinding := &ports.FindingRecord{
		ID:        "finding-1",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-audit",
		RuleID:    "rule-1",
		Title:     "Backfilled risk finding",
		Status:    "open",
		Severity:  "HIGH",
		FindingRisk: ports.FindingRisk{
			RiskScore:        83,
			LikelihoodScore:  80,
			ImpactScore:      86,
			ConfidenceScore:  70,
			LikelihoodLevel:  "high",
			ImpactLevel:      "critical",
			RiskReasons:      []string{"external_exposure"},
			RiskModelVersion: defaultFindingRiskModelVersion,
		},
		LastObservedAt: time.Now().UTC().Add(-7 * 24 * time.Hour),
	}
	closedFinding := cloneFinding(openFinding)
	closedFinding.ID = "finding-closed"
	closedFinding.Status = findingStatusResolved
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			openFinding.ID:   cloneFinding(openFinding),
			closedFinding.ID: cloneFinding(closedFinding),
		},
		backfillState: stubFindingBackfillState{
			results: []*ports.FindingRecord{openFinding, closedFinding},
		},
	}
	graphStore := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(appendLog)
	if err := service.BackfillFindingRisk(context.Background()); err != nil {
		t.Fatalf("BackfillFindingRisk() error = %v", err)
	}
	if !store.backfillState.includeUnprojected {
		t.Fatal("BackfillFindingRisk() did not request unprojected rows with graph configured")
	}
	graphFinding := graphStore.entities["urn:cerebro:tenant-a:finding:finding-1"]
	if graphFinding == nil {
		t.Fatal("BackfillFindingRisk() did not project finding anchor")
	}
	if got := graphFinding.Attributes["risk_score"]; got != "83" {
		t.Fatalf("projected risk_score = %q, want 83", got)
	}
	if got := graphFinding.Attributes[FindingEffectiveSeverityAttribute]; got != "HIGH" {
		t.Fatalf("projected effective_severity = %q, want HIGH", got)
	}
	if closed := graphStore.entities["urn:cerebro:tenant-a:finding:finding-closed"]; closed == nil || closed.Attributes["risk_score"] != "83" {
		t.Fatalf("closed projected finding = %#v, want risk_score 83", closed)
	}
	if got := len(appendLog.events); got != 2 {
		t.Fatalf("len(appended events) = %d, want 2", got)
	}
	if eventTime := appendLog.events[0].GetOccurredAt().AsTime(); time.Since(eventTime) > time.Minute {
		t.Fatalf("backfill event occurred_at = %s, want startup time", eventTime.Format(time.RFC3339Nano))
	}
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingRecorded {
		t.Fatalf("canonical open finding event kind = %q, want %q", got, securityevents.FindingRecorded)
	}
	if got := appendLog.events[1].GetKind(); got != securityevents.FindingStatusChanged {
		t.Fatalf("canonical closed finding event kind = %q, want %q", got, securityevents.FindingStatusChanged)
	}
	if got := store.findings["finding-1"].Attributes[FindingRiskGraphProjectedModelVersionAttribute]; got != defaultFindingRiskModelVersion {
		t.Fatalf("projection marker = %q, want %q", got, defaultFindingRiskModelVersion)
	}
	if got := store.markRiskProjectedCount; got != 2 {
		t.Fatalf("MarkFindingRiskProjected calls = %d, want 2", got)
	}
	if got := store.updateRiskCount; got != 0 {
		t.Fatalf("UpdateFindingRisk calls = %d, want 0 when guarded marker is available", got)
	}
}

func TestBackfillFindingRiskProjectsCurrentRiskAfterConcurrentUpdate(t *testing.T) {
	finding := &ports.FindingRecord{
		ID:        "finding-1",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-audit",
		RuleID:    "rule-1",
		Title:     "Backfilled risk finding",
		Status:    "open",
		Severity:  "HIGH",
		FindingRisk: ports.FindingRisk{
			RiskScore:        83,
			RiskModelVersion: defaultFindingRiskModelVersion,
		},
	}
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			finding.ID: cloneFinding(finding),
		},
		backfillState: stubFindingBackfillState{
			results: []*ports.FindingRecord{finding},
		},
	}
	store.findings[finding.ID].RiskScore = 95
	graphStore := &stubGraphStore{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(&recordingAppendLog{})
	if err := service.BackfillFindingRisk(context.Background()); err != nil {
		t.Fatalf("BackfillFindingRisk() error = %v", err)
	}
	graphFinding := graphStore.entities["urn:cerebro:tenant-a:finding:finding-1"]
	if graphFinding == nil {
		t.Fatal("BackfillFindingRisk() did not project finding anchor")
	}
	if got := graphFinding.Attributes["risk_score"]; got != "95" {
		t.Fatalf("projected risk_score = %q, want current risk 95", got)
	}
	if got := store.findings["finding-1"].Attributes[FindingRiskGraphProjectedModelVersionAttribute]; got != defaultFindingRiskModelVersion {
		t.Fatalf("projection marker = %q, want %q", got, defaultFindingRiskModelVersion)
	}
}

func TestBackfillFindingRiskDoesNotMarkProjectedWithoutGraph(t *testing.T) {
	finding := &ports.FindingRecord{
		ID:        "finding-1",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-audit",
		RuleID:    "rule-1",
		Title:     "Backfilled risk finding",
		Status:    "open",
		Severity:  "HIGH",
		FindingRisk: ports.FindingRisk{
			RiskScore:        83,
			RiskModelVersion: defaultFindingRiskModelVersion,
		},
	}
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{finding.ID: cloneFinding(finding)},
		backfillState: stubFindingBackfillState{
			results: []*ports.FindingRecord{finding},
		},
	}
	service := New(nil, nil, store, store, store, store)
	if err := service.BackfillFindingRisk(context.Background()); err != nil {
		t.Fatalf("BackfillFindingRisk() error = %v", err)
	}
	if store.backfillState.includeUnprojected {
		t.Fatal("BackfillFindingRisk() requested unprojected rows without graph configured")
	}
	if got := store.findings["finding-1"].Attributes[FindingRiskGraphProjectedModelVersionAttribute]; got != "" {
		t.Fatalf("projection marker = %q, want empty without graph", got)
	}
}

func TestProjectFindingAnchorMarksRiskProjected(t *testing.T) {
	finding := &ports.FindingRecord{
		ID:        "finding-1",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-audit",
		RuleID:    "rule-1",
		Title:     "Projected risk finding",
		Status:    "open",
		Severity:  "HIGH",
		FindingRisk: ports.FindingRisk{
			RiskScore:        74,
			RiskModelVersion: defaultFindingRiskModelVersion,
		},
		LastObservedAt: time.Now().UTC(),
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{finding.ID: cloneFinding(finding)}}
	service := New(nil, nil, store, store, store, store).WithGraphStore(&stubGraphStore{})
	if err := service.projectFindingAnchor(context.Background(), finding); err != nil {
		t.Fatalf("projectFindingAnchor() error = %v", err)
	}
	if got := store.findings["finding-1"].Attributes[FindingRiskGraphProjectedModelVersionAttribute]; got != defaultFindingRiskModelVersion {
		t.Fatalf("projection marker = %q, want %q", got, defaultFindingRiskModelVersion)
	}
}

func TestSetFindingDueDateProjectsUpdatedRisk(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:        "finding-1",
				TenantID:  "tenant-a",
				RuntimeID: "runtime-audit",
				RuleID:    "rule-1",
				Title:     "Due date finding",
				Status:    "open",
				Severity:  "MEDIUM",
				FindingRisk: ports.FindingRisk{
					RiskScore:        1,
					RiskReasons:      []string{"stale_reason"},
					RiskModelVersion: defaultFindingRiskModelVersion,
				},
				Attributes:     map[string]string{"risk_score": "1", "risk_reasons": "stale_reason"},
				LastObservedAt: time.Now().UTC().Add(-14 * 24 * time.Hour),
			},
		},
	}
	graphStore := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(appendLog)
	finding, err := service.SetFindingDueDate(context.Background(), "finding-1", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if len(appendLog.events) == 0 {
		t.Fatal("SetFindingDueDate() appended no workflow event, want finding anchor refresh")
	}
	graphFinding := graphStore.entities["urn:cerebro:tenant-a:finding:finding-1"]
	if graphFinding == nil {
		t.Fatal("SetFindingDueDate() did not project finding anchor")
	}
	if got := graphFinding.Attributes["risk_score"]; got != strconv.Itoa(finding.RiskScore) {
		t.Fatalf("projected risk_score = %q, want %d", got, finding.RiskScore)
	}
	if !strings.Contains(graphFinding.Attributes["risk_reasons"], "overdue") {
		t.Fatalf("projected risk_reasons = %q, want overdue", graphFinding.Attributes["risk_reasons"])
	}
	if eventTime := appendLog.events[0].GetOccurredAt().AsTime(); time.Since(eventTime) > time.Minute {
		t.Fatalf("revision event occurred_at = %s, want refresh time", eventTime.Format(time.RFC3339Nano))
	}
	firstEventID := appendLog.events[0].GetId()
	_, err = service.SetFindingDueDate(context.Background(), "finding-1", time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("SetFindingDueDate(second) error = %v", err)
	}
	if got := len(appendLog.events); got != 2 {
		t.Fatalf("len(appended events) = %d, want 2", got)
	}
	if secondEventID := appendLog.events[1].GetId(); secondEventID == firstEventID {
		t.Fatalf("SetFindingDueDate() reused finding_record event id %q, want non-deduplicated refresh event", secondEventID)
	}
}

func TestFindingWorkflowSnapshotDoesNotMergeFreshReasonsWithStoredRisk(t *testing.T) {
	dueAt := time.Now().UTC().Add(-time.Hour)
	snapshot := findingWorkflowSnapshot(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		Severity: "LOW",
		FindingWorkflow: ports.FindingWorkflow{
			DueAt: dueAt,
		},
		FindingRisk: ports.FindingRisk{
			RiskScore:        20,
			LikelihoodScore:  20,
			ImpactScore:      20,
			ConfidenceScore:  70,
			LikelihoodLevel:  "low",
			ImpactLevel:      "low",
			RiskReasons:      []string{"stored_reason"},
			RiskModelVersion: defaultFindingRiskModelVersion,
		},
	}, "tenant-a", "runtime-audit")
	if snapshot.RiskScore != 20 || snapshot.ImpactScore != 20 {
		t.Fatalf("findingWorkflowSnapshot() risk = score %d impact %d, want stored values", snapshot.RiskScore, snapshot.ImpactScore)
	}
	if slices.Contains(snapshot.RiskReasons, "overdue") {
		t.Fatalf("findingWorkflowSnapshot().RiskReasons = %#v, want no mixed fresh overdue reason", snapshot.RiskReasons)
	}
	if !slices.Contains(snapshot.RiskReasons, "stored_reason") {
		t.Fatalf("findingWorkflowSnapshot().RiskReasons = %#v, want stored_reason", snapshot.RiskReasons)
	}
}

func TestFindingWorkflowSnapshotBoundsEventIDsAndPreservesResourceURNs(t *testing.T) {
	resourceURNs := make([]string, 0, maxFindingSnapshotEventIDs+10)
	for i := 0; i < maxFindingSnapshotEventIDs+10; i++ {
		resourceURNs = append(resourceURNs, "urn:cerebro:tenant-a:asset:"+strconv.Itoa(i))
	}
	primaryResourceURN := "urn:cerebro:tenant-a:asset:primary"
	resourceURNs = append(resourceURNs, primaryResourceURN)
	eventIDs := make([]string, 0, maxFindingSnapshotEventIDs+10)
	for i := 0; i < maxFindingSnapshotEventIDs+10; i++ {
		eventIDs = append(eventIDs, "event-"+strconv.Itoa(i))
	}

	snapshot := findingWorkflowSnapshot(&ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-audit",
		RuleID:       "graph-rule",
		Status:       "open",
		Severity:     "HIGH",
		ResourceURNs: resourceURNs,
		EventIDs:     eventIDs,
		Attributes: map[string]string{
			"primary_resource_urn": primaryResourceURN,
		},
	}, "tenant-a", "runtime-audit")

	if got := len(snapshot.ResourceURNs); got != len(resourceURNs) {
		t.Fatalf("len(ResourceURNs) = %d, want all %d resources preserved for graph links", got, len(resourceURNs))
	}
	if got := len(snapshot.EventIDs); got != maxFindingSnapshotEventIDs {
		t.Fatalf("len(EventIDs) = %d, want %d", got, maxFindingSnapshotEventIDs)
	}
	if snapshot.ResourceCount != len(resourceURNs) {
		t.Fatalf("ResourceCount = %d, want full count %d", snapshot.ResourceCount, len(resourceURNs))
	}
	if snapshot.EventCount != len(eventIDs) {
		t.Fatalf("EventCount = %d, want full count %d", snapshot.EventCount, len(eventIDs))
	}
	for _, resourceURN := range resourceURNs {
		if !slices.Contains(snapshot.ResourceURNs, resourceURN) {
			t.Fatalf("snapshot ResourceURNs missing %q", resourceURN)
		}
	}
	event, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    snapshot,
		RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	if got := len(event.GetPayload()); got > 128<<10 {
		t.Fatalf("finding recorded payload = %d bytes, want below 128KiB", got)
	}
}

func TestUpsertFindingWithRiskRecomputesAfterWorkflowPreservation(t *testing.T) {
	dueAt := time.Now().UTC().Add(-time.Hour)
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:          "finding-1",
				Fingerprint: "fingerprint-1",
				TenantID:    "tenant-a",
				RuntimeID:   "runtime-audit",
				RuleID:      "rule-1",
				Title:       "Existing triaged finding",
				Severity:    "LOW",
				Status:      "resolved",
				Summary:     "resolved finding",
				FindingWorkflow: ports.FindingWorkflow{
					DueAt:           dueAt,
					StatusReason:    "triaged",
					StatusUpdatedAt: dueAt,
				},
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	emitted := &ports.FindingRecord{
		ID:          "finding-1",
		Fingerprint: "fingerprint-1",
		TenantID:    "tenant-a",
		RuntimeID:   "runtime-audit",
		RuleID:      "rule-1",
		Title:       "Existing triaged finding",
		Severity:    "LOW",
		Status:      "open",
		Summary:     "reemitted finding",
		Attributes:  map[string]string{},
	}
	stored, err := service.upsertFindingWithRisk(context.Background(), emitted, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("upsertFindingWithRisk() error = %v", err)
	}
	if got := stored.Status; got != "resolved" {
		t.Fatalf("upsertFindingWithRisk().Status = %q, want preserved resolved", got)
	}
	if !slices.Contains(stored.RiskReasons, "overdue") {
		t.Fatalf("upsertFindingWithRisk().RiskReasons = %#v, want overdue from preserved due date", stored.RiskReasons)
	}
	if slices.Contains(stored.RiskReasons, "active") {
		t.Fatalf("upsertFindingWithRisk().RiskReasons = %#v, want no active reason after preserved resolution", stored.RiskReasons)
	}
}

func TestUpsertFindingWithRiskPreservesGraphEvidenceDuringRecompute(t *testing.T) {
	store := &stubFindingStore{dropReturnedGraphEvidence: true}
	service := New(nil, nil, store, store, store, store)
	emitted := &ports.FindingRecord{
		ID:          "finding-graph",
		Fingerprint: "fingerprint-graph",
		TenantID:    "tenant-a",
		RuntimeID:   "runtime-graph",
		RuleID:      "rule-graph",
		Title:       "Graph-backed finding",
		Severity:    "MEDIUM",
		Status:      "open",
		Summary:     "graph finding",
		Attributes:  map[string]string{},
		GraphEvidenceRows: []*cerebrov1.GraphEvidenceRow{
			newGraphEvidenceRow("identity_path", map[string]string{"label": "path"}),
		},
	}
	stored, err := service.upsertFindingWithRisk(context.Background(), emitted, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("upsertFindingWithRisk() error = %v", err)
	}
	if !slices.Contains(stored.RiskReasons, "graph_evidence") {
		t.Fatalf("upsertFindingWithRisk().RiskReasons = %#v, want graph_evidence", stored.RiskReasons)
	}
}

func TestUpsertFindingWithRiskMergesVulnViewMatchedLocationEvidence(t *testing.T) {
	store := &stubFindingStore{}
	service := New(nil, nil, store, store, store, store)
	now := time.Now().UTC()
	first := &ports.FindingRecord{
		ID:           "vulnview-finding",
		Fingerprint:  "vulnview-finding",
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-vulnview",
		RuleID:       vulnViewActionableExternalFindingRuleID,
		Title:        "VulnView Actionable External Finding",
		Severity:     "HIGH",
		Status:       "open",
		Summary:      "first finding",
		ResourceURNs: []string{"urn:cerebro:tenant-a:external_asset:app.writer.com"},
		EventIDs:     []string{"event-1"},
		Attributes: map[string]string{
			"matched_at": "https://app.writer.com/login",
		},
		FirstObservedAt: now,
		LastObservedAt:  now,
	}
	if _, err := service.upsertFindingWithRisk(context.Background(), first, nil, now); err != nil {
		t.Fatalf("upsertFindingWithRisk(first) error = %v", err)
	}
	second := cloneFinding(first)
	second.EventIDs = []string{"event-2"}
	second.Attributes["matched_at"] = "https://app.writer.com/admin"
	second.LastObservedAt = now.Add(time.Minute)
	stored, err := service.upsertFindingWithRisk(context.Background(), second, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("upsertFindingWithRisk(second) error = %v", err)
	}
	if !containsTrimmed(stored.EventIDs, "event-1") || !containsTrimmed(stored.EventIDs, "event-2") {
		t.Fatalf("EventIDs = %#v, want both event IDs", stored.EventIDs)
	}
	var locations []string
	if err := json.Unmarshal([]byte(stored.Attributes["matched_locations_json"]), &locations); err != nil {
		t.Fatalf("matched_locations_json = %q is invalid JSON array: %v", stored.Attributes["matched_locations_json"], err)
	}
	for _, location := range []string{"https://app.writer.com/login", "https://app.writer.com/admin"} {
		if !slices.Contains(locations, location) {
			t.Fatalf("matched_locations_json = %#v, missing %q", locations, location)
		}
	}
}

func TestMergeVulnViewActionableEvidenceUsesActiveGeneratedRow(t *testing.T) {
	now := time.Now().UTC()
	baseID := "vulnview-finding"
	activeID := baseID + "#g2"
	assetURN := "urn:cerebro:tenant-a:external_asset:app.writer.com"
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			baseID: {
				ID:           baseID,
				Fingerprint:  baseID,
				TenantID:     "tenant-a",
				RuntimeID:    "runtime-vulnview",
				RuleID:       vulnViewActionableExternalFindingRuleID,
				PolicyID:     "template-1",
				Status:       findingStatusResolved,
				ResourceURNs: []string{assetURN},
				EventIDs:     []string{"event-stale"},
				Attributes: map[string]string{
					"matched_locations_json": `["https://app.writer.com/stale"]`,
				},
				FindingTombstone: ports.FindingTombstone{Tombstoned: true},
				LastObservedAt:   now.Add(-2 * time.Hour),
			},
			activeID: {
				ID:           activeID,
				Fingerprint:  baseID,
				TenantID:     "tenant-a",
				RuntimeID:    "runtime-vulnview",
				RuleID:       vulnViewActionableExternalFindingRuleID,
				PolicyID:     "template-1",
				Status:       findingStatusOpen,
				ResourceURNs: []string{assetURN},
				EventIDs:     []string{"event-live"},
				Attributes: map[string]string{
					"matched_locations_json": `["https://app.writer.com/live"]`,
				},
				LastObservedAt: now,
			},
		},
	}
	service := New(nil, nil, store, store, store, store)
	incoming := &ports.FindingRecord{
		ID:           baseID,
		Fingerprint:  baseID,
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-vulnview",
		RuleID:       vulnViewActionableExternalFindingRuleID,
		PolicyID:     "template-1",
		Status:       findingStatusOpen,
		ResourceURNs: []string{assetURN},
		EventIDs:     []string{"event-new"},
		Attributes: map[string]string{
			"matched_at": "https://app.writer.com/new",
		},
		LastObservedAt: now.Add(time.Minute),
	}
	merged, _, err := service.mergeExistingFindingEvidence(context.Background(), incoming)
	if err != nil {
		t.Fatalf("mergeExistingFindingEvidence() error = %v", err)
	}
	if containsTrimmed(merged.EventIDs, "event-stale") {
		t.Fatalf("EventIDs = %#v, want no tombstoned stale event id", merged.EventIDs)
	}
	for _, eventID := range []string{"event-live", "event-new"} {
		if !containsTrimmed(merged.EventIDs, eventID) {
			t.Fatalf("EventIDs = %#v, missing %q", merged.EventIDs, eventID)
		}
	}
	var locations []string
	if err := json.Unmarshal([]byte(merged.Attributes["matched_locations_json"]), &locations); err != nil {
		t.Fatalf("matched_locations_json = %q is invalid JSON array: %v", merged.Attributes["matched_locations_json"], err)
	}
	if slices.Contains(locations, "https://app.writer.com/stale") {
		t.Fatalf("matched_locations_json = %#v, want no tombstoned stale location", locations)
	}
	for _, location := range []string{"https://app.writer.com/live", "https://app.writer.com/new"} {
		if !slices.Contains(locations, location) {
			t.Fatalf("matched_locations_json = %#v, missing %q", locations, location)
		}
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
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingNoteAdded {
		t.Fatalf("canonical append event kind = %q, want %q", got, securityevents.FindingNoteAdded)
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
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingTicketLinked {
		t.Fatalf("canonical append event kind = %q, want %q", got, securityevents.FindingTicketLinked)
	}
}

func TestLinkFindingExternalRefRefreshesLifecycleReference(t *testing.T) {
	observedAt := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-panopticon-case",
				RuleID:       "panopticon-curated-case",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:panopticon_case:case-123"},
				Attributes:   map[string]string{"primary_resource_urn": "urn:cerebro:writer:panopticon_case:case-123"},
			},
		},
	}
	graphStore := &stubGraphStore{}
	appendLog := &recordingAppendLog{}
	service := New(nil, nil, store, store, store, store).WithGraphStore(graphStore).WithAppendLog(appendLog)
	first, err := service.LinkFindingExternalRef(context.Background(), "finding-1", ports.FindingExternalRef{
		System:         "panopticon",
		Kind:           "case",
		ExternalID:     "case-123",
		URL:            "https://panopticon.example/cases/123",
		ExternalStatus: "open",
		LifecycleOwner: "external_owned",
		ObservedAt:     observedAt,
	})
	if err != nil {
		t.Fatalf("LinkFindingExternalRef(first) error = %v", err)
	}
	if got := len(first.ExternalRefs); got != 1 {
		t.Fatalf("external refs after first link = %d, want 1", got)
	}
	externalRefURN := ""
	for urn, entity := range graphStore.entities {
		if entity != nil && entity.EntityType == "external_ref" && entity.Attributes["external_id"] == "case-123" {
			externalRefURN = urn
			break
		}
	}
	if externalRefURN == "" {
		t.Fatalf("external ref graph entity missing: %#v", graphStore.entities)
	}
	if _, ok := graphStore.links["urn:cerebro:writer:finding:finding-1|tracked_by|"+externalRefURN]; !ok {
		t.Fatal("finding external ref link missing")
	}
	second, err := service.LinkFindingExternalRef(context.Background(), "finding-1", ports.FindingExternalRef{
		System:               "panopticon",
		Kind:                 "case",
		ExternalID:           "case-123",
		URL:                  "https://panopticon.example/cases/123",
		ExternalStatus:       "closed",
		ExternalStatusReason: "triaged false positive",
		LifecycleOwner:       "external_owned",
		ObservedAt:           observedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("LinkFindingExternalRef(second) error = %v", err)
	}
	if got := len(second.ExternalRefs); got != 1 {
		t.Fatalf("external refs after refresh = %d, want 1", got)
	}
	ref := second.ExternalRefs[0]
	if got := ref.ExternalStatus; got != "closed" {
		t.Fatalf("ExternalStatus = %q, want closed", got)
	}
	if got := ref.ExternalStatusReason; got != "triaged false positive" {
		t.Fatalf("ExternalStatusReason = %q, want triaged false positive", got)
	}
	if got := graphStore.entities[externalRefURN].Attributes["external_status"]; got != "closed" {
		t.Fatalf("projected external_status = %q, want closed", got)
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("len(appendLog.events) = %d, want 2", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingExternalRefLinked {
		t.Fatalf("canonical append event kind = %q, want %q", got, securityevents.FindingExternalRefLinked)
	}
}

func TestEvaluateSourceRuntimePreservesManualWorkflowFields(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newOktaPolicyRuleEvent("okta-policy-rule-active", "ACTIVE"),
			newOktaPolicyRuleEvent("okta-policy-rule-inactive", "INACTIVE"),
		},
	}
	store := &stubFindingStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-policy-rule",
				SourceEventID: "okta-policy-rule-inactive",
			},
		},
	}
	service := New(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"family": "policy_rule"},
			},
		},
	}, replayer, store, store, store, store)

	first, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-policy-rule",
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
		RuntimeID:  "writer-okta-policy-rule",
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
				GraphPathUrns: []string{"urn:cerebro:writer:okta_user:00u2"},
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
		GraphPathURN: "urn:cerebro:writer:okta_user:00u2",
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
	if got := store.evidenceList.GraphPathURN; got != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("ListEvidence().GraphPathURN = %q, want graph path urn", got)
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

//nolint:unparam // Helper keeps outcome explicit to document audit fixture attributes.
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

func newOktaPolicyRuleEvent(id string, status string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.policy_rule",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/policy_rule/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"family":                            "policy_rule",
			"policy_id":                         "pol-1",
			"policy_rule_id":                    "rul-1",
			"policy_type":                       "OKTA_SIGN_ON",
			"name":                              "Require MFA",
			"priority":                          "1",
			"resource_id":                       "rul-1",
			"resource_type":                     "PolicyRule",
			"status":                            status,
			"policy_rule_status":                status,
			"system":                            "false",
			ports.EventAttributeSourceRuntimeID: "writer-okta-policy-rule",
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
	graphEvidenceRows := cloneGraphEvidenceRows(finding.GraphEvidenceRows)
	notes := make([]ports.FindingNote, len(finding.Notes))
	copy(notes, finding.Notes)
	tickets := make([]ports.FindingTicket, len(finding.Tickets))
	copy(tickets, finding.Tickets)
	externalRefs := make([]ports.FindingExternalRef, len(finding.ExternalRefs))
	copy(externalRefs, finding.ExternalRefs)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:          finding.ID,
		Fingerprint: finding.Fingerprint,
		TenantID:    finding.TenantID,
		RuntimeID:   finding.RuntimeID,
		RuleID:      finding.RuleID,
		Title:       finding.Title,
		Severity:    finding.Severity,
		Status:      finding.Status,
		Summary:     finding.Summary,
		FindingRisk: ports.FindingRisk{
			RiskScore:        finding.RiskScore,
			LikelihoodScore:  finding.LikelihoodScore,
			ImpactScore:      finding.ImpactScore,
			ConfidenceScore:  finding.ConfidenceScore,
			LikelihoodLevel:  finding.LikelihoodLevel,
			ImpactLevel:      finding.ImpactLevel,
			RiskReasons:      append([]string(nil), finding.RiskReasons...),
			RiskFactors:      append([]ports.FindingRiskFactor(nil), finding.RiskFactors...),
			RiskModelVersion: finding.RiskModelVersion,
		},
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       controlRefs,
		GraphEvidenceRows: graphEvidenceRows,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			ExternalRefs:    externalRefs,
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		FindingTombstone: ports.FindingTombstone{
			Tombstoned:          finding.Tombstoned,
			TombstonedAt:        finding.TombstonedAt,
			TombstonedBy:        finding.TombstonedBy,
			TombstonedReason:    finding.TombstonedReason,
			TombstonedRunID:     finding.TombstonedRunID,
			PriorStatus:         finding.PriorStatus,
			TombstoneGeneration: finding.TombstoneGeneration,
		},
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func cloneRiskScoringConfig(config *ports.RiskScoringConfig) *ports.RiskScoringConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	if config.RelationWeights != nil {
		cloned.RelationWeights = make(map[string]int, len(config.RelationWeights))
		for key, value := range config.RelationWeights {
			cloned.RelationWeights[key] = value
		}
	}
	if config.FactorWeights != nil {
		cloned.FactorWeights = make(map[string]ports.RiskScoringFactorWeight, len(config.FactorWeights))
		for key, value := range config.FactorWeights {
			cloned.FactorWeights[key] = value
		}
	}
	return &cloned
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
	if len(existing.ExternalRefs) != 0 && len(incoming.ExternalRefs) == 0 {
		incoming.ExternalRefs = append([]ports.FindingExternalRef(nil), existing.ExternalRefs...)
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

func cloneFindingCandidate(candidate *ports.FindingCandidateRecord) *ports.FindingCandidateRecord {
	if candidate == nil {
		return nil
	}
	cloned := *candidate
	cloned.Finding = cloneFinding(candidate.Finding)
	cloned.Evidence = make([]*cerebrov1.FindingEvidence, 0, len(candidate.Evidence))
	for _, evidence := range candidate.Evidence {
		cloned.Evidence = append(cloned.Evidence, cloneFindingEvidence(evidence))
	}
	return &cloned
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
		return false
	}
	if strings.TrimSpace(request.RuntimeID) != "" && strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
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
	if cutoff := request.LastObservedBefore.UTC(); !cutoff.IsZero() && !finding.LastObservedAt.Before(cutoff) {
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

func findStatusChangedPayload(t *testing.T, events []*cerebrov1.EventEnvelope, findingID string) *workflowevents.FindingStatusChanged {
	t.Helper()
	for _, event := range events {
		decodeEvent := event
		if event.GetKind() == securityevents.FindingStatusChanged {
			decodeEvent = protoCloneEvent(event, workflowevents.EventKindFindingStatusChanged)
		} else if event.GetKind() != workflowevents.EventKindFindingStatusChanged {
			continue
		}
		payload, err := workflowevents.DecodeFindingStatusChanged(decodeEvent)
		if err != nil {
			t.Fatalf("DecodeFindingStatusChanged(%q): %v", event.GetId(), err)
		}
		if strings.TrimSpace(payload.Finding.FindingID) == strings.TrimSpace(findingID) {
			return payload
		}
	}
	t.Fatalf("workflow status changed event for finding %q not found in %d events", findingID, len(events))
	return nil
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

func candidateRunForRule(runs map[string]*ports.FindingCandidateRun, ruleID string) (*ports.FindingCandidateRun, bool) {
	for _, run := range runs {
		if strings.TrimSpace(run.RuleID) == strings.TrimSpace(ruleID) {
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
	if request.RunID != "" {
		runID := strings.TrimSpace(request.RunID)
		if strings.TrimSpace(evidence.GetRunId()) != runID && !slices.Contains(evidence.GetRunIds(), runID) {
			return false
		}
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
	if request.GraphPathURN != "" && !containsTrimmed(evidence.GetGraphPathUrns(), request.GraphPathURN) {
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

func captureFindingStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func decodeTelemetryPayload(t *testing.T, stderr string) map[string]any {
	t.Helper()
	line := strings.TrimSpace(stderr)
	if line == "" {
		t.Fatal("telemetry stderr is empty")
	}
	payload := map[string]any{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("decode telemetry JSON %q: %v", line, err)
	}
	return payload
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
	first := findingEvidenceID("rt:a", "finding_x", []string{"urn:root"}, []string{"event-1"})
	second := findingEvidenceID("rt-a", "finding-x", []string{"urn:root"}, []string{"event-1"})
	if first == second {
		t.Fatalf("findingEvidenceID() = %q, want distinct ids for raw inputs that normalize alike", first)
	}
}
