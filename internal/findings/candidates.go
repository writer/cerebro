package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	findingCandidateStatusCandidate = "candidate"
	findingCandidateStatusExpired   = "expired"
	findingCandidateStatusPromoted  = "promoted"
	findingCandidateStatusRejected  = "rejected"
	findingCandidateDecisionType    = "finding_candidate_promotion"
	findingCandidateRejectionType   = "finding_candidate_rejection"
)

func boundedUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

// EvaluateCandidateRulesRequest scopes one non-production candidate evaluation.
type EvaluateCandidateRulesRequest struct {
	RuntimeID  string
	RuleIDs    []string
	EventLimit uint32
}

// FindingCandidateEvaluationResult reports one rule's candidate outputs.
type FindingCandidateEvaluationResult struct {
	Rule       *cerebrov1.RuleSpec
	Run        *ports.FindingCandidateRun
	Candidates []*ports.FindingCandidateRecord
}

// EvaluateCandidateRulesResult reports one candidate evaluation over one runtime.
type EvaluateCandidateRulesResult struct {
	Runtime         *cerebrov1.SourceRuntime
	EventsEvaluated uint32
	Evaluations     []*FindingCandidateEvaluationResult
}

// ListCandidatesRequest scopes a candidate-finding list query.
type ListCandidatesRequest struct {
	RuntimeID   string
	CandidateID string
	RuleID      string
	Status      string
	Fingerprint string
	Limit       uint32
}

// ListCandidatesResult reports candidate findings.
type ListCandidatesResult struct {
	Candidates []*ports.FindingCandidateRecord
}

// PromoteCandidateRequest promotes one reviewed candidate into production findings.
type PromoteCandidateRequest struct {
	CandidateID           string
	PromotedBy            string
	Rationale             string
	ChangeTicket          string
	FalsePositiveReviewed bool
	GraphCoverageReviewed bool
}

// PromoteCandidateResult reports the production finding and updated candidate.
type PromoteCandidateResult struct {
	Candidate  *ports.FindingCandidateRecord
	Finding    *ports.FindingRecord
	DecisionID string
}

// RejectCandidateRequest rejects one reviewed candidate without production writes.
type RejectCandidateRequest struct {
	CandidateID string
	RejectedBy  string
	Rationale   string
}

// RejectCandidateResult reports the updated candidate and audit decision.
type RejectCandidateResult struct {
	Candidate  *ports.FindingCandidateRecord
	DecisionID string
}

type candidateRuleEvaluationState struct {
	rule              Rule
	run               *ports.FindingCandidateRun
	result            *FindingCandidateEvaluationResult
	eventsMatched     uint32
	evaluatedEventIDs []string
	failed            bool
}

// EvaluateSourceRuntimeCandidateRules evaluates real runtime events into isolated
// candidate storage without mutating production findings, evidence, or graph anchors.
func (s *Service) EvaluateSourceRuntimeCandidateRules(ctx context.Context, request EvaluateCandidateRulesRequest) (*EvaluateCandidateRulesResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.candidateStore == nil || s.claimStore == nil || s.rules == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	rules, err := s.selectRules(ctx, runtime, request.RuleIDs)
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	result := &EvaluateCandidateRulesResult{
		Runtime:     runtime,
		Evaluations: make([]*FindingCandidateEvaluationResult, 0, len(rules)),
	}
	states := make([]*candidateRuleEvaluationState, 0, len(rules))
	for _, rule := range rules {
		run := newFindingCandidateRun(runtime, rule.Spec().GetId(), normalizedLimit, startedAt)
		if err := s.candidateStore.PutFindingCandidateRun(ctx, run); err != nil {
			return nil, fmt.Errorf("persist finding candidate run %q: %w", run.ID, err)
		}
		evaluation := &FindingCandidateEvaluationResult{
			Rule: rule.Spec(),
			Run:  run,
		}
		states = append(states, &candidateRuleEvaluationState{
			rule:   rule,
			run:    run,
			result: evaluation,
		})
		result.Evaluations = append(result.Evaluations, evaluation)
	}
	var events []*cerebrov1.EventEnvelope
	if rulesNeedReplay(runtime, ruleEvaluationStatesFromCandidateStates(states)) {
		if err := s.prepareReplay(ctx); err != nil {
			evaluationErr := fmt.Errorf("prepare replay runtime %q events for candidates: %w", runtimeID, err)
			return nil, s.markCandidateEvaluationsFailed(ctx, states, evaluationErr)
		}
		events, err = s.replayer.Replay(ctx, replayRequestForRules(runtime, runtimeID, normalizedLimit, rulesFromCandidateStates(states)))
		if err != nil {
			evaluationErr := fmt.Errorf("replay runtime %q events for candidates: %w", runtimeID, err)
			return nil, s.markCandidateEvaluationsFailed(ctx, states, evaluationErr)
		}
	}
	result.EventsEvaluated = boundedUint32(len(events))
	for _, event := range events {
		for _, state := range states {
			if state.failed || !state.rule.SupportsRuntime(runtime) {
				continue
			}
			emitted, err := state.rule.Evaluate(ctx, runtime, event)
			if err != nil {
				if failErr := s.markCandidateEvaluationFailed(ctx, state, fmt.Errorf("evaluate finding candidate rule %q for event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
					return nil, s.markCandidateEvaluationsFailed(ctx, states, failErr)
				}
				continue
			}
			state.run.EventsEvaluated++
			if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
				state.evaluatedEventIDs = append(state.evaluatedEventIDs, eventID)
			}
			matchedEvent := false
			for _, record := range emitted {
				if record == nil {
					continue
				}
				if !matchedEvent {
					state.eventsMatched++
					matchedEvent = true
				}
				candidateFinding := normalizeCandidateFinding(record, runtime, startedAt)
				config, err := s.riskScoringConfigForFinding(ctx, candidateFinding)
				if err != nil {
					if failErr := s.markCandidateEvaluationFailed(ctx, state, fmt.Errorf("load risk scoring config for candidate finding %q: %w", candidateFinding.ID, err)); failErr != nil {
						return nil, s.markCandidateEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				candidateFinding = recomputeFindingRiskWithConfig(candidateFinding, startedAt, config)
				evidence, err := s.buildFindingEvidence(ctx, candidateFinding, candidateEvidenceRun(state.run))
				if err != nil {
					if failErr := s.markCandidateEvaluationFailed(ctx, state, fmt.Errorf("build candidate evidence for finding %q: %w", candidateFinding.ID, err)); failErr != nil {
						return nil, s.markCandidateEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				candidate := newFindingCandidateRecord(candidateFinding, evidence, state.run.ID)
				stored, err := s.candidateStore.UpsertFindingCandidate(ctx, candidate)
				if err != nil {
					if failErr := s.markCandidateEvaluationFailed(ctx, state, fmt.Errorf("persist finding candidate %q: %w", candidate.ID, err)); failErr != nil {
						return nil, s.markCandidateEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				state.result.Candidates = append(state.result.Candidates, stored)
			}
		}
	}
	for _, state := range states {
		if state.failed {
			continue
		}
		state.run.EventsMatched = state.eventsMatched
		state.run.Candidates = boundedUint32(len(state.result.Candidates))
		state.run.Status = "completed"
		state.run.FinishedAt = time.Now().UTC()
		if _, err := s.candidateStore.ExpireStaleFindingCandidates(ctx, ports.FindingCandidateExpiration{
			TenantID:          strings.TrimSpace(runtime.GetTenantId()),
			RuntimeID:         runtimeID,
			RuleID:            state.run.RuleID,
			RunID:             state.run.ID,
			EvaluatedEventIDs: state.evaluatedEventIDs,
			RunStartedAt:      state.run.StartedAt,
		}); err != nil {
			return nil, s.markCandidateEvaluationsFailed(ctx, unfinishedCandidateEvaluations(states, state), fmt.Errorf("expire stale finding candidates for run %q: %w", state.run.ID, err))
		}
		if err := s.candidateStore.PutFindingCandidateRun(ctx, state.run); err != nil {
			return nil, s.markCandidateEvaluationsFailed(ctx, unfinishedCandidateEvaluations(states, state), fmt.Errorf("persist finding candidate run %q: %w", state.run.ID, err))
		}
		emitFindingCandidateRunTelemetry(ctx, state.run)
	}
	return result, nil
}

// ListFindingCandidates loads isolated candidate findings for one runtime.
func (s *Service) ListFindingCandidates(ctx context.Context, request ListCandidatesRequest) (*ListCandidatesResult, error) {
	if s == nil || s.runtimeStore == nil || s.candidateStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	candidates, err := s.candidateStore.ListFindingCandidates(ctx, ports.ListFindingCandidatesRequest{
		TenantID:    strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID:   runtimeID,
		CandidateID: strings.TrimSpace(request.CandidateID),
		RuleID:      strings.TrimSpace(request.RuleID),
		Status:      strings.TrimSpace(request.Status),
		Fingerprint: strings.TrimSpace(request.Fingerprint),
		Limit:       request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list finding candidates for runtime %q: %w", runtimeID, err)
	}
	emitFindingCandidateListTelemetry(ctx, runtimeID, candidates, request)
	return &ListCandidatesResult{Candidates: candidates}, nil
}

// GetFindingCandidate loads one isolated candidate finding.
func (s *Service) GetFindingCandidate(ctx context.Context, id string) (*ports.FindingCandidateRecord, error) {
	if s == nil || s.candidateStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	candidateID := strings.TrimSpace(id)
	if candidateID == "" {
		return nil, fmt.Errorf("%w: finding candidate id is required", ErrInvalidRequest)
	}
	candidate, err := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if err != nil {
		return nil, err
	}
	return candidate, nil
}

// PromoteFindingCandidate turns one reviewed candidate snapshot into production
// finding state and records an audit decision for the promotion.
// Candidate lifecycle transitions rely on store-owned compare-and-swap updates:
// MarkFindingCandidatePromoted/Rejected only mutate rows still in candidate state.
func (s *Service) PromoteFindingCandidate(ctx context.Context, request PromoteCandidateRequest) (*PromoteCandidateResult, error) {
	if s == nil || s.candidateStore == nil || s.store == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	startedAt := time.Now().UTC()
	candidateID := strings.TrimSpace(request.CandidateID)
	if candidateID == "" {
		return nil, fmt.Errorf("%w: finding candidate id is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.PromotedBy) == "" {
		return nil, fmt.Errorf("%w: promoted_by is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.Rationale) == "" {
		return nil, fmt.Errorf("%w: promotion rationale is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.ChangeTicket) == "" {
		return nil, fmt.Errorf("%w: promotion change ticket is required", ErrInvalidRequest)
	}
	if !request.FalsePositiveReviewed {
		return nil, fmt.Errorf("%w: false positive review is required", ErrInvalidRequest)
	}
	if !request.GraphCoverageReviewed {
		return nil, fmt.Errorf("%w: graph coverage review is required", ErrInvalidRequest)
	}
	candidate, err := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusPromoted) {
		finding, err := s.store.GetFinding(ctx, strings.TrimSpace(candidate.PromotedFindingID))
		if err != nil {
			return nil, err
		}
		emitFindingCandidatePromotionTelemetry(ctx, "already_promoted", candidate, finding, strings.TrimSpace(candidate.DecisionID), startedAt)
		return &PromoteCandidateResult{Candidate: candidate, Finding: finding, DecisionID: strings.TrimSpace(candidate.DecisionID)}, nil
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusRejected) {
		return nil, fmt.Errorf("%w: rejected finding candidate cannot be promoted", ErrInvalidRequest)
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusExpired) {
		return nil, fmt.Errorf("%w: expired finding candidate cannot be promoted", ErrInvalidRequest)
	}
	if candidate.Finding == nil {
		return nil, fmt.Errorf("%w: finding candidate has no finding snapshot", ErrInvalidRequest)
	}
	if len(candidate.Evidence) == 0 {
		return nil, fmt.Errorf("%w: finding candidate has no evidence", ErrInvalidRequest)
	}
	now := time.Now().UTC()
	production := cloneFindingRecord(candidate.Finding)
	if production.Attributes == nil {
		production.Attributes = map[string]string{}
	}
	production.Attributes["promoted_from_candidate_id"] = candidate.ID
	production.Attributes["promotion_change_ticket"] = strings.TrimSpace(request.ChangeTicket)
	production.Attributes["promotion_rationale"] = strings.TrimSpace(request.Rationale)
	production.Attributes["promoted_by"] = strings.TrimSpace(request.PromotedBy)
	production.Attributes["promoted_at"] = now.Format(time.RFC3339Nano)
	decisionID := candidatePromotionDecisionID(candidate, production, request, now)
	stored, err := s.upsertFindingWithRisk(ctx, production, &cerebrov1.SourceRuntime{
		Id:       strings.TrimSpace(candidate.RuntimeID),
		TenantId: strings.TrimSpace(candidate.TenantID),
	}, now)
	if err != nil {
		return nil, fmt.Errorf("promote finding candidate %q: %w", candidate.ID, err)
	}
	for _, evidence := range candidate.Evidence {
		if evidence == nil {
			continue
		}
		productionEvidence := proto.Clone(evidence).(*cerebrov1.FindingEvidence)
		productionEvidence.FindingId = strings.TrimSpace(stored.ID)
		if productionEvidence.GetRunId() == "" {
			productionEvidence.RunId = strings.TrimSpace(candidate.LastRunID)
		}
		if err := s.evidenceStore.PutFindingEvidence(ctx, productionEvidence); err != nil {
			return nil, fmt.Errorf("persist promoted candidate %q evidence %q: %w", candidate.ID, productionEvidence.GetId(), err)
		}
	}
	if err := s.projectFindingAnchor(ctx, stored); err != nil {
		return nil, fmt.Errorf("project promoted candidate %q finding %q: %w", candidate.ID, stored.ID, err)
	}
	if err := s.recordCandidatePromotionDecision(ctx, candidate, stored, request, now, decisionID); err != nil {
		return nil, err
	}
	promoted, err := s.candidateStore.MarkFindingCandidatePromoted(ctx, ports.FindingCandidatePromotion{
		CandidateID:       candidate.ID,
		PromotedFindingID: stored.ID,
		DecisionID:        decisionID,
		PromotedBy:        strings.TrimSpace(request.PromotedBy),
		Rationale:         strings.TrimSpace(request.Rationale),
		ChangeTicket:      strings.TrimSpace(request.ChangeTicket),
		PromotedAt:        now,
	})
	if err != nil {
		recovered, recoverErr := s.recoverPromotedCandidate(ctx, candidate.ID, stored.ID, decisionID, request)
		if recoverErr == nil {
			recoveredFinding, loadErr := s.store.GetFinding(ctx, strings.TrimSpace(recovered.PromotedFindingID))
			if loadErr != nil {
				return nil, loadErr
			}
			emitFindingCandidatePromotionTelemetry(ctx, "promoted_recovered", recovered, recoveredFinding, decisionID, startedAt)
			return &PromoteCandidateResult{Candidate: recovered, Finding: recoveredFinding, DecisionID: decisionID}, nil
		}
		return nil, s.findingCandidateLifecycleConflict(ctx, candidate.ID, findingCandidateStatusPromoted, err)
	}
	emitFindingCandidatePromotionTelemetry(ctx, "promoted", promoted, stored, decisionID, startedAt)
	return &PromoteCandidateResult{Candidate: promoted, Finding: stored, DecisionID: decisionID}, nil
}

// RejectFindingCandidate marks a reviewed candidate as intentionally not
// production-worthy and records the review decision for audit.
func (s *Service) RejectFindingCandidate(ctx context.Context, request RejectCandidateRequest) (*RejectCandidateResult, error) {
	if s == nil || s.candidateStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	startedAt := time.Now().UTC()
	candidateID := strings.TrimSpace(request.CandidateID)
	if candidateID == "" {
		return nil, fmt.Errorf("%w: finding candidate id is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.RejectedBy) == "" {
		return nil, fmt.Errorf("%w: rejected_by is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.Rationale) == "" {
		return nil, fmt.Errorf("%w: rejection rationale is required", ErrInvalidRequest)
	}
	candidate, err := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusPromoted) {
		return nil, fmt.Errorf("%w: promoted finding candidate cannot be rejected", ErrInvalidRequest)
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusExpired) {
		return nil, fmt.Errorf("%w: expired finding candidate cannot be rejected", ErrInvalidRequest)
	}
	if strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusRejected) {
		emitFindingCandidateRejectionTelemetry(ctx, "already_rejected", candidate, strings.TrimSpace(candidate.DecisionID), startedAt)
		return &RejectCandidateResult{Candidate: candidate, DecisionID: strings.TrimSpace(candidate.DecisionID)}, nil
	}
	now := time.Now().UTC()
	decisionID := candidateRejectionDecisionID(candidate, request, now)
	if err := s.recordCandidateRejectionDecision(ctx, candidate, request, now, decisionID); err != nil {
		return nil, err
	}
	rejected, err := s.candidateStore.MarkFindingCandidateRejected(ctx, ports.FindingCandidateRejection{
		CandidateID: candidate.ID,
		DecisionID:  decisionID,
		RejectedBy:  strings.TrimSpace(request.RejectedBy),
		Rationale:   strings.TrimSpace(request.Rationale),
		RejectedAt:  now,
	})
	if err != nil {
		recovered, recoverErr := s.recoverRejectedCandidate(ctx, candidate.ID, decisionID, request)
		if recoverErr == nil {
			emitFindingCandidateRejectionTelemetry(ctx, "rejected_recovered", recovered, decisionID, startedAt)
			return &RejectCandidateResult{Candidate: recovered, DecisionID: decisionID}, nil
		}
		return nil, s.findingCandidateLifecycleConflict(ctx, candidate.ID, findingCandidateStatusRejected, err)
	}
	emitFindingCandidateRejectionTelemetry(ctx, "rejected", rejected, decisionID, startedAt)
	return &RejectCandidateResult{Candidate: rejected, DecisionID: decisionID}, nil
}

func (s *Service) findingCandidateLifecycleConflict(ctx context.Context, candidateID string, attemptedStatus string, err error) error {
	if !errors.Is(err, ports.ErrFindingCandidateNotFound) {
		return err
	}
	current, lookupErr := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if lookupErr != nil {
		return err
	}
	switch strings.TrimSpace(current.Status) {
	case findingCandidateStatusPromoted:
		return fmt.Errorf("%w: promoted finding candidate cannot transition to %s", ErrInvalidRequest, strings.TrimSpace(attemptedStatus))
	case findingCandidateStatusExpired:
		return fmt.Errorf("%w: expired finding candidate cannot transition to %s", ErrInvalidRequest, strings.TrimSpace(attemptedStatus))
	case findingCandidateStatusRejected:
		return fmt.Errorf("%w: rejected finding candidate cannot transition to %s", ErrInvalidRequest, strings.TrimSpace(attemptedStatus))
	default:
		return fmt.Errorf("%w: finding candidate status changed before lifecycle transition", ErrInvalidRequest)
	}
}

func (s *Service) recoverPromotedCandidate(ctx context.Context, candidateID string, findingID string, decisionID string, request PromoteCandidateRequest) (*ports.FindingCandidateRecord, error) {
	current, err := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(current.Status), findingCandidateStatusPromoted) {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(current.PromotedFindingID) != strings.TrimSpace(findingID) || strings.TrimSpace(current.DecisionID) != strings.TrimSpace(decisionID) {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(current.PromotedBy) != strings.TrimSpace(request.PromotedBy) ||
		strings.TrimSpace(current.PromotionRationale) != strings.TrimSpace(request.Rationale) ||
		strings.TrimSpace(current.ChangeTicket) != strings.TrimSpace(request.ChangeTicket) {
		return nil, ErrInvalidRequest
	}
	return current, nil
}

func (s *Service) recoverRejectedCandidate(ctx context.Context, candidateID string, decisionID string, request RejectCandidateRequest) (*ports.FindingCandidateRecord, error) {
	current, err := s.candidateStore.GetFindingCandidate(ctx, candidateID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(current.Status), findingCandidateStatusRejected) || strings.TrimSpace(current.DecisionID) != strings.TrimSpace(decisionID) {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(current.RejectedBy) != strings.TrimSpace(request.RejectedBy) ||
		strings.TrimSpace(current.RejectionRationale) != strings.TrimSpace(request.Rationale) {
		return nil, ErrInvalidRequest
	}
	return current, nil
}

func candidatePromotionDecisionID(candidate *ports.FindingCandidateRecord, finding *ports.FindingRecord, request PromoteCandidateRequest, observedAt time.Time) string {
	if candidate == nil || finding == nil {
		return ""
	}
	tenantID := strings.TrimSpace(candidate.TenantID)
	reviewID := candidateReviewDecisionSuffix(
		"promotion",
		candidate.ID,
		finding.ID,
		request.PromotedBy,
		request.Rationale,
		request.ChangeTicket,
		fmt.Sprint(request.FalsePositiveReviewed),
		fmt.Sprint(request.GraphCoverageReviewed),
	)
	return workflowevents.CanonicalWorkflowID(tenantID, "decision", reviewID, findingCandidateDecisionType, []string{
		findingGraphFindingURN(tenantID, finding),
		findingCandidateURN(tenantID, candidate.ID),
	}, observedAt)
}

func candidateRejectionDecisionID(candidate *ports.FindingCandidateRecord, request RejectCandidateRequest, observedAt time.Time) string {
	if candidate == nil {
		return ""
	}
	tenantID := strings.TrimSpace(candidate.TenantID)
	reviewID := candidateReviewDecisionSuffix("rejection", candidate.ID, request.RejectedBy, request.Rationale)
	return workflowevents.CanonicalWorkflowID(tenantID, "decision", reviewID, findingCandidateRejectionType, []string{
		findingCandidateURN(tenantID, candidate.ID),
	}, observedAt)
}

func candidateReviewDecisionSuffix(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.TrimSpace(part))
	}
	digest := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return strings.TrimSpace(parts[1]) + "-" + strings.TrimSpace(parts[0]) + "-" + hex.EncodeToString(digest[:8])
}

func (s *Service) recordCandidatePromotionDecision(ctx context.Context, candidate *ports.FindingCandidateRecord, finding *ports.FindingRecord, request PromoteCandidateRequest, observedAt time.Time, decisionID string) error {
	if candidate == nil || finding == nil {
		return errors.New("candidate and finding are required")
	}
	tenantID := strings.TrimSpace(candidate.TenantID)
	targetIDs := []string{
		findingGraphFindingURN(tenantID, finding),
		findingCandidateURN(tenantID, candidate.ID),
	}
	event, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:      tenantID,
		DecisionID:    decisionID,
		DecisionType:  findingCandidateDecisionType,
		Status:        findingDecisionStatusCompleted,
		MadeBy:        strings.TrimSpace(request.PromotedBy),
		Rationale:     strings.TrimSpace(request.Rationale),
		TargetIDs:     targetIDs,
		EvidenceIDs:   candidateEvidenceIDs(candidate.Evidence),
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(candidate.ID),
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
		ValidFrom:     observedAt.Format(time.RFC3339Nano),
		Metadata: map[string]any{
			"tenant_id":                   tenantID,
			"candidate_id":                strings.TrimSpace(candidate.ID),
			"finding_id":                  strings.TrimSpace(finding.ID),
			"runtime_id":                  strings.TrimSpace(candidate.RuntimeID),
			"rule_id":                     strings.TrimSpace(candidate.RuleID),
			"change_ticket":               strings.TrimSpace(request.ChangeTicket),
			"false_positive_reviewed":     request.FalsePositiveReviewed,
			"graph_coverage_reviewed":     request.GraphCoverageReviewed,
			"candidate_observation_count": candidate.ObservationCount,
		},
	})
	if err != nil {
		return err
	}
	if err := s.recordAndProjectWorkflowEvent(ctx, event); err != nil {
		return fmt.Errorf("record finding candidate %q promotion decision: %w", candidate.ID, err)
	}
	return nil
}

func (s *Service) recordCandidateRejectionDecision(ctx context.Context, candidate *ports.FindingCandidateRecord, request RejectCandidateRequest, observedAt time.Time, decisionID string) error {
	if candidate == nil {
		return errors.New("candidate is required")
	}
	tenantID := strings.TrimSpace(candidate.TenantID)
	targetIDs := []string{findingCandidateURN(tenantID, candidate.ID)}
	event, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:      tenantID,
		DecisionID:    decisionID,
		DecisionType:  findingCandidateRejectionType,
		Status:        findingDecisionStatusCompleted,
		MadeBy:        strings.TrimSpace(request.RejectedBy),
		Rationale:     strings.TrimSpace(request.Rationale),
		TargetIDs:     targetIDs,
		EvidenceIDs:   candidateEvidenceIDs(candidate.Evidence),
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(candidate.ID),
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
		ValidFrom:     observedAt.Format(time.RFC3339Nano),
		Metadata: map[string]any{
			"tenant_id":                   tenantID,
			"candidate_id":                strings.TrimSpace(candidate.ID),
			"runtime_id":                  strings.TrimSpace(candidate.RuntimeID),
			"rule_id":                     strings.TrimSpace(candidate.RuleID),
			"candidate_observation_count": candidate.ObservationCount,
		},
	})
	if err != nil {
		return err
	}
	if err := s.recordAndProjectWorkflowEvent(ctx, event); err != nil {
		return fmt.Errorf("record finding candidate %q rejection decision: %w", candidate.ID, err)
	}
	return nil
}

func normalizeCandidateFinding(record *ports.FindingRecord, runtime *cerebrov1.SourceRuntime, observedAt time.Time) *ports.FindingRecord {
	cloned := cloneFindingRecord(record)
	if cloned == nil {
		return nil
	}
	if cloned.Attributes == nil {
		cloned.Attributes = map[string]string{}
	}
	cloned.TenantID = firstNonEmpty(strings.TrimSpace(cloned.TenantID), strings.TrimSpace(runtime.GetTenantId()))
	cloned.RuntimeID = firstNonEmpty(strings.TrimSpace(cloned.RuntimeID), strings.TrimSpace(runtime.GetId()))
	if cloned.FirstObservedAt.IsZero() {
		cloned.FirstObservedAt = observedAt
	}
	if cloned.LastObservedAt.IsZero() {
		cloned.LastObservedAt = observedAt
	}
	return recomputeFindingRisk(enrichFindingRisk(cloned, runtime, observedAt), observedAt)
}

func newFindingCandidateRecord(finding *ports.FindingRecord, evidence *cerebrov1.FindingEvidence, runID string) *ports.FindingCandidateRecord {
	evidenceRecords := []*cerebrov1.FindingEvidence{}
	if evidence != nil {
		evidenceRecords = append(evidenceRecords, proto.Clone(evidence).(*cerebrov1.FindingEvidence))
	}
	return &ports.FindingCandidateRecord{
		ID:               findingCandidateID(finding),
		TenantID:         strings.TrimSpace(finding.TenantID),
		RuntimeID:        strings.TrimSpace(finding.RuntimeID),
		RuleID:           strings.TrimSpace(finding.RuleID),
		Fingerprint:      strings.TrimSpace(finding.Fingerprint),
		Status:           findingCandidateStatusCandidate,
		Finding:          cloneFindingRecord(finding),
		Evidence:         evidenceRecords,
		LastRunID:        strings.TrimSpace(runID),
		ObservationCount: 1,
		FirstObservedAt:  finding.FirstObservedAt.UTC(),
		LastObservedAt:   finding.LastObservedAt.UTC(),
	}
}

func newFindingCandidateRun(runtime *cerebrov1.SourceRuntime, ruleID string, eventLimit uint32, startedAt time.Time) *ports.FindingCandidateRun {
	return &ports.FindingCandidateRun{
		ID:         findingCandidateRunID(runtime.GetId(), ruleID, startedAt.UTC()),
		TenantID:   strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID:  strings.TrimSpace(runtime.GetId()),
		RuleID:     strings.TrimSpace(ruleID),
		Status:     "running",
		EventLimit: normalizeEventLimit(eventLimit),
		StartedAt:  startedAt.UTC(),
	}
}

func candidateEvidenceRun(run *ports.FindingCandidateRun) *cerebrov1.FindingEvaluationRun {
	if run == nil {
		return nil
	}
	return &cerebrov1.FindingEvaluationRun{
		Id:         strings.TrimSpace(run.ID),
		RuntimeId:  strings.TrimSpace(run.RuntimeID),
		RuleId:     strings.TrimSpace(run.RuleID),
		Status:     strings.TrimSpace(run.Status),
		EventLimit: run.EventLimit,
		StartedAt:  timestamppb.New(run.StartedAt.UTC()),
	}
}

func findingCandidateID(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	parts := []string{
		strings.TrimSpace(finding.TenantID),
		strings.TrimSpace(finding.RuntimeID),
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.Fingerprint),
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "finding-candidate-" + hex.EncodeToString(digest[:12])
}

func findingCandidateRunID(runtimeID string, ruleID string, startedAt time.Time) string {
	return strings.Replace(findingEvaluationRunID(runtimeID, ruleID, startedAt), "finding-evaluation-run-", "finding-candidate-run-", 1)
}

func findingCandidateURN(tenantID string, candidateID string) string {
	return fmt.Sprintf("urn:cerebro:%s:finding_candidate:%s", strings.TrimSpace(tenantID), strings.TrimSpace(candidateID))
}

func candidateEvidenceIDs(evidence []*cerebrov1.FindingEvidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, record := range evidence {
		if record == nil {
			continue
		}
		if id := strings.TrimSpace(record.GetId()); id != "" {
			ids = append(ids, id)
		}
	}
	return uniqueSortedStrings(ids)
}

func emitFindingCandidateRunTelemetry(ctx context.Context, run *ports.FindingCandidateRun) {
	if run == nil {
		return
	}
	durationMS := int64(0)
	if !run.StartedAt.IsZero() && !run.FinishedAt.IsZero() {
		durationMS = run.FinishedAt.Sub(run.StartedAt).Milliseconds()
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "run_id", Value: strings.TrimSpace(run.ID)},
		telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(run.TenantID)},
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(run.RuntimeID)},
		telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(run.RuleID)},
		telemetry.Field{Key: "status", Value: strings.TrimSpace(run.Status)},
		telemetry.Field{Key: "event_limit", Value: run.EventLimit},
		telemetry.Field{Key: "events_evaluated", Value: run.EventsEvaluated},
		telemetry.Field{Key: "events_matched", Value: run.EventsMatched},
		telemetry.Field{Key: "candidates_emitted", Value: run.Candidates},
		telemetry.Field{Key: "duration_ms", Value: durationMS},
	)
	telemetry.Event(ctx, "finding_candidate.run", attrs)
	telemetry.IncrementMain(ctx, "finding_candidate.run.count", 1)
	if !strings.EqualFold(strings.TrimSpace(run.Status), "completed") {
		telemetry.IncrementMain(ctx, "finding_candidate.run.non_completed.count", 1)
	}
	telemetry.AnnotateMain(ctx, telemetry.Attrs(
		telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(run.TenantID)},
		telemetry.Field{Key: "finding_candidate.runtime_id", Value: strings.TrimSpace(run.RuntimeID)},
		telemetry.Field{Key: "finding_candidate.rule_id", Value: strings.TrimSpace(run.RuleID)},
		telemetry.Field{Key: "finding_candidate.status", Value: strings.TrimSpace(run.Status)},
		telemetry.Field{Key: "finding_candidate.event_limit", Value: run.EventLimit},
		telemetry.Field{Key: "finding_candidate.events_evaluated", Value: run.EventsEvaluated},
		telemetry.Field{Key: "finding_candidate.events_matched", Value: run.EventsMatched},
		telemetry.Field{Key: "finding_candidate.candidates_emitted", Value: run.Candidates},
		telemetry.Field{Key: "finding_candidate.duration_ms", Value: durationMS},
	))
}

func emitFindingCandidateListTelemetry(ctx context.Context, runtimeID string, candidates []*ports.FindingCandidateRecord, request ListCandidatesRequest) {
	counts := findingCandidateListTelemetryCounts(candidates, time.Now().UTC())
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(runtimeID)},
		telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(request.RuleID)},
		telemetry.Field{Key: "status_filter", Value: strings.TrimSpace(request.Status)},
		telemetry.Field{Key: "candidate_count", Value: counts.candidateCount},
		telemetry.Field{Key: "promoted_count", Value: counts.promotedCount},
		telemetry.Field{Key: "rejected_count", Value: counts.rejectedCount},
		telemetry.Field{Key: "expired_count", Value: counts.expiredCount},
		telemetry.Field{Key: "open_candidate_count", Value: counts.openCount()},
		telemetry.Field{Key: "stale_candidate_count", Value: counts.staleCount},
	)
	telemetry.Event(ctx, "finding_candidate.list", attrs)
	telemetry.IncrementMain(ctx, "finding_candidate.list.count", 1)
	telemetry.AnnotateMain(ctx, telemetry.Attrs(
		telemetry.Field{Key: "finding_candidate.runtime_id", Value: strings.TrimSpace(runtimeID)},
		telemetry.Field{Key: "finding_candidate.rule_id", Value: strings.TrimSpace(request.RuleID)},
		telemetry.Field{Key: "finding_candidate.status_filter", Value: strings.TrimSpace(request.Status)},
		telemetry.Field{Key: "finding_candidate.candidate_count", Value: counts.candidateCount},
		telemetry.Field{Key: "finding_candidate.promoted_count", Value: counts.promotedCount},
		telemetry.Field{Key: "finding_candidate.rejected_count", Value: counts.rejectedCount},
		telemetry.Field{Key: "finding_candidate.expired_count", Value: counts.expiredCount},
		telemetry.Field{Key: "finding_candidate.open_candidate_count", Value: counts.openCount()},
		telemetry.Field{Key: "finding_candidate.stale_candidate_count", Value: counts.staleCount},
	))
}

type findingCandidateTelemetryCounts struct {
	candidateCount int
	promotedCount  int
	rejectedCount  int
	expiredCount   int
	staleCount     int
}

func (counts findingCandidateTelemetryCounts) openCount() int {
	return counts.candidateCount - counts.promotedCount - counts.rejectedCount - counts.expiredCount
}

func findingCandidateListTelemetryCounts(candidates []*ports.FindingCandidateRecord, now time.Time) findingCandidateTelemetryCounts {
	counts := findingCandidateTelemetryCounts{}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		counts.candidateCount++
		switch {
		case strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusPromoted):
			counts.promotedCount++
			continue
		case strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusRejected):
			counts.rejectedCount++
			continue
		case strings.EqualFold(strings.TrimSpace(candidate.Status), findingCandidateStatusExpired):
			counts.expiredCount++
			continue
		}
		if !candidate.LastObservedAt.IsZero() && now.Sub(candidate.LastObservedAt.UTC()) > 7*24*time.Hour {
			counts.staleCount++
		}
	}
	return counts
}

func emitFindingCandidatePromotionTelemetry(ctx context.Context, outcome string, candidate *ports.FindingCandidateRecord, finding *ports.FindingRecord, decisionID string, startedAt time.Time) {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "outcome", Value: strings.TrimSpace(outcome)},
		telemetry.Field{Key: "decision_id", Value: strings.TrimSpace(decisionID)},
		telemetry.Field{Key: "duration_ms", Value: time.Since(startedAt).Milliseconds()},
	)
	if candidate != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "candidate_id", Value: strings.TrimSpace(candidate.ID)})
		attrs = attrs.WithField(telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(candidate.TenantID)})
		attrs = attrs.WithField(telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(candidate.RuntimeID)})
		attrs = attrs.WithField(telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(candidate.RuleID)})
		attrs = attrs.WithField(telemetry.Field{Key: "observation_count", Value: candidate.ObservationCount})
	}
	if finding != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "finding_id", Value: strings.TrimSpace(finding.ID)})
	}
	telemetry.Event(ctx, "finding_candidate.promotion", attrs)
	telemetry.IncrementMain(ctx, "finding_candidate.promotion.count", 1)
	telemetry.AnnotateMain(ctx, findingCandidateDecisionMainAttrs("promotion", outcome, candidate, startedAt))
}

func emitFindingCandidateRejectionTelemetry(ctx context.Context, outcome string, candidate *ports.FindingCandidateRecord, decisionID string, startedAt time.Time) {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "outcome", Value: strings.TrimSpace(outcome)},
		telemetry.Field{Key: "decision_id", Value: strings.TrimSpace(decisionID)},
		telemetry.Field{Key: "duration_ms", Value: time.Since(startedAt).Milliseconds()},
	)
	if candidate != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "candidate_id", Value: strings.TrimSpace(candidate.ID)})
		attrs = attrs.WithField(telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(candidate.TenantID)})
		attrs = attrs.WithField(telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(candidate.RuntimeID)})
		attrs = attrs.WithField(telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(candidate.RuleID)})
		attrs = attrs.WithField(telemetry.Field{Key: "observation_count", Value: candidate.ObservationCount})
	}
	telemetry.Event(ctx, "finding_candidate.rejection", attrs)
	telemetry.IncrementMain(ctx, "finding_candidate.rejection.count", 1)
	telemetry.AnnotateMain(ctx, findingCandidateDecisionMainAttrs("rejection", outcome, candidate, startedAt))
}

func findingCandidateDecisionMainAttrs(decision string, outcome string, candidate *ports.FindingCandidateRecord, startedAt time.Time) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "finding_candidate.decision", Value: strings.TrimSpace(decision)},
		telemetry.Field{Key: "finding_candidate.decision_outcome", Value: strings.TrimSpace(outcome)},
		telemetry.Field{Key: "finding_candidate.decision_duration_ms", Value: time.Since(startedAt).Milliseconds()},
	)
	if candidate == nil {
		return attrs
	}
	return attrs.
		WithField(telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(candidate.TenantID)}).
		WithField(telemetry.Field{Key: "finding_candidate.runtime_id", Value: strings.TrimSpace(candidate.RuntimeID)}).
		WithField(telemetry.Field{Key: "finding_candidate.rule_id", Value: strings.TrimSpace(candidate.RuleID)}).
		WithField(telemetry.Field{Key: "finding_candidate.observation_count", Value: candidate.ObservationCount})
}

func (s *Service) markCandidateEvaluationFailed(ctx context.Context, state *candidateRuleEvaluationState, evaluationErr error) error {
	if state == nil || state.run == nil {
		return evaluationErr
	}
	state.run.Status = "failed"
	state.run.EventsMatched = state.eventsMatched
	state.run.Candidates = boundedUint32(len(state.result.Candidates))
	state.run.Error = strings.TrimSpace(evaluationErr.Error())
	state.run.FinishedAt = time.Now().UTC()
	if err := s.candidateStore.PutFindingCandidateRun(ctx, state.run); err != nil {
		return errors.Join(evaluationErr, fmt.Errorf("persist finding candidate run %q: %w", state.run.ID, err))
	}
	emitFindingCandidateRunTelemetry(ctx, state.run)
	state.failed = true
	return nil
}

func (s *Service) markCandidateEvaluationsFailed(ctx context.Context, states []*candidateRuleEvaluationState, evaluationErr error) error {
	var cleanupErr error
	for _, state := range states {
		if state != nil && state.failed {
			continue
		}
		if failErr := s.markCandidateEvaluationFailed(ctx, state, evaluationErr); failErr != nil {
			cleanupErr = errors.Join(cleanupErr, failErr)
		}
	}
	if cleanupErr != nil {
		return errors.Join(evaluationErr, cleanupErr)
	}
	return evaluationErr
}

func unfinishedCandidateEvaluations(states []*candidateRuleEvaluationState, first *candidateRuleEvaluationState) []*candidateRuleEvaluationState {
	for index, state := range states {
		if state == first {
			return states[index:]
		}
	}
	return nil
}

func ruleEvaluationStatesFromCandidateStates(states []*candidateRuleEvaluationState) []*ruleEvaluationState {
	out := make([]*ruleEvaluationState, 0, len(states))
	for _, state := range states {
		if state == nil {
			continue
		}
		out = append(out, &ruleEvaluationState{rule: state.rule})
	}
	return out
}

func rulesFromCandidateStates(states []*candidateRuleEvaluationState) []Rule {
	out := make([]Rule, 0, len(states))
	for _, state := range states {
		if state == nil || state.rule == nil {
			continue
		}
		out = append(out, state.rule)
	}
	return out
}

func cloneFindingRecord(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	cloned := *finding
	cloned.ResourceURNs = append([]string(nil), finding.ResourceURNs...)
	cloned.EventIDs = append([]string(nil), finding.EventIDs...)
	cloned.ObservedPolicyIDs = append([]string(nil), finding.ObservedPolicyIDs...)
	cloned.ControlRefs = append([]ports.FindingControlRef(nil), finding.ControlRefs...)
	cloned.GraphEvidenceRows = cloneGraphEvidenceRows(finding.GraphEvidenceRows)
	cloned.RiskReasons = append([]string(nil), finding.RiskReasons...)
	cloned.RiskFactors = append([]ports.FindingRiskFactor(nil), finding.RiskFactors...)
	cloned.Notes = append([]ports.FindingNote(nil), finding.Notes...)
	cloned.Tickets = append([]ports.FindingTicket(nil), finding.Tickets...)
	if finding.Attributes != nil {
		cloned.Attributes = make(map[string]string, len(finding.Attributes))
		for key, value := range finding.Attributes {
			cloned.Attributes[key] = value
		}
	}
	return &cloned
}
