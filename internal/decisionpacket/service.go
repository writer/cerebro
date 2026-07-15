package decisionpacket

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
)

var ErrInvalidRequest = errors.New("invalid decision packet request")

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type Service struct {
	resolver Resolver
	clock    Clock
}

func NewService(resolver Resolver, clock Clock) *Service {
	if clock == nil {
		clock = SystemClock{}
	}
	return &Service{resolver: resolver, clock: clock}
}

func (s *Service) Build(ctx context.Context, tenant AuthorizedTenant, actor AuthorizedActor, request Request) (*Packet, error) {
	if s == nil || s.resolver == nil {
		return nil, fmt.Errorf("%w: resolver is required", ErrResolverUnavailable)
	}
	tenant.ID = strings.TrimSpace(tenant.ID)
	actor.ID = strings.TrimSpace(actor.ID)
	if tenant.ID == "" || actor.ID == "" {
		return nil, fmt.Errorf("%w: authenticated tenant and actor are required", ErrInvalidRequest)
	}
	request, err := NormalizeRequest(request)
	if err != nil {
		return nil, err
	}
	if request.Workflow == "" || request.Question == "" {
		return nil, fmt.Errorf("%w: workflow and question are required", ErrInvalidRequest)
	}
	if request.ScopeURN != "" && !tenantScopedURN(tenant.ID, request.ScopeURN) {
		return nil, ErrProtectedReference
	}

	facts, err := s.resolver.Resolve(ctx, tenant, request)
	if err != nil {
		return nil, err
	}
	if err := validateResolvedFacts(tenant.ID, facts); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	facts = normalizeResolvedFacts(facts)
	rawFacts := facts
	allContradictions := DetectContradictions(rawFacts.Observations)
	truncated := resultIsTruncated(rawFacts, len(allContradictions), request.Budgets)
	facts = boundResolvedFacts(facts, request.Budgets)
	contradictions := boundSlice(allContradictions, request.Budgets.Contradictions)
	coverage := coverageContext(tenant.ID, facts.CoverageGaps, now)
	guardrails := agentplatform.BuildAgentDecisionGuardrails(agentplatform.EvidencePacketRequest{
		TenantID: tenant.ID, ActorID: actor.ID, Question: request.Question, ScopeURN: request.ScopeURN,
		CapabilityIDs:   []string{"graph-reasoning", "knowledge-provenance"},
		RequestedScopes: actor.Scopes, CoverageContext: coverage,
		Action:      agentplatform.EvidencePacketAction{Stage: agentplatform.ActionStageRecommend},
		GeneratedAt: now.Format(time.RFC3339Nano),
	})
	claim := buildResolvedClaim(tenant.ID, actor.ID, request, facts, contradictions, coverage)
	requiredGap, requiredStale, requiredUnverified, optionalGapMatters := gapFlags(facts.CoverageGaps)
	primaryConflict := hasPrimaryConflict(contradictions)
	decision := DeriveDecision(DecisionInputs{
		ClaimVerdict: claim.Verdict, Applicable: facts.Applicable, RequiredGap: requiredGap,
		RequiredStale: requiredStale, PrimaryConflict: primaryConflict, OutcomeTruncated: truncated,
	})
	decision.Rationale = strings.TrimSpace(facts.Rationale)
	confidence := DeriveConfidence(ConfidenceInputs{
		SupportingEvidence: len(facts.Evidence), RequiredGap: requiredGap, RequiredStale: requiredStale,
		RequiredUnverified: requiredUnverified, UnresolvedConflict: len(contradictions) > 0,
		OptionalGapMatters: optionalGapMatters, OutcomeTruncated: truncated,
		GuardrailsPassed: guardrails.Readiness.State != agentplatform.AgentReadinessBlocked,
	})
	packet := Packet{
		SchemaVersion: SchemaVersion, GeneratedAt: now,
		Workflow:   Workflow{ID: request.Workflow, Question: request.Question},
		Scope:      Scope{TenantID: tenant.ID, ActorID: actor.ID, URN: request.ScopeURN},
		Guardrails: guardrails, Claim: claim, Decision: decision, Confidence: confidence,
		Freshness: deriveFreshness(facts.Evidence, requiredStale), Evidence: facts.Evidence,
		Contradictions: contradictions, CoverageGaps: facts.CoverageGaps, Affected: facts.Affected,
		Controls: facts.Controls, AuditPackets: facts.AuditPackets, Actions: safeActions(facts.Actions, decision.State),
		Provenance: Provenance{ResolverIDs: facts.ResolverIDs, SourceIDs: facts.SourceIDs},
		Limits:     resultLimits(rawFacts, len(allContradictions), request.Budgets),
	}
	packet, _, err = CanonicalizePacket(packet)
	if err != nil {
		return nil, err
	}
	return &packet, nil
}

func validateResolvedFacts(tenantID string, facts ResolvedFacts) error {
	for _, evidence := range facts.Evidence {
		if (evidence.URN != "" && !tenantScopedURN(tenantID, evidence.URN)) || (evidence.SubjectURN != "" && !tenantScopedURN(tenantID, evidence.SubjectURN)) {
			return ErrProtectedReference
		}
	}
	for _, observation := range facts.Observations {
		if observation.TenantID != tenantID || (observation.SubjectURN != "" && !tenantScopedURN(tenantID, observation.SubjectURN)) {
			return ErrProtectedReference
		}
	}
	for _, subject := range facts.Affected {
		if !tenantScopedURN(tenantID, subject.URN) {
			return ErrProtectedReference
		}
	}
	for _, action := range facts.Actions {
		switch action.State {
		case ActionInformational, ActionStateProposal, ActionApprovalRequired:
		default:
			return fmt.Errorf("%w: unsupported action proposal state", ErrInvalidRequest)
		}
		for _, target := range action.TargetURNs {
			if strings.HasPrefix(target, "urn:cerebro:") && !tenantScopedURN(tenantID, target) {
				return ErrProtectedReference
			}
		}
	}
	return nil
}

func buildResolvedClaim(tenantID, actorID string, request Request, facts ResolvedFacts, contradictions []Contradiction, coverage *agentplatform.AgentCoverageContext) agentplatform.ClaimVerification {
	supporting := make([]string, 0, len(facts.Evidence))
	for _, evidence := range facts.Evidence {
		supporting = append(supporting, evidenceURN(tenantID, evidence))
	}
	counter := []string{}
	for _, contradiction := range contradictions {
		counter = append(counter, evidenceURN(tenantID, contradiction.Right))
	}
	missing := []string{}
	for _, gap := range facts.CoverageGaps {
		if gap.Required {
			missing = append(missing, gap.ID)
		}
	}
	freshness := "fresh"
	_, requiredStale, _, _ := gapFlags(facts.CoverageGaps)
	if requiredStale {
		freshness = "stale"
	}
	return agentplatform.BuildClaimVerification(agentplatform.ClaimVerificationRequest{
		TenantID: tenantID, ActorID: actorID, Claim: request.Question, ClaimType: request.Workflow,
		ScopeURN: request.ScopeURN, SupportingEvidenceURNs: supporting, CounterEvidenceURNs: counter,
		MissingEvidence: missing, FreshnessState: freshness, CoverageContext: coverage,
		RequestedActionStage: agentplatform.ActionStageRecommend,
	})
}

func boundResolvedFacts(facts ResolvedFacts, budgets Budgets) ResolvedFacts {
	facts.Evidence = boundSlice(facts.Evidence, budgets.Evidence)
	facts.CoverageGaps = boundSlice(facts.CoverageGaps, budgets.CoverageGaps)
	facts.Affected = boundSlice(facts.Affected, budgets.Affected)
	facts.Controls = boundSlice(facts.Controls, budgets.Controls)
	facts.AuditPackets = boundSlice(facts.AuditPackets, budgets.AuditPackets)
	facts.Actions = boundSlice(facts.Actions, budgets.Actions)
	return facts
}

func normalizeResolvedFacts(facts ResolvedFacts) ResolvedFacts {
	for index := range facts.Evidence {
		facts.Evidence[index] = normalizeEvidenceReference(facts.Evidence[index])
	}
	facts.Evidence = dedupeEvidence(facts.Evidence)
	sort.Slice(facts.CoverageGaps, func(i, j int) bool { return facts.CoverageGaps[i].ID < facts.CoverageGaps[j].ID })
	facts.CoverageGaps = dedupeByKey(facts.CoverageGaps, func(value CoverageGap) string { return value.ID })
	sort.Slice(facts.Affected, func(i, j int) bool { return facts.Affected[i].URN < facts.Affected[j].URN })
	facts.Affected = dedupeByKey(facts.Affected, func(value SubjectReference) string { return value.URN })
	sort.Slice(facts.Controls, func(i, j int) bool { return facts.Controls[i].ID < facts.Controls[j].ID })
	facts.Controls = dedupeByKey(facts.Controls, func(value ControlReference) string { return value.Framework + "\x00" + value.ID })
	sort.Slice(facts.AuditPackets, func(i, j int) bool { return facts.AuditPackets[i].ID < facts.AuditPackets[j].ID })
	facts.AuditPackets = dedupeByKey(facts.AuditPackets, func(value AuditPacketReference) string { return value.ID })
	sort.Slice(facts.Actions, func(i, j int) bool { return facts.Actions[i].ID < facts.Actions[j].ID })
	facts.Actions = dedupeByKey(facts.Actions, func(value ActionProposal) string { return value.ID })
	facts.ResolverIDs = normalizeStrings(facts.ResolverIDs)
	facts.SourceIDs = normalizeStrings(facts.SourceIDs)
	return facts
}

func dedupeByKey[T any](values []T, key func(T) string) []T {
	result := make([]T, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		itemKey := key(value)
		if _, found := seen[itemKey]; found {
			continue
		}
		seen[itemKey] = struct{}{}
		result = append(result, value)
	}
	return result
}

func boundSlice[T any](values []T, limit int) []T {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func coverageContext(tenantID string, gaps []CoverageGap, now time.Time) *agentplatform.AgentCoverageContext {
	context := &agentplatform.AgentCoverageContext{Version: agentplatform.ContractVersion, TenantID: tenantID, GeneratedAt: now.Format(time.RFC3339Nano)}
	for _, gap := range gaps {
		context.TotalDimensions++
		switch gap.State {
		case CoveragePartial:
			context.PartialCount++
		case CoverageStale:
			context.StaleCount++
		case CoverageFailed:
			context.FailedCount++
		case CoverageUnsupported:
			context.UnsupportedCount++
		case CoverageUnconfigured:
			context.UnconfiguredCount++
		}
		context.BlindSpotCount++
	}
	return context
}

func gapFlags(gaps []CoverageGap) (requiredGap, requiredStale, requiredUnverified, optionalGapMatters bool) {
	for _, gap := range gaps {
		if gap.Required {
			requiredGap = true
			requiredStale = requiredStale || gap.State == CoverageStale
			requiredUnverified = requiredUnverified || gap.State == CoverageUnverified
		} else if gap.CouldChangeConclusion {
			optionalGapMatters = true
		}
	}
	return requiredGap, requiredStale, requiredUnverified, optionalGapMatters
}

func hasPrimaryConflict(values []Contradiction) bool {
	for _, value := range values {
		if value.PrimaryClaim && value.ResolutionState == ContradictionUnresolved {
			return true
		}
	}
	return false
}

func safeActions(actions []ActionProposal, decisionState string) []ActionProposal {
	result := append([]ActionProposal(nil), actions...)
	if decisionState == DecisionBlocked || decisionState == DecisionInsufficientEvidence {
		for index := range result {
			result[index].State = ActionInformational
			result[index].ApprovalRequirements = nil
		}
	}
	return result
}

func deriveFreshness(evidence []EvidenceReference, requiredStale bool) Freshness {
	result := Freshness{State: "unknown", RequiredStale: requiredStale}
	for _, item := range evidence {
		if item.ObservedAt.IsZero() {
			continue
		}
		if result.OldestObservedAt.IsZero() || item.ObservedAt.Before(result.OldestObservedAt) {
			result.OldestObservedAt = item.ObservedAt
		}
		if result.NewestObservedAt.IsZero() || item.ObservedAt.After(result.NewestObservedAt) {
			result.NewestObservedAt = item.ObservedAt
		}
	}
	if !result.NewestObservedAt.IsZero() {
		result.State = "fresh"
	}
	if requiredStale {
		result.State = "stale"
	}
	return result
}

func evidenceURN(tenantID string, evidence EvidenceReference) string {
	if evidence.URN != "" {
		return evidence.URN
	}
	return "urn:cerebro:" + tenantID + ":evidence:" + evidence.ID
}

func tenantScopedURN(tenantID, urn string) bool {
	return strings.HasPrefix(strings.TrimSpace(urn), "urn:cerebro:"+tenantID+":")
}

func resultLimits(facts ResolvedFacts, contradictionCount int, budgets Budgets) ResultLimits {
	return ResultLimits{
		Evidence: limitOf(len(facts.Evidence), budgets.Evidence), Contradictions: limitOf(contradictionCount, budgets.Contradictions),
		CoverageGaps: limitOf(len(facts.CoverageGaps), budgets.CoverageGaps), Affected: limitOf(len(facts.Affected), budgets.Affected),
		Controls: limitOf(len(facts.Controls), budgets.Controls), AuditPackets: limitOf(len(facts.AuditPackets), budgets.AuditPackets),
		Actions: limitOf(len(facts.Actions), budgets.Actions), GraphRows: ResultLimit{Requested: budgets.GraphRows, Applied: budgets.GraphRows},
		GraphDepth: ResultLimit{Requested: budgets.GraphDepth, Applied: budgets.GraphDepth},
	}
}

func limitOf(count, limit int) ResultLimit {
	return ResultLimit{Requested: limit, Applied: limit, Returned: min(count, limit), TotalKnown: count, Truncated: count > limit}
}

func resultIsTruncated(facts ResolvedFacts, contradictionCount int, budgets Budgets) bool {
	return len(facts.Evidence) > budgets.Evidence || contradictionCount > budgets.Contradictions || len(facts.CoverageGaps) > budgets.CoverageGaps || len(facts.Affected) > budgets.Affected || len(facts.Controls) > budgets.Controls || len(facts.AuditPackets) > budgets.AuditPackets || len(facts.Actions) > budgets.Actions
}
