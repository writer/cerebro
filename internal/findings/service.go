package findings

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findingevidence"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
	"github.com/writer/cerebro/internal/workflowevents"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultEventLimit       = 100
	maxEventLimit           = 1000
	defaultListLimit        = uint32(500)
	maxListLimit            = uint32(500)
	defaultEvidenceClaimCap = 100
	findingStatusOpen       = "open"
	findingStatusResolved   = "resolved"
	findingStatusSuppressed = "suppressed"

	findingAttributeLegacyID          = "legacy_finding_id"
	findingAttributeLegacyFingerprint = "legacy_fingerprint"
)

var (
	// ErrRuntimeUnavailable indicates that the runtime, replay, or finding store boundary is unavailable.
	ErrRuntimeUnavailable = errors.New("finding runtime is unavailable")

	// ErrInvalidRequest indicates that a finding request failed validation.
	ErrInvalidRequest = errors.New("invalid finding request")

	// ErrRuleNotFound indicates that one requested finding rule is not registered.
	ErrRuleNotFound = errors.New("finding rule not found")

	// ErrRuleSelectionRequired indicates that one finding rule must be selected explicitly.
	ErrRuleSelectionRequired = errors.New("finding rule id is required")

	// ErrRuleUnsupported indicates that one finding rule does not support the requested runtime.
	ErrRuleUnsupported = errors.New("finding rule is not supported for source runtime")

	// ErrRuleUnavailable indicates that no registered finding rule supports the requested runtime.
	ErrRuleUnavailable = errors.New("finding rule is unavailable for source runtime")
)

// Service replays runtime events through one selected finding rule and persists emitted findings.
//
// The service intentionally selects one rule per call so the returned RuleSpec, persisted
// fingerprints, and runtime-level lineage all stay explicit instead of collapsing into an
// opaque multi-rule batch.
type Service struct {
	runtimeStore              ports.SourceRuntimeStore
	replayer                  ports.EventReplayer
	store                     ports.FindingStore
	runStore                  ports.FindingEvaluationRunStore
	evidenceStore             ports.FindingEvidenceStore
	candidateStore            ports.FindingCandidateStore
	claimStore                ports.ClaimStore
	graphQuery                ports.GraphQueryStore
	graph                     ports.ProjectionGraphStore
	appendLog                 ports.AppendLog
	closeoutStore             ports.CloseoutRunStore
	tombstoneEventStore       ports.FindingTombstoneEventStore
	closeoutHeartbeatInterval time.Duration
	rules                     *Registry
	ttlClock                  ttlClock
	ttlLogSink                ttlLogSink
}

// EvaluateRequest scopes one replay-backed finding evaluation.
type EvaluateRequest struct {
	RuntimeID  string
	RuleID     string
	EventLimit uint32
}

// EvaluateRulesRequest scopes one replay-backed multi-rule evaluation.
type EvaluateRulesRequest struct {
	RuntimeID  string
	RuleIDs    []string
	EventLimit uint32
}

// ListRequest scopes one persisted finding query.
type ListRequest struct {
	RuntimeID   string
	FindingID   string
	RuleID      string
	Severity    string
	Status      string
	ResourceURN string
	EventID     string
	PolicyID    string
	Limit       uint32
	Order       ports.FindingOrder
}

// EvaluateResult reports the persisted findings emitted for one runtime evaluation.
type EvaluateResult struct {
	Runtime         *cerebrov1.SourceRuntime
	Rule            *cerebrov1.RuleSpec
	EventsEvaluated uint32
	Findings        []*ports.FindingRecord
	Run             *cerebrov1.FindingEvaluationRun
	Evidence        []*cerebrov1.FindingEvidence
}

// RuleEvaluationResult reports one rule's outputs inside a multi-rule evaluation pass.
type RuleEvaluationResult struct {
	Rule     *cerebrov1.RuleSpec
	Findings []*ports.FindingRecord
	Run      *cerebrov1.FindingEvaluationRun
	Evidence []*cerebrov1.FindingEvidence
}

// EvaluateRulesResult reports one multi-rule evaluation over one runtime replay.
type EvaluateRulesResult struct {
	Runtime         *cerebrov1.SourceRuntime
	EventsEvaluated uint32
	Evaluations     []*RuleEvaluationResult
}

// ListResult reports one persisted finding query.
type ListResult struct {
	Findings []*ports.FindingRecord
}

// ListEvaluationRunsRequest scopes one persisted finding evaluation run query.
type ListEvaluationRunsRequest struct {
	RuntimeID string
	RuleID    string
	Status    string
	Limit     uint32
}

// ListEvaluationRunsResult reports one persisted finding evaluation run query.
type ListEvaluationRunsResult struct {
	Runs []*cerebrov1.FindingEvaluationRun
}

// ListEvidenceRequest scopes one persisted finding evidence query.
type ListEvidenceRequest struct {
	RuntimeID    string
	FindingID    string
	RunID        string
	RuleID       string
	ClaimID      string
	EventID      string
	GraphRootURN string
	GraphPathURN string
	Limit        uint32
}

// ListEvidenceResult reports one persisted finding evidence query.
type ListEvidenceResult struct {
	Evidence []*cerebrov1.FindingEvidence
}

// New constructs a replay-backed finding service with the built-in rule registry.
func New(
	runtimeStore ports.SourceRuntimeStore,
	replayer ports.EventReplayer,
	store ports.FindingStore,
	runStore ports.FindingEvaluationRunStore,
	evidenceStore ports.FindingEvidenceStore,
	claimStore ports.ClaimStore,
) *Service {
	return NewWithRegistry(runtimeStore, replayer, store, runStore, evidenceStore, claimStore, Builtin())
}

// NewWithRegistry constructs a replay-backed finding service with one explicit rule registry.
func NewWithRegistry(
	runtimeStore ports.SourceRuntimeStore,
	replayer ports.EventReplayer,
	store ports.FindingStore,
	runStore ports.FindingEvaluationRunStore,
	evidenceStore ports.FindingEvidenceStore,
	claimStore ports.ClaimStore,
	rules *Registry,
) *Service {
	return &Service{
		runtimeStore:  runtimeStore,
		replayer:      replayer,
		store:         store,
		runStore:      runStore,
		evidenceStore: evidenceStore,
		claimStore:    claimStore,
		rules:         rules,
	}
}

// WithGraphStore wires one optional graph projection boundary used for workflow metadata.
func (s *Service) WithGraphStore(graph ports.ProjectionGraphStore) *Service {
	if s == nil {
		return nil
	}
	s.graph = graph
	return s
}

// WithGraphQueryStore wires one optional graph query boundary used by workflow bridges.
func (s *Service) WithGraphQueryStore(graphQuery ports.GraphQueryStore) *Service {
	if s == nil {
		return nil
	}
	s.graphQuery = graphQuery
	return s
}

// WithAppendLog wires one optional durable append log used for workflow metadata events.
func (s *Service) WithAppendLog(appendLog ports.AppendLog) *Service {
	if s == nil {
		return nil
	}
	s.appendLog = appendLog
	return s
}

// WithFindingCandidateStore wires the isolated candidate-finding persistence
// boundary. Candidate evaluations do not write production findings until an
// explicit promotion call uses the production store.
func (s *Service) WithFindingCandidateStore(store ports.FindingCandidateStore) *Service {
	if s == nil {
		return nil
	}
	s.candidateStore = store
	return s
}

// WithCloseoutStore wires one optional closeout_run lifecycle boundary used by the bulk
// tombstone primitive (TombstoneFindingsBulk). When unset the bulk primitive refuses to run.
func (s *Service) WithCloseoutStore(store ports.CloseoutRunStore) *Service {
	if s == nil {
		return nil
	}
	s.closeoutStore = store
	return s
}

// WithFindingTombstoneEventStore wires one optional finding_tombstone_events audit boundary
// used by the bulk tombstone primitive (TombstoneFindingsBulk). When unset the bulk primitive
// refuses to run.
func (s *Service) WithFindingTombstoneEventStore(store ports.FindingTombstoneEventStore) *Service {
	if s == nil {
		return nil
	}
	s.tombstoneEventStore = store
	return s
}

// ListRules returns the discoverable registered finding rule catalog. Graph rules are hidden
// from the public catalog: every public evaluation handler (`EvaluateSourceRuntimeRules`,
// `EvaluateSourceRuntime`) rejects them, so advertising their ids would let clients discover
// rules they cannot run. Graph rules execute exclusively from the orchestrator hook.
func (s *Service) ListRules() *cerebrov1.ListFindingRulesResponse {
	if s == nil || s.rules == nil {
		return &cerebrov1.ListFindingRulesResponse{}
	}
	specs := s.rules.List()
	publicSpecs := make([]*cerebrov1.RuleSpec, 0, len(specs))
	for _, spec := range specs {
		rule, ok := s.rules.Get(spec.GetId())
		if !ok {
			continue
		}
		if _, isGraph := asGraphRule(rule); isGraph {
			continue
		}
		publicSpecs = append(publicSpecs, spec)
	}
	return &cerebrov1.ListFindingRulesResponse{
		Rules: publicSpecs,
	}
}

// EvaluateSourceRuntime replays one runtime and persists findings for one selected registered rule.
func (s *Service) EvaluateSourceRuntime(ctx context.Context, request EvaluateRequest) (*EvaluateResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.claimStore == nil || s.rules == nil {
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
	rule, err := s.selectRule(ctx, runtime, request.RuleID)
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return nil, fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	var events []*cerebrov1.EventEnvelope
	if rule.SupportsRuntime(runtime) {
		events, err = s.replayer.Replay(ctx, ports.ReplayRequest{
			RuntimeID: runtimeID,
			Limit:     normalizedLimit,
		})
		if err != nil {
			evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
			return nil, s.finishFailedRun(ctx, run, 0, 0, nil, evaluationErr)
		}
	}
	result := &EvaluateResult{
		Runtime: runtime,
		Rule:    rule.Spec(),
		Run:     run,
	}
	evidenceIDs := map[string]struct{}{}
	evaluatedEventIDs := map[string]struct{}{}
	emittedFindingIDs := map[string]struct{}{}
	var eventsMatched uint32
	for _, event := range events {
		if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
			evaluatedEventIDs[eventID] = struct{}{}
		}
		emitted, err := rule.Evaluate(ctx, runtime, event)
		if err != nil {
			evaluationErr := fmt.Errorf("evaluate finding rule %q for event %q: %w", result.Rule.GetId(), event.GetId(), err)
			return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
		}
		result.EventsEvaluated++
		matchedEvent := false
		for _, record := range emitted {
			if record == nil {
				continue
			}
			if !matchedEvent {
				eventsMatched++
				matchedEvent = true
			}
			record, err = s.reconcileLegacyFindingIdentity(ctx, record)
			if err != nil {
				evaluationErr := fmt.Errorf("reconcile finding identity for rule %q event %q: %w", result.Rule.GetId(), event.GetId(), err)
				return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
			}
			stored, isNewFinding, err := s.upsertFindingWithRiskAndNewness(ctx, record, runtime, startedAt)
			if err != nil {
				evaluationErr := fmt.Errorf("persist finding for rule %q event %q: %w", result.Rule.GetId(), event.GetId(), err)
				return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
			}
			result.Findings = append(result.Findings, stored)
			emittedFindingIDs[strings.TrimSpace(stored.ID)] = struct{}{}
			evidence, err := s.buildFindingEvidence(ctx, stored, run)
			if err != nil {
				evaluationErr := fmt.Errorf("build evidence for finding %q: %w", stored.ID, err)
				return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
			}
			if _, seen := evidenceIDs[evidence.GetId()]; !seen {
				if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
					evaluationErr := fmt.Errorf("persist evidence for finding %q: %w", stored.ID, err)
					return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
				}
				evidenceIDs[evidence.GetId()] = struct{}{}
				result.Evidence = append(result.Evidence, evidence)
			}
			if err := s.projectFindingAnchor(ctx, stored); err != nil {
				evaluationErr := fmt.Errorf("project finding %q graph anchor: %w", stored.ID, err)
				return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
			}
			if err := s.projectFindingExternalRefs(ctx, stored); err != nil {
				evaluationErr := fmt.Errorf("project finding %q external refs: %w", stored.ID, err)
				return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
			}
			if isNewFinding {
				if err := s.projectFindingNewActionRecommendations(ctx, stored); err != nil {
					evaluationErr := fmt.Errorf("project finding %q action recommendations: %w", stored.ID, err)
					return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
				}
			}
		}
	}
	resolvedCounterFindings, err := s.resolveRuleOpenFindings(ctx, runtime, rule, events, evaluatedEventIDs, emittedFindingIDs)
	if err != nil {
		evaluationErr := fmt.Errorf("resolve stale findings for rule %q: %w", result.Rule.GetId(), err)
		return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
	}
	if err := s.applyCounterEventResolutionResults(ctx, run, result.Findings, &result.Evidence, evidenceIDs, resolvedCounterFindings); err != nil {
		evaluationErr := fmt.Errorf("persist counter-event close evidence for rule %q: %w", result.Rule.GetId(), err)
		return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
	}
	if err := s.finishCompletedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings)); err != nil {
		return nil, err
	}
	return result, nil
}

// EvaluateSourceRuntimeRules replays one runtime once and evaluates one or more registered rules over that shared pass.
func (s *Service) EvaluateSourceRuntimeRules(ctx context.Context, request EvaluateRulesRequest) (*EvaluateRulesResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.claimStore == nil || s.rules == nil {
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
	states := make([]*ruleEvaluationState, 0, len(rules))
	result := &EvaluateRulesResult{
		Runtime:     runtime,
		Evaluations: make([]*RuleEvaluationResult, 0, len(rules)),
	}
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	for _, rule := range rules {
		run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
		if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
			evaluationErr := fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
			return nil, s.markRuleEvaluationsFailed(ctx, states, evaluationErr)
		}
		state := &ruleEvaluationState{
			rule:              rule,
			evidenceIDs:       map[string]struct{}{},
			emittedFindingIDs: map[string]struct{}{},
			result: &RuleEvaluationResult{
				Rule: rule.Spec(),
				Run:  run,
			},
		}
		states = append(states, state)
		result.Evaluations = append(result.Evaluations, state.result)
	}
	var events []*cerebrov1.EventEnvelope
	if rulesNeedReplay(runtime, states) {
		events, err = s.replayer.Replay(ctx, ports.ReplayRequest{
			RuntimeID: runtimeID,
			Limit:     normalizedLimit,
		})
		if err != nil {
			evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
			return nil, s.markRuleEvaluationsFailed(ctx, states, evaluationErr)
		}
	}
	result.EventsEvaluated = boundedUint32(len(events))
	evaluatedEventIDs := map[string]struct{}{}
	for _, event := range events {
		if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
			evaluatedEventIDs[eventID] = struct{}{}
		}
		for _, state := range states {
			if state.failed || !state.rule.SupportsRuntime(runtime) {
				continue
			}
			emitted, err := state.rule.Evaluate(ctx, runtime, event)
			if err != nil {
				if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("evaluate finding rule %q for event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
					return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
				}
				continue
			}
			state.eventsEvaluated++
			matchedEvent := false
			for _, record := range emitted {
				if record == nil {
					continue
				}
				if !matchedEvent {
					state.eventsMatched++
					matchedEvent = true
				}
				record, err = s.reconcileLegacyFindingIdentity(ctx, record)
				if err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("reconcile finding identity for rule %q event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				stored, isNewFinding, err := s.upsertFindingWithRiskAndNewness(ctx, record, runtime, startedAt)
				if err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("persist finding for rule %q event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				state.result.Findings = append(state.result.Findings, stored)
				state.emittedFindingIDs[strings.TrimSpace(stored.ID)] = struct{}{}
				evidence, err := s.buildFindingEvidence(ctx, stored, state.result.Run)
				if err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("build evidence for finding %q: %w", stored.ID, err)); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				if _, seen := state.evidenceIDs[evidence.GetId()]; !seen {
					if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
						if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("persist evidence for finding %q: %w", stored.ID, err)); failErr != nil {
							return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
						}
						break
					}
					state.evidenceIDs[evidence.GetId()] = struct{}{}
					state.result.Evidence = append(state.result.Evidence, evidence)
				}
				if err := s.projectFindingAnchor(ctx, stored); err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("project finding %q graph anchor: %w", stored.ID, err)); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				if err := s.projectFindingExternalRefs(ctx, stored); err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("project finding %q external refs: %w", stored.ID, err)); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
					}
					break
				}
				if isNewFinding {
					if err := s.projectFindingNewActionRecommendations(ctx, stored); err != nil {
						if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("project finding %q action recommendations: %w", stored.ID, err)); failErr != nil {
							return nil, s.markRuleEvaluationsFailed(ctx, states, failErr)
						}
						break
					}
				}
			}
		}
	}
	for _, state := range states {
		if state.failed {
			continue
		}
		resolvedCounterFindings, err := s.resolveRuleOpenFindings(ctx, runtime, state.rule, events, evaluatedEventIDs, state.emittedFindingIDs)
		if err != nil {
			evaluationErr := fmt.Errorf("resolve stale findings for rule %q: %w", state.result.Rule.GetId(), err)
			return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), evaluationErr)
		}
		if err := s.applyCounterEventResolutionResults(ctx, state.result.Run, state.result.Findings, &state.result.Evidence, state.evidenceIDs, resolvedCounterFindings); err != nil {
			evaluationErr := fmt.Errorf("persist counter-event close evidence for rule %q: %w", state.result.Rule.GetId(), err)
			return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), evaluationErr)
		}
		if err := s.finishCompletedRun(ctx, state.result.Run, state.eventsEvaluated, state.eventsMatched, findingIDs(state.result.Findings)); err != nil {
			return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), err)
		}
	}
	return result, nil
}

func rulesNeedReplay(runtime *cerebrov1.SourceRuntime, states []*ruleEvaluationState) bool {
	for _, state := range states {
		if state != nil && state.rule != nil && state.rule.SupportsRuntime(runtime) {
			return true
		}
	}
	return false
}

// ListFindings loads persisted findings for one runtime.
func (s *Service) ListFindings(ctx context.Context, request ListRequest) (*ListResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil {
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
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:    strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID:   runtimeID,
		FindingID:   strings.TrimSpace(request.FindingID),
		RuleID:      strings.TrimSpace(request.RuleID),
		Severity:    strings.TrimSpace(request.Severity),
		Status:      strings.TrimSpace(request.Status),
		ResourceURN: strings.TrimSpace(request.ResourceURN),
		EventID:     strings.TrimSpace(request.EventID),
		PolicyID:    strings.TrimSpace(request.PolicyID),
		Limit:       normalizeListLimit(request.Limit),
		Order:       request.Order,
	})
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtime %q: %w", strings.TrimSpace(runtime.GetTenantId()), runtimeID, err)
	}
	return &ListResult{Findings: findings}, nil
}

type openFindingRetirementRule interface {
	RetiresOpenFindings() bool
}

func (s *Service) resolveRetiredOpenFindings(ctx context.Context, tenantID string, runtimeID string, ruleID string, emittedFindingIDs map[string]struct{}) error {
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list retired candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		if _, emitted := emittedFindingIDs[strings.TrimSpace(finding.ID)]; emitted {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve retired finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project retired finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

func (s *Service) resolveStaleOpenFindings(ctx context.Context, tenantID string, runtimeID string, ruleID string, evaluatedEventIDs map[string]struct{}, emittedFindingIDs map[string]struct{}) error {
	if len(evaluatedEventIDs) == 0 {
		return nil
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list stale candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		if _, emitted := emittedFindingIDs[strings.TrimSpace(finding.ID)]; emitted {
			continue
		}
		if !findingReferencesEvaluatedEvent(finding, evaluatedEventIDs) {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve stale finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project stale finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

type counterAnchorLatestEvent struct {
	observedAt time.Time
	sequence   int
	closes     bool
	eventIDs   []string
}

func (s *Service) resolveCounterEventOpenFindings(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, counterRule CounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if counterRule == nil || runtime == nil || rule == nil || len(evaluatedEvents) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	ruleID := ""
	if spec := rule.Spec(); spec != nil {
		ruleID = strings.TrimSpace(spec.GetId())
	}
	latestByAnchor, err := latestCounterAnchorEvents(ctx, runtime, rule, counterRule, evaluatedEvents)
	if err != nil {
		return nil, err
	}
	if !hasLatestCounterAnchorClose(latestByAnchor) {
		return nil, nil
	}
	listRequest := ports.ListFindingsRequest{
		TenantID: tenantID,
		RuleID:   ruleID,
		Status:   findingStatusOpen,
	}
	if counterEventCloseLookupRuntimeScoped(rule) {
		listRequest.RuntimeID = runtimeID
	}
	findings, err := s.store.ListFindings(ctx, listRequest)
	if err != nil {
		return nil, fmt.Errorf("list counter-event candidates for rule %q: %w", ruleID, err)
	}
	resolved := []*ports.FindingRecord{}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		openAnchor := strings.TrimSpace(counterRule.OpenAnchor(finding.Attributes))
		if openAnchor == "" {
			continue
		}
		latest, ok := latestByAnchor[openAnchor]
		if !ok || !latest.closes {
			continue
		}
		if counterAnchorClosePrecedesFinding(latest, finding) {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonClosedByCounterEvent,
			UpdatedAt: time.Now().UTC(),
			EventIDs:  uniqueTrimmedStringsPreserveOrder(latest.eventIDs),
		})
		if err != nil {
			return nil, fmt.Errorf("resolve counter-event finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return nil, fmt.Errorf("project counter-event finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
		resolved = append(resolved, updated)
	}
	return resolved, nil
}

func latestCounterAnchorEvents(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, counterRule CounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) (map[string]counterAnchorLatestEvent, error) {
	if aggregateRule, ok := counterRule.(AggregateCounterEventRule); ok {
		if latestByAnchor, handled := latestAggregateCounterAnchorEvents(aggregateRule, evaluatedEvents); handled {
			return latestByAnchor, nil
		}
	}
	latestByAnchor := make(map[string]counterAnchorLatestEvent)
	ruleID := ""
	if spec := rule.Spec(); spec != nil {
		ruleID = strings.TrimSpace(spec.GetId())
	}
	for sequence, event := range evaluatedEvents {
		if event == nil {
			continue
		}
		observedAt := counterAnchorEventObservedAt(event)
		records, err := rule.Evaluate(ctx, runtime, event)
		if err != nil {
			return nil, fmt.Errorf("evaluate counter-event chronology for rule %q event %q: %w", ruleID, strings.TrimSpace(event.GetId()), err)
		}
		for _, record := range records {
			if record == nil {
				continue
			}
			openAnchor := strings.TrimSpace(counterRule.OpenAnchor(record.Attributes))
			if openAnchor == "" {
				continue
			}
			recordLatestCounterAnchorEvent(latestByAnchor, openAnchor, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
			})
		}
		anchor, closes := counterRule.CloseOnEvent(event)
		anchor = strings.TrimSpace(anchor)
		if closes && anchor != "" {
			eventIDs := []string(nil)
			if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
				eventIDs = []string{eventID}
			}
			recordLatestCounterAnchorEvent(latestByAnchor, anchor, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
				closes:     true,
				eventIDs:   eventIDs,
			})
		}
	}
	return latestByAnchor, nil
}

func latestAggregateCounterAnchorEvents(rule AggregateCounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) (map[string]counterAnchorLatestEvent, bool) {
	if rule == nil {
		return nil, false
	}
	latestByAnchorAndKey := map[string]map[string]counterAnchorLatestEvent{}
	handled := false
	for sequence, event := range evaluatedEvents {
		if event == nil {
			continue
		}
		observedAt := counterAnchorEventObservedAt(event)
		for _, state := range rule.CounterEventStates(event) {
			anchor := strings.TrimSpace(state.Anchor)
			key := strings.TrimSpace(state.Key)
			if anchor == "" || key == "" {
				continue
			}
			eventIDs := uniqueTrimmedStringsPreserveOrder(state.EventIDs)
			if len(eventIDs) == 0 {
				if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
					eventIDs = []string{eventID}
				}
			}
			if latestByAnchorAndKey[anchor] == nil {
				latestByAnchorAndKey[anchor] = map[string]counterAnchorLatestEvent{}
			}
			recordLatestCounterAnchorEvent(latestByAnchorAndKey[anchor], key, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
				closes:     state.Closes,
				eventIDs:   eventIDs,
			})
			handled = true
		}
	}
	if !handled {
		return nil, false
	}
	latestByAnchor := make(map[string]counterAnchorLatestEvent)
	for anchor, latestByKey := range latestByAnchorAndKey {
		if latest, ok := aggregateCounterAnchorClose(latestByKey); ok {
			latestByAnchor[anchor] = latest
		}
	}
	return latestByAnchor, true
}

func aggregateCounterAnchorClose(latestByKey map[string]counterAnchorLatestEvent) (counterAnchorLatestEvent, bool) {
	if len(latestByKey) == 0 {
		return counterAnchorLatestEvent{}, false
	}
	latestClose := counterAnchorLatestEvent{}
	eventIDs := []string{}
	for _, latest := range latestByKey {
		if !latest.closes {
			return counterAnchorLatestEvent{}, false
		}
		if !latestClose.closes || counterAnchorEventIsNewer(latest, latestClose) {
			latestClose = latest
		}
		eventIDs = append(eventIDs, latest.eventIDs...)
	}
	latestClose.closes = true
	latestClose.eventIDs = uniqueTrimmedStringsPreserveOrder(eventIDs)
	return latestClose, true
}

func recordLatestCounterAnchorEvent(latestByAnchor map[string]counterAnchorLatestEvent, anchor string, event counterAnchorLatestEvent) {
	anchor = strings.TrimSpace(anchor)
	if anchor == "" {
		return
	}
	current, ok := latestByAnchor[anchor]
	if !ok || counterAnchorEventIsNewer(event, current) {
		latestByAnchor[anchor] = event
	}
}

func counterAnchorEventIsNewer(next counterAnchorLatestEvent, current counterAnchorLatestEvent) bool {
	if !next.observedAt.Equal(current.observedAt) {
		return next.observedAt.After(current.observedAt)
	}
	return next.sequence >= current.sequence
}

func counterAnchorEventObservedAt(event *cerebrov1.EventEnvelope) time.Time {
	if event == nil || event.GetOccurredAt() == nil {
		return time.Time{}
	}
	return event.GetOccurredAt().AsTime().UTC()
}

func counterAnchorClosePrecedesFinding(event counterAnchorLatestEvent, finding *ports.FindingRecord) bool {
	if finding == nil || !event.closes || event.observedAt.IsZero() {
		return false
	}
	observedAt := finding.LastObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = finding.FirstObservedAt.UTC()
	}
	if observedAt.IsZero() {
		return false
	}
	return event.observedAt.Before(observedAt)
}

func hasLatestCounterAnchorClose(latestByAnchor map[string]counterAnchorLatestEvent) bool {
	for _, event := range latestByAnchor {
		if event.closes {
			return true
		}
	}
	return false
}

func (s *Service) resolveRuleOpenFindings(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, evaluatedEvents []*cerebrov1.EventEnvelope, evaluatedEventIDs map[string]struct{}, emittedFindingIDs map[string]struct{}) ([]*ports.FindingRecord, error) {
	if runtime == nil || rule == nil {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	ruleID := strings.TrimSpace(rule.Spec().GetId())
	if isTTLEvidenceRule(rule) {
		return nil, s.resolveTTLOpenFindings(ctx, tenantID, ruleID)
	}
	if retirementRule, ok := rule.(openFindingRetirementRule); ok && retirementRule.RetiresOpenFindings() {
		return nil, s.resolveRetiredOpenFindings(ctx, tenantID, runtimeID, ruleID, emittedFindingIDs)
	}
	if rule.SupportsRuntime(runtime) {
		var resolvedCounterFindings []*ports.FindingRecord
		if counterRule, ok := durableStateCounterEventRule(rule); ok {
			resolved, err := s.resolveCounterEventOpenFindings(ctx, runtime, rule, counterRule, evaluatedEvents)
			if err != nil {
				return nil, err
			}
			resolvedCounterFindings = resolved
		}
		if err := s.resolveStaleOpenFindings(ctx, tenantID, runtimeID, ruleID, evaluatedEventIDs, emittedFindingIDs); err != nil {
			return nil, err
		}
		return resolvedCounterFindings, nil
	}
	return nil, s.resolveAllOpenFindingsForRule(ctx, tenantID, runtimeID, ruleID)
}

func (s *Service) applyCounterEventResolutionResults(ctx context.Context, run *cerebrov1.FindingEvaluationRun, resultFindings []*ports.FindingRecord, resultEvidence *[]*cerebrov1.FindingEvidence, evidenceIDs map[string]struct{}, resolvedFindings []*ports.FindingRecord) error {
	if len(resolvedFindings) == 0 {
		return nil
	}
	replaceResultFindingsWithSnapshots(resultFindings, resolvedFindings)
	if evidenceIDs == nil {
		evidenceIDs = map[string]struct{}{}
	}
	for _, finding := range resolvedFindings {
		if finding == nil {
			continue
		}
		evidence, err := s.buildFindingEvidence(ctx, finding, run)
		if err != nil {
			return fmt.Errorf("build counter-event evidence for finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if _, seen := evidenceIDs[evidence.GetId()]; seen {
			continue
		}
		if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
			return fmt.Errorf("persist counter-event evidence for finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		evidenceIDs[evidence.GetId()] = struct{}{}
		if resultEvidence != nil {
			*resultEvidence = append(*resultEvidence, evidence)
		}
	}
	return nil
}

func replaceResultFindingsWithSnapshots(resultFindings []*ports.FindingRecord, resolvedFindings []*ports.FindingRecord) {
	if len(resultFindings) == 0 || len(resolvedFindings) == 0 {
		return
	}
	byID := make(map[string]*ports.FindingRecord, len(resolvedFindings))
	byFingerprint := make(map[string]*ports.FindingRecord, len(resolvedFindings))
	for _, finding := range resolvedFindings {
		if finding == nil {
			continue
		}
		if id := strings.TrimSpace(finding.ID); id != "" {
			byID[id] = finding
		}
		if fingerprint := strings.TrimSpace(finding.Fingerprint); fingerprint != "" {
			byFingerprint[fingerprint] = finding
		}
	}
	for index, finding := range resultFindings {
		if finding == nil {
			continue
		}
		if updated, ok := byID[strings.TrimSpace(finding.ID)]; ok {
			resultFindings[index] = updated
			continue
		}
		if updated, ok := byFingerprint[strings.TrimSpace(finding.Fingerprint)]; ok {
			resultFindings[index] = updated
		}
	}
}

func durableStateCounterEventRule(rule Rule) (CounterEventRule, bool) {
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		return nil, false
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return nil, false
	}
	lifecycleKind := LifecycleKind(strings.TrimSpace(string(metadataRule.RuleMetadata().Lifecycle.Kind)))
	if lifecycleKind != LifecycleDurableState {
		return nil, false
	}
	return counterRule, true
}

func counterEventCloseLookupRuntimeScoped(rule Rule) bool {
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return true
	}
	definition := metadataRule.RuleMetadata()
	if LifecycleKind(strings.TrimSpace(string(definition.Lifecycle.Kind))) != LifecycleDurableState {
		return true
	}
	if len(definition.FingerprintFields) == 0 {
		return true
	}
	return fingerprintFieldsIncludeRuntimeID(definition.FingerprintFields)
}

func fingerprintFieldsIncludeRuntimeID(fields []string) bool {
	for _, field := range fields {
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "runtime_id", "source_runtime_id":
			return true
		}
	}
	return false
}

func isTTLEvidenceRule(rule Rule) bool {
	if rule == nil {
		return false
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return false
	}
	return metadataRule.RuleMetadata().Lifecycle.Kind == LifecycleTTLEvidence
}

func (s *Service) resolveAllOpenFindingsForRule(ctx context.Context, tenantID string, runtimeID string, ruleID string) error {
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list stale candidates for unsupported rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve stale finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project stale finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

func findingReferencesEvaluatedEvent(finding *ports.FindingRecord, evaluatedEventIDs map[string]struct{}) bool {
	if finding == nil {
		return false
	}
	for _, eventID := range finding.EventIDs {
		if _, ok := evaluatedEventIDs[strings.TrimSpace(eventID)]; ok {
			return true
		}
	}
	return false
}

// GetFinding loads one persisted finding by durable identifier.
func (s *Service) GetFinding(ctx context.Context, id string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// BackfillFindingRisk refreshes startup-migrated risk fields and graph projections for rows it updates.
func (s *Service) BackfillFindingRisk(ctx context.Context) error {
	if s == nil || s.store == nil {
		return ErrRuntimeUnavailable
	}
	backfiller, ok := s.store.(interface {
		BackfillFindingRisk(context.Context, bool) ([]*ports.FindingRecord, error)
	})
	if !ok {
		return nil
	}
	includeUnprojected := s.graph != nil
	updated, err := backfiller.BackfillFindingRisk(ctx, includeUnprojected)
	if err != nil {
		return err
	}
	revisionTime := time.Now().UTC().Format(time.RFC3339Nano)
	for _, finding := range updated {
		if finding == nil {
			continue
		}
		current := finding
		if getter, ok := s.store.(interface {
			GetFinding(context.Context, string) (*ports.FindingRecord, error)
		}); ok {
			loaded, err := getter.GetFinding(ctx, strings.TrimSpace(finding.ID))
			if err != nil && !errors.Is(err, ports.ErrFindingNotFound) {
				return fmt.Errorf("load finding %q backfilled risk: %w", finding.ID, err)
			}
			if loaded != nil {
				current = loaded
			}
		}
		revision := fmt.Sprintf("startup-risk-backfill|%s|%s", revisionTime, strings.TrimSpace(current.ID))
		if err := s.projectFindingAnchorRevision(ctx, current, revision); err != nil {
			return fmt.Errorf("project finding %q backfilled risk: %w", current.ID, err)
		}
		if err := s.markFindingRiskProjected(ctx, current); err != nil {
			return fmt.Errorf("mark finding %q backfilled risk projected: %w", current.ID, err)
		}
	}
	return nil
}

// ResolveFinding marks one persisted finding as resolved.
func (s *Service) ResolveFinding(ctx context.Context, id string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatus(ctx, id, findingStatusResolved, reason)
}

// SuppressFinding marks one persisted finding as suppressed.
func (s *Service) SuppressFinding(ctx context.Context, id string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatus(ctx, id, findingStatusSuppressed, reason)
}

// FindingStatusUpdateOptions carries optimistic lifecycle preconditions and
// attribution for an external coordinator.
type FindingStatusUpdateOptions struct {
	ExpectedStatus     string
	LastObservedBefore time.Time
	Source             string
}

// ResolveFindingWithOptions marks one persisted finding as resolved when any
// supplied lifecycle preconditions still match the live row.
func (s *Service) ResolveFindingWithOptions(ctx context.Context, id string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, findingStatusResolved, reason, options)
}

// SuppressFindingWithOptions marks one persisted finding as suppressed when any
// supplied lifecycle preconditions still match the live row.
func (s *Service) SuppressFindingWithOptions(ctx context.Context, id string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, findingStatusSuppressed, reason, options)
}

// AssignFinding updates or clears one persisted finding assignee.
func (s *Service) AssignFinding(ctx context.Context, id string, assignee string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.store.UpdateFindingAssignee(ctx, ports.FindingAssigneeUpdate{
		FindingID: findingID,
		Assignee:  strings.TrimSpace(assignee),
	})
	if err != nil {
		return nil, fmt.Errorf("assign finding %q: %w", findingID, err)
	}
	return finding, nil
}

// SetFindingDueDate updates one persisted finding due date.
func (s *Service) SetFindingDueDate(ctx context.Context, id string, dueAt time.Time) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	normalizedDueAt := dueAt.UTC()
	if normalizedDueAt.IsZero() {
		return nil, fmt.Errorf("%w: finding due date is required", ErrInvalidRequest)
	}
	finding, err := s.store.UpdateFindingDueDate(ctx, ports.FindingDueDateUpdate{
		FindingID: findingID,
		DueAt:     normalizedDueAt,
	})
	if err != nil {
		return nil, fmt.Errorf("set finding %q due date: %w", findingID, err)
	}
	finding, err = s.persistFindingRisk(ctx, finding, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("refresh finding %q risk after due date update: %w", findingID, err)
	}
	if err := s.projectFindingAnchorRevision(ctx, finding, "due-risk-refresh|"+time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("project finding %q due date risk update: %w", findingID, err)
	}
	if err := s.markFindingRiskProjected(ctx, finding); err != nil {
		return nil, fmt.Errorf("mark finding %q due date risk projected: %w", findingID, err)
	}
	return finding, nil
}

// AddFindingNote appends one analyst note to one persisted finding.
func (s *Service) AddFindingNote(ctx context.Context, id string, note string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	body := strings.TrimSpace(note)
	if body == "" {
		return nil, fmt.Errorf("%w: finding note is required", ErrInvalidRequest)
	}
	createdAt := time.Now().UTC()
	noteRecord := ports.FindingNote{
		ID:        findingNoteID(findingID, createdAt),
		Body:      body,
		CreatedAt: createdAt,
	}
	finding, err := s.store.AddFindingNote(ctx, ports.FindingNoteCreate{
		FindingID: findingID,
		Note:      noteRecord,
	})
	if err != nil {
		return nil, fmt.Errorf("add finding %q note: %w", findingID, err)
	}
	if err := s.projectFindingNote(ctx, finding, noteRecord); err != nil {
		return nil, fmt.Errorf("project finding %q note into graph: %w", findingID, err)
	}
	return finding, nil
}

// LinkFindingTicket appends one external ticket reference to one persisted finding.
func (s *Service) LinkFindingTicket(ctx context.Context, id string, ticketURL string, name string, externalID string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	normalizedURL := strings.TrimSpace(ticketURL)
	if normalizedURL == "" {
		return nil, fmt.Errorf("%w: finding ticket url is required", ErrInvalidRequest)
	}
	if _, err := url.ParseRequestURI(normalizedURL); err != nil {
		return nil, fmt.Errorf("%w: finding ticket url is invalid: %w", ErrInvalidRequest, err)
	}
	linkedAt := time.Now().UTC()
	ticket := ports.FindingTicket{
		URL:        normalizedURL,
		Name:       strings.TrimSpace(name),
		ExternalID: strings.TrimSpace(externalID),
		LinkedAt:   linkedAt,
	}
	finding, err := s.store.LinkFindingTicket(ctx, ports.FindingTicketLink{
		FindingID: findingID,
		Ticket:    ticket,
	})
	if err != nil {
		return nil, fmt.Errorf("link ticket to finding %q: %w", findingID, err)
	}
	if err := s.projectFindingTicket(ctx, finding, ticket); err != nil {
		return nil, fmt.Errorf("project finding %q ticket into graph: %w", findingID, err)
	}
	return finding, nil
}

// LinkFindingExternalRef appends or refreshes one external lifecycle reference on
// one persisted finding.
func (s *Service) LinkFindingExternalRef(ctx context.Context, id string, ref ports.FindingExternalRef) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	ref.System = strings.TrimSpace(ref.System)
	ref.Kind = strings.TrimSpace(ref.Kind)
	ref.ExternalID = strings.TrimSpace(ref.ExternalID)
	if ref.System == "" {
		return nil, fmt.Errorf("%w: external ref system is required", ErrInvalidRequest)
	}
	if ref.Kind == "" {
		return nil, fmt.Errorf("%w: external ref kind is required", ErrInvalidRequest)
	}
	if ref.ExternalID == "" {
		return nil, fmt.Errorf("%w: external ref external id is required", ErrInvalidRequest)
	}
	if ref.URL = strings.TrimSpace(ref.URL); ref.URL != "" {
		if _, err := url.ParseRequestURI(ref.URL); err != nil {
			return nil, fmt.Errorf("%w: external ref url is invalid: %w", ErrInvalidRequest, err)
		}
	}
	ref.ExternalStatus = strings.TrimSpace(ref.ExternalStatus)
	ref.ExternalStatusReason = strings.TrimSpace(ref.ExternalStatusReason)
	ref.LifecycleOwner = strings.TrimSpace(ref.LifecycleOwner)
	ref.ObservedAt = ref.ObservedAt.UTC()
	if ref.ObservedAt.IsZero() {
		ref.ObservedAt = time.Now().UTC()
	}
	finding, err := s.store.LinkFindingExternalRef(ctx, ports.FindingExternalRefLink{
		FindingID:   findingID,
		ExternalRef: ref,
	})
	if err != nil {
		return nil, fmt.Errorf("link external ref to finding %q: %w", findingID, err)
	}
	if err := s.projectFindingExternalRef(ctx, finding, ref); err != nil {
		return nil, fmt.Errorf("project finding %q external ref: %w", findingID, err)
	}
	return finding, nil
}

// ListEvaluationRuns loads persisted finding evaluation runs for one runtime.
func (s *Service) ListEvaluationRuns(ctx context.Context, request ListEvaluationRunsRequest) (*ListEvaluationRunsResult, error) {
	if s == nil || s.runtimeStore == nil || s.runStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	runs, err := s.runStore.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{
		RuntimeID: runtimeID,
		RuleID:    strings.TrimSpace(request.RuleID),
		Status:    strings.TrimSpace(request.Status),
		Limit:     request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list finding evaluation runs for runtime %q: %w", runtimeID, err)
	}
	return &ListEvaluationRunsResult{Runs: runs}, nil
}

// GetEvaluationRun loads one persisted finding evaluation run.
func (s *Service) GetEvaluationRun(ctx context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	if s == nil || s.runStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return nil, fmt.Errorf("%w: finding evaluation run id is required", ErrInvalidRequest)
	}
	run, err := s.runStore.GetFindingEvaluationRun(ctx, trimmedID)
	if err != nil {
		return nil, err
	}
	return run, nil
}

// ListEvidence loads persisted finding evidence for one runtime.
func (s *Service) ListEvidence(ctx context.Context, request ListEvidenceRequest) (*ListEvidenceResult, error) {
	if s == nil || s.runtimeStore == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	evidence, err := s.evidenceStore.ListFindingEvidence(ctx, ports.ListFindingEvidenceRequest{
		RuntimeID:    runtimeID,
		FindingID:    strings.TrimSpace(request.FindingID),
		RunID:        strings.TrimSpace(request.RunID),
		RuleID:       strings.TrimSpace(request.RuleID),
		ClaimID:      strings.TrimSpace(request.ClaimID),
		EventID:      strings.TrimSpace(request.EventID),
		GraphRootURN: strings.TrimSpace(request.GraphRootURN),
		GraphPathURN: strings.TrimSpace(request.GraphPathURN),
		Limit:        request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list finding evidence for runtime %q: %w", runtimeID, err)
	}
	return &ListEvidenceResult{Evidence: evidence}, nil
}

// GetEvidence loads one persisted finding evidence record.
func (s *Service) GetEvidence(ctx context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	if s == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return nil, fmt.Errorf("%w: finding evidence id is required", ErrInvalidRequest)
	}
	evidence, err := s.evidenceStore.GetFindingEvidence(ctx, trimmedID)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

type ruleEvaluationState struct {
	rule              Rule
	result            *RuleEvaluationResult
	eventsEvaluated   uint32
	eventsMatched     uint32
	evidenceIDs       map[string]struct{}
	emittedFindingIDs map[string]struct{}
	failed            bool
}

func (s *Service) selectRule(ctx context.Context, runtime *cerebrov1.SourceRuntime, ruleID string) (Rule, error) {
	trimmedRuleID := strings.TrimSpace(ruleID)
	if trimmedRuleID != "" {
		rule, ok := s.rules.Get(trimmedRuleID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrRuleNotFound, trimmedRuleID)
		}
		if _, isGraph := asGraphRule(rule); isGraph {
			return nil, fmt.Errorf("%w: %s is a graph rule and cannot be evaluated via event replay", ErrRuleUnsupported, trimmedRuleID)
		}
		if !rule.SupportsRuntime(runtime) {
			hasStale, err := s.hasOpenFindingsForRule(ctx, runtime, trimmedRuleID)
			if err != nil {
				return nil, err
			}
			if !hasStale {
				return nil, fmt.Errorf("%w: %s", ErrRuleUnsupported, trimmedRuleID)
			}
		}
		return rule, nil
	}
	applicable := filterEventDrivenRules(s.rules.ForRuntime(runtime))
	switch len(applicable) {
	case 0:
		staleRules, err := s.staleOpenRulesForRuntime(ctx, runtime, nil)
		if err != nil {
			return nil, err
		}
		switch len(staleRules) {
		case 0:
			return nil, fmt.Errorf("%w: %s", ErrRuleUnavailable, strings.TrimSpace(runtime.GetId()))
		case 1:
			return staleRules[0], nil
		default:
			return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
		}
	case 1:
		return applicable[0], nil
	default:
		return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
	}
}

func (s *Service) selectRules(ctx context.Context, runtime *cerebrov1.SourceRuntime, ruleIDs []string) ([]Rule, error) {
	if len(ruleIDs) == 0 {
		applicable, err := s.eventDrivenRulesForRuntime(ctx, runtime)
		if err != nil {
			return nil, err
		}
		if len(applicable) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrRuleUnavailable, strings.TrimSpace(runtime.GetId()))
		}
		return applicable, nil
	}
	selected := make([]Rule, 0, len(ruleIDs))
	seen := make(map[string]struct{}, len(ruleIDs))
	for _, rawID := range ruleIDs {
		trimmedID := strings.TrimSpace(rawID)
		if trimmedID == "" {
			continue
		}
		if _, ok := seen[trimmedID]; ok {
			continue
		}
		rule, ok := s.rules.Get(trimmedID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrRuleNotFound, trimmedID)
		}
		if _, isGraph := asGraphRule(rule); isGraph {
			return nil, fmt.Errorf("%w: %s is a graph rule and cannot be evaluated via event replay", ErrRuleUnsupported, trimmedID)
		}
		if !rule.SupportsRuntime(runtime) {
			hasStale, err := s.hasOpenFindingsForRule(ctx, runtime, trimmedID)
			if err != nil {
				return nil, err
			}
			if !hasStale {
				return nil, fmt.Errorf("%w: %s", ErrRuleUnsupported, trimmedID)
			}
		}
		seen[trimmedID] = struct{}{}
		selected = append(selected, rule)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
	}
	return selected, nil
}

func (s *Service) eventDrivenRulesForRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime) ([]Rule, error) {
	applicable := filterEventDrivenRules(s.rules.ForRuntime(runtime))
	seen := make(map[string]struct{}, len(applicable))
	for _, rule := range applicable {
		if rule == nil || rule.Spec() == nil {
			continue
		}
		seen[strings.TrimSpace(rule.Spec().GetId())] = struct{}{}
	}
	staleRules, err := s.staleOpenRulesForRuntime(ctx, runtime, seen)
	if err != nil {
		return nil, err
	}
	return append(applicable, staleRules...), nil
}

func (s *Service) staleOpenRulesForRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime, seen map[string]struct{}) ([]Rule, error) {
	if seen == nil {
		seen = map[string]struct{}{}
	}
	candidates := make(map[string]Rule)
	staleRules := []Rule{}
	for _, spec := range s.rules.List() {
		ruleID := strings.TrimSpace(spec.GetId())
		if ruleID == "" {
			continue
		}
		if _, ok := seen[ruleID]; ok {
			continue
		}
		rule, ok := s.rules.Get(ruleID)
		if !ok || rule.SupportsRuntime(runtime) {
			continue
		}
		if _, isGraph := asGraphRule(rule); isGraph {
			continue
		}
		candidates[ruleID] = rule
	}
	if len(candidates) == 0 {
		return staleRules, nil
	}
	openRuleIDs, err := s.openFindingRuleIDsForRuntime(ctx, runtime)
	if err != nil {
		return nil, err
	}
	for _, spec := range s.rules.List() {
		ruleID := strings.TrimSpace(spec.GetId())
		rule, ok := candidates[ruleID]
		if !ok {
			continue
		}
		if _, ok := openRuleIDs[ruleID]; !ok {
			continue
		}
		seen[ruleID] = struct{}{}
		staleRules = append(staleRules, rule)
	}
	return staleRules, nil
}

func (s *Service) openFindingRuleIDsForRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime) (map[string]struct{}, error) {
	ruleIDs := map[string]struct{}{}
	if s == nil || s.store == nil || runtime == nil {
		return ruleIDs, nil
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID: strings.TrimSpace(runtime.GetId()),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return nil, fmt.Errorf("list stale candidates for runtime %q: %w", strings.TrimSpace(runtime.GetId()), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if ruleID := strings.TrimSpace(finding.RuleID); ruleID != "" {
			ruleIDs[ruleID] = struct{}{}
		}
	}
	return ruleIDs, nil
}

func (s *Service) hasOpenFindingsForRule(ctx context.Context, runtime *cerebrov1.SourceRuntime, ruleID string) (bool, error) {
	if s == nil || s.store == nil || runtime == nil {
		return false, nil
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID: strings.TrimSpace(runtime.GetId()),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
		Limit:     1,
	})
	if err != nil {
		return false, fmt.Errorf("list stale candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	return len(findings) != 0, nil
}

// filterEventDrivenRules excludes graph rules from a rule slice. Graph rules implement Rule
// only to satisfy the registry contract; their Evaluate() is a no-op because they need a
// graph cypher query that the event-replay path cannot supply. Including them in the replay
// pass produces empty completed evaluation runs and duplicates the run record per rule.
func filterEventDrivenRules(rules []Rule) []Rule {
	if len(rules) == 0 {
		return rules
	}
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if _, isGraph := asGraphRule(rule); isGraph {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func normalizeEventLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return defaultEventLimit
	case limit > maxEventLimit:
		return maxEventLimit
	default:
		return limit
	}
}

func normalizeListLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return defaultListLimit
	case limit > maxListLimit:
		return maxListLimit
	default:
		return limit
	}
}

func (s *Service) updateFindingStatus(ctx context.Context, id string, status string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, status, reason, FindingStatusUpdateOptions{})
}

func (s *Service) updateFindingStatusWithOptions(ctx context.Context, id string, status string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
		FindingID:          findingID,
		Status:             strings.TrimSpace(status),
		Reason:             strings.TrimSpace(reason),
		UpdatedAt:          time.Now().UTC(),
		ExpectedStatus:     strings.TrimSpace(options.ExpectedStatus),
		LastObservedBefore: options.LastObservedBefore.UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("update finding %q status to %q: %w", findingID, status, err)
	}
	statusSource := strings.TrimSpace(options.Source)
	if statusSource == "" {
		statusSource = workflowevents.FindingStatusSourceManual
	}
	if err := s.recordFindingStatusWorkflow(ctx, finding, statusSource); err != nil {
		return nil, fmt.Errorf("record finding %q status workflow: %w", findingID, err)
	}
	return finding, nil
}

func (s *Service) updateFindingStatusAndRisk(ctx context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	finding, err := s.store.UpdateFindingStatus(ctx, request)
	if err != nil {
		return nil, err
	}
	return s.persistFindingRisk(ctx, finding, request.UpdatedAt)
}

func (s *Service) upsertFindingWithRisk(ctx context.Context, finding *ports.FindingRecord, runtime *cerebrov1.SourceRuntime, now time.Time) (*ports.FindingRecord, error) {
	stored, _, err := s.upsertFindingWithRiskAndNewness(ctx, finding, runtime, now)
	return stored, err
}

func (s *Service) upsertFindingWithRiskAndNewness(ctx context.Context, finding *ports.FindingRecord, runtime *cerebrov1.SourceRuntime, now time.Time) (*ports.FindingRecord, bool, error) {
	merged, existing, err := s.mergeExistingFindingEvidence(ctx, finding)
	if err != nil {
		return nil, false, err
	}
	enriched := enrichFindingRisk(merged, runtime, now)
	stored, err := s.store.UpsertFinding(ctx, enriched)
	if err != nil {
		return nil, false, err
	}
	if stored != nil {
		stored.GraphEvidenceRows = append([]*cerebrov1.GraphEvidenceRow(nil), enriched.GraphEvidenceRows...)
	}
	stored, err = s.persistFindingRisk(ctx, stored, now)
	return stored, existing == nil, err
}

func (s *Service) mergeExistingFindingEvidence(ctx context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, *ports.FindingRecord, error) {
	if s == nil || s.store == nil || finding == nil {
		return finding, nil, nil
	}
	if finding.RuleID == vulnViewActionableExternalFindingRuleID {
		if existing := s.activeVulnViewActionableFinding(ctx, finding); existing != nil {
			return mergeFindingEvidenceForUpsert(existing, finding), existing, nil
		}
		return finding, nil, nil
	}
	findingID := strings.TrimSpace(finding.ID)
	if findingID == "" {
		return finding, nil, nil
	}
	existing, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		if errors.Is(err, ports.ErrFindingNotFound) {
			return finding, nil, nil
		}
		return nil, nil, err
	}
	return mergeFindingEvidenceForUpsert(existing, finding), existing, nil
}

func mergeFindingEvidenceForUpsert(existing *ports.FindingRecord, incoming *ports.FindingRecord) *ports.FindingRecord {
	if existing == nil || incoming == nil {
		return incoming
	}
	if isCoordinationGraphRuleID(incoming.RuleID) {
		primaryURN := ""
		if incoming.Attributes != nil {
			primaryURN = incoming.Attributes["primary_resource_urn"]
		}
		if primaryURN == "" && len(incoming.ResourceURNs) > 0 {
			primaryURN = incoming.ResourceURNs[0]
		}
		incoming.ResourceURNs = limitedCoordinationResourceURNs(primaryURN, incoming.ResourceURNs)
	} else {
		incoming.ResourceURNs = uniqueTrimmedStringsPreserveOrder(append(append([]string(nil), existing.ResourceURNs...), incoming.ResourceURNs...))
	}
	incoming.EventIDs = uniqueTrimmedStringsPreserveOrder(append(append([]string(nil), existing.EventIDs...), incoming.EventIDs...))
	incoming.ObservedPolicyIDs = uniqueTrimmedStringsPreserveOrder(append(append([]string(nil), existing.ObservedPolicyIDs...), incoming.ObservedPolicyIDs...))
	incoming.Attributes = mergeFindingAttributesForUpsert(existing.Attributes, incoming.Attributes)
	if !existing.FirstObservedAt.IsZero() && (incoming.FirstObservedAt.IsZero() || existing.FirstObservedAt.Before(incoming.FirstObservedAt)) {
		incoming.FirstObservedAt = existing.FirstObservedAt
	}
	if existing.LastObservedAt.After(incoming.LastObservedAt) {
		incoming.LastObservedAt = existing.LastObservedAt
	}
	return incoming
}

func mergeFindingAttributesForUpsert(existing map[string]string, incoming map[string]string) map[string]string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(incoming))
	for key, value := range existing {
		if trimmedKey := strings.TrimSpace(key); trimmedKey != "" {
			merged[trimmedKey] = strings.TrimSpace(value)
		}
	}
	for key, value := range incoming {
		if trimmedKey := strings.TrimSpace(key); trimmedKey != "" {
			merged[trimmedKey] = strings.TrimSpace(value)
		}
	}
	mergeFindingListAttribute(merged, existing, incoming, "matched_locations", "matched_at")
	mergeFindingJSONListAttribute(merged, existing, incoming, "matched_locations_json", "matched_at")
	trimEmptyAttributes(merged)
	return merged
}

func (s *Service) activeVulnViewActionableFinding(ctx context.Context, incoming *ports.FindingRecord) *ports.FindingRecord {
	if s == nil || s.store == nil || incoming == nil {
		return nil
	}
	fingerprint := strings.TrimSpace(incoming.Fingerprint)
	resourceURN := firstNonEmpty(incoming.ResourceURNs...)
	if strings.TrimSpace(incoming.TenantID) != "" &&
		strings.TrimSpace(incoming.RuntimeID) != "" &&
		strings.TrimSpace(incoming.PolicyID) != "" &&
		resourceURN != "" {
		candidates, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
			TenantID:    strings.TrimSpace(incoming.TenantID),
			RuntimeID:   strings.TrimSpace(incoming.RuntimeID),
			RuleID:      vulnViewActionableExternalFindingRuleID,
			PolicyID:    strings.TrimSpace(incoming.PolicyID),
			ResourceURN: resourceURN,
			Limit:       25,
		})
		if err == nil {
			for _, candidate := range candidates {
				if candidate == nil || candidate.Tombstoned {
					continue
				}
				candidateFingerprint := strings.TrimSpace(candidate.Fingerprint)
				if fingerprint != "" && candidateFingerprint != "" && candidateFingerprint != fingerprint {
					continue
				}
				return candidate
			}
		}
	}
	existing, err := s.store.GetFinding(ctx, strings.TrimSpace(incoming.ID))
	if err == nil && existing != nil && !existing.Tombstoned {
		return existing
	}
	return nil
}

func mergeFindingListAttribute(merged map[string]string, existing map[string]string, incoming map[string]string, listKey string, scalarKeys ...string) {
	values := append(splitFindingListAttribute(existing[listKey]), splitFindingListAttribute(incoming[listKey])...)
	for _, key := range scalarKeys {
		values = append(values, existing[key], incoming[key])
	}
	values = uniqueTrimmedStringsPreserveOrder(values)
	if len(values) == 0 {
		delete(merged, listKey)
		return
	}
	merged[listKey] = strings.Join(values, ",")
}

func mergeFindingJSONListAttribute(merged map[string]string, existing map[string]string, incoming map[string]string, listKey string, scalarKeys ...string) {
	values := append(splitFindingJSONListAttribute(existing[listKey]), splitFindingJSONListAttribute(incoming[listKey])...)
	for _, key := range scalarKeys {
		values = append(values, existing[key], incoming[key])
	}
	values = uniqueTrimmedStringsPreserveOrder(values)
	if len(values) == 0 {
		delete(merged, listKey)
		return
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		delete(merged, listKey)
		return
	}
	merged[listKey] = string(encoded)
}

func splitFindingJSONListAttribute(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(value), &values); err != nil {
		return nil
	}
	return values
}

func splitFindingListAttribute(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func (s *Service) persistFindingRisk(ctx context.Context, finding *ports.FindingRecord, now time.Time) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	recomputed := recomputeFindingRisk(finding, now)
	if updater, ok := s.store.(interface {
		UpdateFindingRisk(context.Context, ports.FindingRiskUpdate) (*ports.FindingRecord, error)
	}); ok {
		return updater.UpdateFindingRisk(ctx, ports.FindingRiskUpdate{
			FindingID:   strings.TrimSpace(recomputed.ID),
			FindingRisk: recomputed.FindingRisk,
			Attributes:  findingRiskAttributes(recomputed),
		})
	}
	stored, err := s.store.UpsertFinding(ctx, recomputed)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

func newFindingEvaluationRun(runtimeID string, ruleID string, eventLimit uint32, startedAt time.Time) *cerebrov1.FindingEvaluationRun {
	normalizedStartedAt := startedAt.UTC()
	return &cerebrov1.FindingEvaluationRun{
		Id:            findingEvaluationRunID(runtimeID, ruleID, normalizedStartedAt),
		RuntimeId:     strings.TrimSpace(runtimeID),
		RuleId:        strings.TrimSpace(ruleID),
		Status:        "running",
		EventLimit:    normalizeEventLimit(eventLimit),
		StartedAt:     timestamppb.New(normalizedStartedAt),
		GraphRule:     proto.Bool(false),
		GraphRowsRead: proto.Uint32(0),
	}
}

// newGraphFindingEvaluationRun mints a run row for a graph-rule pass. Graph rules
// evaluate cypher rows over the projected graph and never replay events, so the
// per-event `EventLimit` does not apply. Persisting the default replay cap of 100
// here would make Get/ListFindingEvaluationRun advertise misleading metadata for
// graph runs (as if they were event replays capped at 100), so we leave EventLimit
// at zero — the proto-default — for callers to interpret as "n/a for graph rule".
//
// GraphRule is set at construction time so failures that abort the run before
// any rows are read still carry the discriminator that tells operators they
// are looking at a graph rule rather than an event rule that never saw events.
func newGraphFindingEvaluationRun(runtimeID string, ruleID string, startedAt time.Time) *cerebrov1.FindingEvaluationRun {
	normalizedStartedAt := startedAt.UTC()
	return &cerebrov1.FindingEvaluationRun{
		Id:            findingEvaluationRunID(runtimeID, ruleID, normalizedStartedAt),
		RuntimeId:     strings.TrimSpace(runtimeID),
		RuleId:        strings.TrimSpace(ruleID),
		Status:        "running",
		StartedAt:     timestamppb.New(normalizedStartedAt),
		GraphRule:     proto.Bool(true),
		GraphRowsRead: proto.Uint32(0),
	}
}

var findingEvaluationRunIDReplacer = strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")

func findingEvaluationRunID(runtimeID string, ruleID string, startedAt time.Time) string {
	rawRuntime := strings.TrimSpace(runtimeID)
	rawRule := strings.TrimSpace(ruleID)
	prefix := findingEvaluationRunIDReplacer.Replace(rawRuntime + "-" + rawRule)
	digest := sha256.Sum256([]byte(rawRuntime + "\x00" + rawRule))
	hashSuffix := hex.EncodeToString(digest[:4])
	return "finding-evaluation-run-" + prefix + "-" + hashSuffix + "-" + fmt.Sprintf("%d", startedAt.UnixNano()) + "-" + randomFindingRunSuffix()
}

func randomFindingRunSuffix() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "0000"
	}
	return hex.EncodeToString(buf[:])
}

func findingNoteID(findingID string, createdAt time.Time) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	return "finding-note-" + replacer.Replace(strings.TrimSpace(findingID)) + "-" + fmt.Sprintf("%d", createdAt.UnixNano())
}

func (s *Service) finishCompletedRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, eventsProcessed uint32, eventsMatched uint32, findingIDs []string) error {
	if run == nil {
		return nil
	}
	run.Status = "completed"
	setFindingEvaluationRunMetrics(run, eventsProcessed, eventsMatched, findingIDs)
	run.Error = ""
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	emitFindingEvaluationRunTelemetry(ctx, run)
	return nil
}

func (s *Service) finishFailedRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, eventsProcessed uint32, eventsMatched uint32, findingIDs []string, evaluationErr error) error {
	if run == nil {
		return evaluationErr
	}
	run.Status = "failed"
	setFindingEvaluationRunMetrics(run, eventsProcessed, eventsMatched, findingIDs)
	run.Error = strings.TrimSpace(evaluationErr.Error())
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return errors.Join(
			evaluationErr,
			fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err),
		)
	}
	emitFindingEvaluationRunTelemetry(ctx, run)
	return evaluationErr
}

// finishCompletedGraphRun finalizes a successful graph-rule run. Graph rules
// track graph_rows_read instead of events_* counters, so a dedicated finalizer
// keeps the event-rule helper from accidentally overwriting graph telemetry to
// zero. Callers must pass the cypher row count and the emitted finding ids.
func (s *Service) finishCompletedGraphRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, graphRowsRead uint32, findingIDs []string) error {
	if run == nil {
		return nil
	}
	run.Status = "completed"
	setGraphFindingEvaluationRunMetrics(run, graphRowsRead, findingIDs)
	run.Error = ""
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	emitFindingEvaluationRunTelemetry(ctx, run)
	return nil
}

// finishFailedGraphRun finalizes a failed graph-rule run while preserving the
// graph_rows_read counter accumulated before the failure, so operators can
// distinguish "failure before any rows were read" (graphRowsRead=0) from
// "failure after fetching N rows" (graphRowsRead=N).
func (s *Service) finishFailedGraphRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, graphRowsRead uint32, findingIDs []string, evaluationErr error) error {
	if run == nil {
		return evaluationErr
	}
	run.Status = "failed"
	setGraphFindingEvaluationRunMetrics(run, graphRowsRead, findingIDs)
	run.Error = strings.TrimSpace(evaluationErr.Error())
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return errors.Join(
			evaluationErr,
			fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err),
		)
	}
	emitFindingEvaluationRunTelemetry(ctx, run)
	return evaluationErr
}

func (s *Service) markRuleEvaluationFailed(ctx context.Context, state *ruleEvaluationState, evaluationErr error) error {
	if state == nil || state.result == nil || state.result.Run == nil {
		return evaluationErr
	}
	run := state.result.Run
	run.Status = "failed"
	setFindingEvaluationRunMetrics(run, state.eventsEvaluated, state.eventsMatched, findingIDs(state.result.Findings))
	run.Error = strings.TrimSpace(evaluationErr.Error())
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return errors.Join(
			evaluationErr,
			fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err),
		)
	}
	emitFindingEvaluationRunTelemetry(ctx, run)
	state.failed = true
	return nil
}

func setFindingEvaluationRunMetrics(run *cerebrov1.FindingEvaluationRun, eventsProcessed uint32, eventsMatched uint32, findingIDs []string) {
	if run == nil {
		return
	}
	run.EventsEvaluated = eventsProcessed
	run.EventsProcessed = eventsProcessed
	run.EventsMatched = eventsMatched
	run.FindingsUpserted = boundedUint32(len(findingIDs))
	run.FindingsEmitted = boundedUint32(len(findingIDs))
	run.FindingIds = append([]string(nil), findingIDs...)
}

// setGraphFindingEvaluationRunMetrics records the per-run counters for one
// graph-rule evaluation. The graph_rule discriminator is set at construction
// time (newGraphFindingEvaluationRun) so failures before the cypher query
// still preserve the rule-class signal; this helper only refreshes the
// counters that change as the run progresses.
func setGraphFindingEvaluationRunMetrics(run *cerebrov1.FindingEvaluationRun, graphRowsRead uint32, findingIDs []string) {
	if run == nil {
		return
	}
	run.GraphRowsRead = proto.Uint32(graphRowsRead)
	run.FindingsUpserted = boundedUint32(len(findingIDs))
	run.FindingsEmitted = boundedUint32(len(findingIDs))
	run.FindingIds = append([]string(nil), findingIDs...)
}

func emitFindingEvaluationRunTelemetry(ctx context.Context, run *cerebrov1.FindingEvaluationRun) {
	if run == nil {
		return
	}
	telemetry.Event(ctx, "finding_evaluation.run", telemetry.Attrs(
		telemetry.Field{Key: "run_id", Value: strings.TrimSpace(run.GetId())},
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(run.GetRuntimeId())},
		telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(run.GetRuleId())},
		telemetry.Field{Key: "status", Value: strings.TrimSpace(run.GetStatus())},
		telemetry.Field{Key: "event_limit", Value: run.GetEventLimit()},
		telemetry.Field{Key: "events_processed", Value: run.GetEventsProcessed()},
		telemetry.Field{Key: "events_matched", Value: run.GetEventsMatched()},
		telemetry.Field{Key: "findings_emitted", Value: run.GetFindingsEmitted()},
		telemetry.Field{Key: "graph_rule", Value: run.GetGraphRule()},
		telemetry.Field{Key: "graph_rows_read", Value: run.GetGraphRowsRead()},
	))
}

func (s *Service) markRuleEvaluationsFailed(ctx context.Context, states []*ruleEvaluationState, evaluationErr error) error {
	var cleanupErr error
	for _, state := range states {
		if state != nil && state.failed {
			continue
		}
		if failErr := s.markRuleEvaluationFailed(ctx, state, evaluationErr); failErr != nil {
			cleanupErr = errors.Join(cleanupErr, failErr)
		}
	}
	if cleanupErr != nil {
		return errors.Join(evaluationErr, cleanupErr)
	}
	return evaluationErr
}

func unfinishedRuleEvaluations(states []*ruleEvaluationState, first *ruleEvaluationState) []*ruleEvaluationState {
	for index, state := range states {
		if state == first {
			return states[index:]
		}
	}
	return nil
}

func findingIDs(findings []*ports.FindingRecord) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if id := strings.TrimSpace(finding.ID); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *Service) reconcileLegacyFindingIdentity(ctx context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil || finding == nil || finding.Attributes == nil {
		return finding, nil
	}
	legacyID := strings.TrimSpace(finding.Attributes[findingAttributeLegacyID])
	if legacyID == "" || legacyID == strings.TrimSpace(finding.ID) {
		return finding, nil
	}
	legacy, err := s.store.GetFinding(ctx, legacyID)
	if err != nil {
		if errors.Is(err, ports.ErrFindingNotFound) {
			return finding, nil
		}
		return nil, fmt.Errorf("load legacy finding %q: %w", legacyID, err)
	}
	if !matchesLegacyFindingIdentity(finding, legacy) {
		return finding, nil
	}
	finding.ID = strings.TrimSpace(legacy.ID)
	if legacyFingerprint := strings.TrimSpace(legacy.Fingerprint); legacyFingerprint != "" {
		finding.Fingerprint = legacyFingerprint
	}
	return finding, nil
}

func matchesLegacyFindingIdentity(incoming *ports.FindingRecord, legacy *ports.FindingRecord) bool {
	if incoming == nil || legacy == nil {
		return false
	}
	if strings.TrimSpace(incoming.TenantID) != strings.TrimSpace(legacy.TenantID) {
		return false
	}
	if strings.TrimSpace(incoming.RuntimeID) != strings.TrimSpace(legacy.RuntimeID) {
		return false
	}
	if strings.TrimSpace(incoming.RuleID) != strings.TrimSpace(legacy.RuleID) {
		return false
	}
	if len(legacy.EventIDs) == 0 {
		return true
	}
	for _, eventID := range incoming.EventIDs {
		if containsString(legacy.EventIDs, eventID) {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	if trimmedExpected == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}

func (s *Service) buildFindingEvidence(ctx context.Context, finding *ports.FindingRecord, run *cerebrov1.FindingEvaluationRun, graphRows ...*cerebrov1.GraphEvidenceRow) (*cerebrov1.FindingEvidence, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	if run == nil {
		return nil, errors.New("finding evaluation run is required")
	}
	claimIDs, err := s.claimIDsForFinding(ctx, finding)
	if err != nil {
		return nil, err
	}
	graphRootURNs := uniqueSortedStrings(finding.ResourceURNs)
	eventIDs := uniqueSortedStrings(finding.EventIDs)
	if len(graphRows) == 0 {
		graphRows = finding.GraphEvidenceRows
	}
	observedAt := time.Now().UTC()
	clonedGraphRows := cloneGraphEvidenceRows(graphRows)
	// Evidence is keyed by the runtime that performed THIS evaluation, not by the runtime
	// the finding happens to be pinned to. For event rules these are identical because the
	// fingerprint includes runtime_id. For graph rules the finding's runtime_id is pinned to
	// the first triggering runtime by UpsertFinding's ON CONFLICT clause, but every
	// triggering runtime should still record its own evidence. The evidence id intentionally
	// excludes run_id so repeated same-shape runs update last_observed_at instead of
	// proliferating rows.
	evidenceRuntimeID := strings.TrimSpace(run.GetRuntimeId())
	evidence := &cerebrov1.FindingEvidence{
		Id:             findingEvidenceID(evidenceRuntimeID, finding.ID, graphRootURNs, eventIDs),
		RuntimeId:      evidenceRuntimeID,
		RuleId:         strings.TrimSpace(finding.RuleID),
		FindingId:      strings.TrimSpace(finding.ID),
		RunId:          strings.TrimSpace(run.GetId()),
		RunIds:         []string{strings.TrimSpace(run.GetId())},
		ClaimIds:       claimIDs,
		EventIds:       eventIDs,
		GraphRootUrns:  graphRootURNs,
		CreatedAt:      timestamppb.New(observedAt),
		GraphRows:      clonedGraphRows,
		LastObservedAt: timestamppb.New(observedAt),
		Attributes:     compactStringMap(finding.Attributes),
		GraphPathUrns:  graphPathURNs(clonedGraphRows),
	}
	if observation := findingevidence.ObservationFor(evidence); observation != nil {
		evidence.Observations = []*cerebrov1.FindingEvidenceObservation{observation}
	}
	evidence.ObservationCount = boundedUint32(len(evidence.GetObservations()))
	return evidence, nil
}

func cloneGraphEvidenceRows(rows []*cerebrov1.GraphEvidenceRow) []*cerebrov1.GraphEvidenceRow {
	if len(rows) == 0 {
		return nil
	}
	cloned := make([]*cerebrov1.GraphEvidenceRow, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			continue
		}
		cloned = append(cloned, proto.Clone(row).(*cerebrov1.GraphEvidenceRow))
	}
	return cloned
}

func (s *Service) claimIDsForFinding(ctx context.Context, finding *ports.FindingRecord) ([]string, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	claimIDs := make([]string, 0, len(finding.EventIDs))
	for _, eventID := range uniqueSortedStrings(finding.EventIDs) {
		claims, err := s.claimStore.ListClaims(ctx, ports.ListClaimsRequest{
			RuntimeID:     strings.TrimSpace(finding.RuntimeID),
			TenantID:      strings.TrimSpace(finding.TenantID),
			SourceEventID: eventID,
			Limit:         defaultEvidenceClaimCap,
		})
		if err != nil {
			return nil, fmt.Errorf("list claims for event %q: %w", eventID, err)
		}
		for _, claim := range claims {
			if claim == nil || strings.TrimSpace(claim.ID) == "" {
				continue
			}
			claimIDs = append(claimIDs, claim.ID)
		}
	}
	return uniqueSortedStrings(claimIDs), nil
}

func graphPathURNs(rows []*cerebrov1.GraphEvidenceRow) []string {
	if len(rows) == 0 {
		return nil
	}
	urns := []string{}
	for _, row := range rows {
		if row == nil {
			continue
		}
		for _, path := range row.GetPaths() {
			if path == nil {
				continue
			}
			urns = append(urns, path.GetFromUrn(), path.GetToUrn())
		}
	}
	return uniqueSortedStrings(urns)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	sort.Strings(unique)
	return unique
}

func uniqueTrimmedStringsPreserveOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	return unique
}

func findingEvidenceID(runtimeID string, findingID string, graphRootURNs []string, eventIDs []string) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	identityParts := []string{strings.TrimSpace(runtimeID), strings.TrimSpace(findingID)}
	fingerprintParts := append([]string{}, identityParts...)
	fingerprintParts = append(fingerprintParts, uniqueSortedStrings(graphRootURNs)...)
	fingerprintParts = append(fingerprintParts, uniqueSortedStrings(eventIDs)...)
	prefix := replacer.Replace(strings.Join(identityParts, "-"))
	digest := sha256.Sum256([]byte(strings.Join(fingerprintParts, "\x00")))
	return "finding-evidence-" + prefix + "-" + hex.EncodeToString(digest[:8])
}
