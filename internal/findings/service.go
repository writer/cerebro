package findings

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/appendlogindex"
	"github.com/writer/cerebro/internal/findingevidence"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
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
	replayPreparer            ReplayPreparer
	requireRuntimeIndexReplay bool
	store                     ports.FindingStore
	runStore                  ports.FindingEvaluationRunStore
	evidenceStore             ports.FindingEvidenceStore
	candidateStore            ports.FindingCandidateStore
	claimStore                ports.ClaimStore
	graphQuery                ports.GraphQueryStore
	graphRunStore             GraphIngestRunStore
	requireTrustedResolution  bool
	graph                     ports.ProjectionGraphStore
	appendLog                 ports.AppendLog
	closeoutStore             ports.CloseoutRunStore
	tombstoneEventStore       ports.FindingTombstoneEventStore
	closeoutHeartbeatInterval time.Duration
	graphRuleQueryTimeout     time.Duration
	findingEvaluationLeaseTTL time.Duration
	rules                     *Registry
	ttlClock                  ttlClock
	ttlLogSink                ttlLogSink
}

// ReplayPreparer runs before replay-backed finding evaluation to make required
// replay indexes ready without hiding failures behind fallback scans.
type ReplayPreparer func(context.Context) error

// defaultGraphRuleQueryTimeout bounds a single graph rule's Cypher read so one
// pathological rule cannot consume the entire orchestrator phase budget. A stuck
// rule then fails with a clean, attributable per-rule deadline rather than a
// connectivity error from the phase context being cancelled out from under an
// in-flight query. The production orchestrator derives the budget from its
// configured graph-rule phase timeout (keeping it strictly under that deadline)
// via WithGraphRuleQueryTimeout; this default applies only when no budget is
// wired (e.g. tests) and matches the default 15m phase timeout less its margin.
const defaultGraphRuleQueryTimeout = 14 * time.Minute

const (
	defaultFindingEvaluationLeaseTTL     = 30 * time.Minute
	findingEvaluationLeaseReleaseTimeout = 5 * time.Second
)

// EvaluateRequest scopes one replay-backed finding evaluation.
type EvaluateRequest struct {
	RuntimeID        string
	RuleID           string
	EventLimit       uint32
	RuntimeLeaseHeld bool
}

// EvaluateRulesRequest scopes one replay-backed multi-rule evaluation.
type EvaluateRulesRequest struct {
	RuntimeID        string
	RuleIDs          []string
	EventLimit       uint32
	RuntimeLeaseHeld bool
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

// NewWithOptionalRegistry uses an explicit registry when one is configured.
func NewWithOptionalRegistry(runtimeStore ports.SourceRuntimeStore, replayer ports.EventReplayer, store ports.FindingStore, runStore ports.FindingEvaluationRunStore, evidenceStore ports.FindingEvidenceStore, claimStore ports.ClaimStore, rules *Registry) *Service {
	if rules == nil {
		return New(runtimeStore, replayer, store, runStore, evidenceStore, claimStore)
	}
	return NewWithRegistry(runtimeStore, replayer, store, runStore, evidenceStore, claimStore, rules)
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
	if graphRuns, ok := graphQuery.(GraphIngestRunStore); ok {
		s.graphRunStore = graphRuns
	}
	return s
}

// WithGraphIngestRunStore wires the durable projection checkpoints used to
// prove graph-rule input freshness.
func (s *Service) WithGraphIngestRunStore(store GraphIngestRunStore) *Service {
	if s == nil {
		return nil
	}
	s.graphRunStore = store
	return s
}

// WithTrustedSourceResolution prevents an incomplete source or graph snapshot
// from closing an existing finding. Positive matches may still be recorded.
func (s *Service) WithTrustedSourceResolution() *Service {
	if s == nil {
		return nil
	}
	s.requireTrustedResolution = true
	return s
}

// WithGraphRuleQueryTimeout overrides the per-graph-rule Cypher read budget. A
// non-positive value falls back to defaultGraphRuleQueryTimeout.
func (s *Service) WithGraphRuleQueryTimeout(timeout time.Duration) *Service {
	if s == nil {
		return nil
	}
	s.graphRuleQueryTimeout = timeout
	return s
}

// graphRuleQueryBudget returns the effective per-graph-rule Cypher read budget.
func (s *Service) graphRuleQueryBudget() time.Duration {
	if s != nil && s.graphRuleQueryTimeout > 0 {
		return s.graphRuleQueryTimeout
	}
	return defaultGraphRuleQueryTimeout
}

// WithAppendLog wires one optional durable append log used for workflow metadata events.
func (s *Service) WithAppendLog(appendLog ports.AppendLog) *Service {
	if s == nil {
		return nil
	}
	s.appendLog = appendLog
	return s
}

// WithReplayPreparer wires an optional pre-replay readiness hook.
func (s *Service) WithReplayPreparer(preparer ReplayPreparer) *Service {
	if s == nil {
		return nil
	}
	s.replayPreparer = preparer
	return s
}

// WithRuntimeIndexReplayPreparer wires the runtime-index warmup required by
// replay-backed rules when JetStream runtime indexing is enabled.
func (s *Service) WithRuntimeIndexReplayPreparer(enabled bool, appendLog ports.AppendLog, stateStore ports.StateStore) *Service {
	if s == nil || !enabled {
		return s
	}
	s.requireRuntimeIndexReplay = true
	source, sourceOK := appendLog.(ports.RuntimeIndexSource)
	writer, writerOK := stateStore.(ports.RuntimeIndexWriter)
	return s.WithReplayPreparer(func(ctx context.Context) error {
		if !sourceOK || source == nil {
			return fmt.Errorf("%w: append log does not support runtime indexing", ErrRuntimeUnavailable)
		}
		if !writerOK || writer == nil {
			return fmt.Errorf("%w: state store does not support runtime indexing", ErrRuntimeUnavailable)
		}
		if err := appendlogindex.PrepareReplay(ctx, source, writer, 0, 0); err != nil {
			return fmt.Errorf("prepare append log runtime index: %w", err)
		}
		return nil
	})
}

func (s *Service) prepareReplay(ctx context.Context) error {
	if s == nil || s.replayPreparer == nil {
		return nil
	}
	return s.replayPreparer(ctx)
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
func (s *Service) EvaluateSourceRuntime(ctx context.Context, request EvaluateRequest) (result *EvaluateResult, err error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.claimStore == nil || s.rules == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	leaseCtx, releaseLease, trustedInput, err := s.acquireFindingEvaluationLease(ctx, runtimeID, request.RuntimeLeaseHeld)
	if err != nil {
		return nil, err
	}
	ctx = leaseCtx
	defer func() {
		if releaseErr := releaseLease(); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
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
	applicable := rule.SupportsRuntime(runtime)
	run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
	run.RuleApplicable = proto.Bool(applicable)
	bindFindingEvaluationSourceSnapshot(run, runtime)
	if s.requireTrustedResolution && !trustedInput {
		run.SourceDependencyComplete = proto.Bool(false)
	}
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return nil, fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	var events []*cerebrov1.EventEnvelope
	if applicable {
		if err := s.prepareReplay(ctx); err != nil {
			evaluationErr := fmt.Errorf("prepare replay runtime %q events: %w", runtimeID, err)
			return nil, s.finishFailedRun(ctx, run, 0, 0, nil, evaluationErr)
		}
		events, err = s.replayer.Replay(ctx, replayRequestForRules(runtime, runtimeID, normalizedLimit, []Rule{rule}, s.requireRuntimeIndexReplay))
		if err != nil {
			evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
			return nil, s.finishFailedRun(ctx, run, 0, 0, nil, evaluationErr)
		}
	}
	result = &EvaluateResult{
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
	if s.canResolveFromEventEvaluationRun(run, result.EventsEvaluated) {
		resolvedCounterFindings, err := s.resolveRuleOpenFindings(ctx, runtime, rule, events, evaluatedEventIDs, emittedFindingIDs)
		if err != nil {
			evaluationErr := fmt.Errorf("resolve stale findings for rule %q: %w", result.Rule.GetId(), err)
			return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
		}
		if err := s.applyCounterEventResolutionResults(ctx, run, result.Findings, &result.Evidence, evidenceIDs, resolvedCounterFindings); err != nil {
			evaluationErr := fmt.Errorf("persist counter-event close evidence for rule %q: %w", result.Rule.GetId(), err)
			return nil, s.finishFailedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings), evaluationErr)
		}
	}
	if err := s.finishCompletedRun(ctx, run, result.EventsEvaluated, eventsMatched, findingIDs(result.Findings)); err != nil {
		return nil, err
	}
	return result, nil
}

// EvaluateSourceRuntimeRules replays one runtime once and evaluates one or more registered rules over that shared pass.
func (s *Service) EvaluateSourceRuntimeRules(ctx context.Context, request EvaluateRulesRequest) (result *EvaluateRulesResult, err error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.claimStore == nil || s.rules == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	leaseCtx, releaseLease, trustedInput, err := s.acquireFindingEvaluationLease(ctx, runtimeID, request.RuntimeLeaseHeld)
	if err != nil {
		return nil, err
	}
	ctx = leaseCtx
	defer func() {
		if releaseErr := releaseLease(); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
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
	result = &EvaluateRulesResult{
		Runtime:     runtime,
		Evaluations: make([]*RuleEvaluationResult, 0, len(rules)),
	}
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	for _, rule := range rules {
		run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
		run.RuleApplicable = proto.Bool(rule.SupportsRuntime(runtime))
		bindFindingEvaluationSourceSnapshot(run, runtime)
		if s.requireTrustedResolution && !trustedInput {
			run.SourceDependencyComplete = proto.Bool(false)
		}
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
		if err := s.prepareReplay(ctx); err != nil {
			evaluationErr := fmt.Errorf("prepare replay runtime %q events: %w", runtimeID, err)
			return nil, s.markRuleEvaluationsFailed(ctx, states, evaluationErr)
		}
		events, err = s.replayer.Replay(ctx, replayRequestForRules(runtime, runtimeID, normalizedLimit, rulesFromEvaluationStates(states), s.requireRuntimeIndexReplay))
		if err != nil {
			evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
			return nil, s.markRuleEvaluationsFailed(ctx, states, evaluationErr)
		}
	}
	result.EventsEvaluated = boundedUint32(len(events))
	evaluatedEventIDs := map[string]struct{}{}
	var evaluationErr error
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
				ruleErr := fmt.Errorf("evaluate finding rule %q for event %q: %w", state.result.Rule.GetId(), event.GetId(), err)
				evaluationErr = errors.Join(evaluationErr, ruleErr)
				if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
					return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
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
					ruleErr := fmt.Errorf("reconcile finding identity for rule %q event %q: %w", state.result.Rule.GetId(), event.GetId(), err)
					evaluationErr = errors.Join(evaluationErr, ruleErr)
					if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
					}
					break
				}
				stored, isNewFinding, err := s.upsertFindingWithRiskAndNewness(ctx, record, runtime, startedAt)
				if err != nil {
					ruleErr := fmt.Errorf("persist finding for rule %q event %q: %w", state.result.Rule.GetId(), event.GetId(), err)
					evaluationErr = errors.Join(evaluationErr, ruleErr)
					if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
					}
					break
				}
				state.result.Findings = append(state.result.Findings, stored)
				state.emittedFindingIDs[strings.TrimSpace(stored.ID)] = struct{}{}
				evidence, err := s.buildFindingEvidence(ctx, stored, state.result.Run)
				if err != nil {
					ruleErr := fmt.Errorf("build evidence for finding %q: %w", stored.ID, err)
					evaluationErr = errors.Join(evaluationErr, ruleErr)
					if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
					}
					break
				}
				if _, seen := state.evidenceIDs[evidence.GetId()]; !seen {
					if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
						ruleErr := fmt.Errorf("persist evidence for finding %q: %w", stored.ID, err)
						evaluationErr = errors.Join(evaluationErr, ruleErr)
						if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
							return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
						}
						break
					}
					state.evidenceIDs[evidence.GetId()] = struct{}{}
					state.result.Evidence = append(state.result.Evidence, evidence)
				}
				if err := s.projectFindingAnchor(ctx, stored); err != nil {
					ruleErr := fmt.Errorf("project finding %q graph anchor: %w", stored.ID, err)
					evaluationErr = errors.Join(evaluationErr, ruleErr)
					if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
					}
					break
				}
				if err := s.projectFindingExternalRefs(ctx, stored); err != nil {
					ruleErr := fmt.Errorf("project finding %q external refs: %w", stored.ID, err)
					evaluationErr = errors.Join(evaluationErr, ruleErr)
					if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
						return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
					}
					break
				}
				if isNewFinding {
					if err := s.projectFindingNewActionRecommendations(ctx, stored); err != nil {
						ruleErr := fmt.Errorf("project finding %q action recommendations: %w", stored.ID, err)
						evaluationErr = errors.Join(evaluationErr, ruleErr)
						if failErr := s.markRuleEvaluationFailed(ctx, state, ruleErr); failErr != nil {
							return nil, s.markRuleEvaluationsFailed(ctx, states, errors.Join(evaluationErr, failErr))
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
		if s.canResolveFromEventEvaluationRun(state.result.Run, state.eventsEvaluated) {
			resolvedCounterFindings, err := s.resolveRuleOpenFindings(ctx, runtime, state.rule, events, evaluatedEventIDs, state.emittedFindingIDs)
			if err != nil {
				finalErr := fmt.Errorf("resolve stale findings for rule %q: %w", state.result.Rule.GetId(), err)
				return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), errors.Join(evaluationErr, finalErr))
			}
			if err := s.applyCounterEventResolutionResults(ctx, state.result.Run, state.result.Findings, &state.result.Evidence, state.evidenceIDs, resolvedCounterFindings); err != nil {
				finalErr := fmt.Errorf("persist counter-event close evidence for rule %q: %w", state.result.Rule.GetId(), err)
				return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), errors.Join(evaluationErr, finalErr))
			}
		}
		if err := s.finishCompletedRun(ctx, state.result.Run, state.eventsEvaluated, state.eventsMatched, findingIDs(state.result.Findings)); err != nil {
			return nil, s.markRuleEvaluationsFailed(ctx, unfinishedRuleEvaluations(states, state), errors.Join(evaluationErr, err))
		}
	}
	if evaluationErr != nil {
		return result, evaluationErr
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

func replayRequestForRules(runtime *cerebrov1.SourceRuntime, runtimeID string, limit uint32, rules []Rule, requireRuntimeIndex bool) ports.ReplayRequest {
	request := ports.ReplayRequest{
		RuntimeID:           strings.TrimSpace(runtimeID),
		RequireRuntimeIndex: requireRuntimeIndex,
		Limit:               limit,
	}
	kindPrefixes := replayExactKindFiltersForRules(runtime, rules)
	if len(kindPrefixes) > 0 {
		request.KindPrefixes = kindPrefixes
		request.ExactKindFilters = true
	}
	return request
}

func replayExactKindFiltersForRules(runtime *cerebrov1.SourceRuntime, rules []Rule) []string {
	runtimeKind := strings.TrimSpace(runtimeConfiguredEventKind(runtime))
	seen := map[string]struct{}{}
	supportingRules := 0
	for _, rule := range rules {
		if rule == nil || !rule.SupportsRuntime(runtime) {
			continue
		}
		supportingRules++
		metadataRule, ok := rule.(MetadataRule)
		if !ok {
			return nil
		}
		definition := metadataRule.RuleMetadata()
		if len(definition.EventKinds) == 0 {
			return nil
		}
		matchedRuleKind := false
		for _, rawKind := range definition.EventKinds {
			kind := strings.TrimSpace(rawKind)
			if kind == "" {
				continue
			}
			if runtimeKind != "" && kind != runtimeKind {
				continue
			}
			seen[kind] = struct{}{}
			matchedRuleKind = true
		}
		if !matchedRuleKind {
			return nil
		}
	}
	if supportingRules == 0 {
		return nil
	}
	kinds := make([]string, 0, len(seen))
	for kind := range seen {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func rulesFromEvaluationStates(states []*ruleEvaluationState) []Rule {
	rules := make([]Rule, 0, len(states))
	for _, state := range states {
		if state == nil || state.rule == nil {
			continue
		}
		rules = append(rules, state.rule)
	}
	return rules
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
		config, err := s.riskScoringConfigForFinding(ctx, current)
		if err != nil {
			return err
		}
		if config != nil {
			current, err = s.persistFindingRisk(ctx, current, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("refresh finding %q backfilled risk: %w", finding.ID, err)
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

func (s *Service) upsertFindingWithRisk(ctx context.Context, finding *ports.FindingRecord, runtime *cerebrov1.SourceRuntime, now time.Time) (*ports.FindingRecord, error) {
	stored, _, err := s.upsertFindingWithRiskAndNewness(ctx, finding, runtime, now)
	return stored, err
}

func (s *Service) upsertFindingWithRiskAndNewness(ctx context.Context, finding *ports.FindingRecord, _ *cerebrov1.SourceRuntime, now time.Time) (*ports.FindingRecord, bool, error) {
	merged, existing, err := s.mergeExistingFindingEvidence(ctx, finding)
	if err != nil {
		return nil, false, err
	}
	config, err := s.riskScoringConfigForFinding(ctx, merged)
	if err != nil {
		return nil, false, err
	}
	enriched := enrichFindingRiskWithConfig(merged, now, config)
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
	config, err := s.riskScoringConfigForFinding(ctx, finding)
	if err != nil {
		return nil, err
	}
	recomputed := recomputeFindingRiskWithConfig(finding, now, config)
	if updater, ok := s.store.(interface {
		UpdateFindingRisk(context.Context, ports.FindingRiskUpdate) (*ports.FindingRecord, error)
	}); ok {
		return updater.UpdateFindingRisk(ctx, ports.FindingRiskUpdate{
			FindingID:   strings.TrimSpace(recomputed.ID),
			FindingRisk: recomputed.FindingRisk,
			Attributes:  findingRiskAttributesWithConfig(recomputed, config),
		})
	}
	stored, err := s.store.UpsertFinding(ctx, recomputed)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *Service) riskScoringConfigForFinding(ctx context.Context, finding *ports.FindingRecord) (*ports.RiskScoringConfig, error) {
	if s == nil || s.store == nil || finding == nil {
		return nil, nil
	}
	store, ok := s.store.(ports.RiskScoringConfigStore)
	if !ok {
		return nil, nil
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	if tenantID == "" {
		return nil, nil
	}
	config, err := store.GetRiskScoringConfig(ctx, tenantID)
	if err == nil {
		return config, nil
	}
	if errors.Is(err, ports.ErrRiskScoringConfigNotFound) {
		return nil, nil
	}
	return nil, fmt.Errorf("load risk scoring config for tenant %q: %w", tenantID, err)
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
		Id:             findingEvaluationRunID(runtimeID, ruleID, normalizedStartedAt),
		RuntimeId:      strings.TrimSpace(runtimeID),
		RuleId:         strings.TrimSpace(ruleID),
		Status:         "running",
		StartedAt:      timestamppb.New(normalizedStartedAt),
		GraphRule:      proto.Bool(true),
		GraphRowsRead:  proto.Uint32(0),
		GraphTruncated: proto.Bool(false),
	}
}

func bindFindingEvaluationSourceSnapshot(run *cerebrov1.FindingEvaluationRun, runtime *cerebrov1.SourceRuntime) {
	if run == nil {
		return
	}
	run.SourceSnapshots = []*cerebrov1.FindingEvaluationSourceSnapshot{findingEvaluationSourceSnapshot(runtime)}
	run.SourceDependencyComplete = proto.Bool(runtime != nil)
}

const (
	findingSnapshotStatusKey       = "__cerebro_runtime_status"
	findingSnapshotScannedKey      = "__cerebro_runtime_records_scanned"
	findingSnapshotAcceptedKey     = "__cerebro_runtime_records_accepted"
	findingSnapshotRejectedKey     = "__cerebro_runtime_records_rejected"
	findingSnapshotFailureKey      = "__cerebro_runtime_last_failure_category"
	findingSnapshotContractKey     = "__cerebro_runtime_contract_probe_state"
	findingSnapshotProgressHashKey = "__cerebro_resolved_progress_config_hash"
)

func findingEvaluationSourceSnapshot(runtime *cerebrov1.SourceRuntime) *cerebrov1.FindingEvaluationSourceSnapshot {
	snapshot := &cerebrov1.FindingEvaluationSourceSnapshot{Complete: proto.Bool(false)}
	if runtime == nil {
		return snapshot
	}
	config := runtime.GetConfig()
	snapshot.RuntimeId = strings.TrimSpace(runtime.GetId())
	snapshot.SourceId = strings.TrimSpace(runtime.GetSourceId())
	snapshot.Family = strings.TrimSpace(config["family"])
	snapshot.SyncStatus = strings.TrimSpace(config[findingSnapshotStatusKey])
	snapshot.ContractProbeState = strings.TrimSpace(config[findingSnapshotContractKey])
	snapshot.ProgressConfigHash = strings.TrimSpace(config[findingSnapshotProgressHashKey])
	scanned, scannedOK := findingSnapshotUint32(config[findingSnapshotScannedKey])
	accepted, acceptedOK := findingSnapshotUint32(config[findingSnapshotAcceptedKey])
	rejected, rejectedOK := findingSnapshotUint32(config[findingSnapshotRejectedKey])
	snapshot.RecordsScanned = scanned
	snapshot.RecordsAccepted = accepted
	snapshot.RecordsRejected = rejected
	lastSyncedAt := runtime.GetLastSyncedAt()
	checkpointWatermark := runtime.GetCheckpoint().GetWatermark()
	if lastSyncedAt != nil && lastSyncedAt.CheckValid() == nil {
		snapshot.LastSyncedAt = timestamppb.New(lastSyncedAt.AsTime().UTC())
	}
	if checkpointWatermark != nil && checkpointWatermark.CheckValid() == nil {
		snapshot.CheckpointWatermark = timestamppb.New(checkpointWatermark.AsTime().UTC())
	}
	contractUsable := snapshot.ContractProbeState == "passing" || snapshot.ContractProbeState == "not_configured"
	complete := snapshot.RuntimeId != "" && snapshot.SourceId != "" && snapshot.LastSyncedAt != nil && snapshot.CheckpointWatermark != nil &&
		strings.TrimSpace(runtime.GetNextCursor().GetOpaque()) == "" && snapshot.SyncStatus == "completed" &&
		strings.TrimSpace(config[findingSnapshotFailureKey]) == "" && contractUsable && snapshot.ProgressConfigHash != "" &&
		scannedOK && acceptedOK && rejectedOK && accepted <= scanned && rejected == 0
	snapshot.Complete = proto.Bool(complete)
	return snapshot
}

func findingSnapshotUint32(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	return uint32(parsed), err == nil
}

func bindGraphSnapshot(snapshot *cerebrov1.FindingEvaluationSourceSnapshot, run graphstore.IngestRun, evaluationStartedAt time.Time) {
	if snapshot == nil {
		return
	}
	snapshot.GraphSnapshotComplete = proto.Bool(false)
	if strings.TrimSpace(run.RuntimeID) != snapshot.GetRuntimeId() {
		return
	}
	snapshot.GraphIngestRunId = strings.TrimSpace(run.ID)
	snapshot.GraphIngestStatus = strings.TrimSpace(run.Status)
	snapshot.GraphCheckpointId = strings.TrimSpace(run.CheckpointID)
	finishedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(run.FinishedAt))
	if err != nil {
		return
	}
	snapshot.GraphIngestedAt = timestamppb.New(finishedAt.UTC())
	lastSyncedAt := snapshot.GetLastSyncedAt()
	complete := snapshot.GraphIngestRunId != "" && snapshot.GraphIngestStatus == graphstore.IngestRunStatusCompleted &&
		snapshot.GraphCheckpointId != "" && run.CheckpointComplete && strings.TrimSpace(run.CheckpointCursor) == "" &&
		!finishedAt.After(evaluationStartedAt) && lastSyncedAt != nil && lastSyncedAt.CheckValid() == nil &&
		!finishedAt.Before(lastSyncedAt.AsTime())
	snapshot.GraphSnapshotComplete = proto.Bool(complete)
}

func findingEvaluationSourceSnapshotsTrusted(run *cerebrov1.FindingEvaluationRun, requireGraph bool) bool {
	if run == nil || run.SourceDependencyComplete == nil || !run.GetSourceDependencyComplete() || len(run.GetSourceSnapshots()) == 0 {
		return false
	}
	for _, snapshot := range run.GetSourceSnapshots() {
		if snapshot == nil || snapshot.Complete == nil || !snapshot.GetComplete() {
			return false
		}
		if requireGraph && (snapshot.GraphSnapshotComplete == nil || !snapshot.GetGraphSnapshotComplete()) {
			return false
		}
	}
	return true
}

func (s *Service) canResolveFromFindingEvaluationRun(run *cerebrov1.FindingEvaluationRun, requireGraph bool) bool {
	return s != nil && (!s.requireTrustedResolution || findingEvaluationSourceSnapshotsTrusted(run, requireGraph))
}

func (s *Service) canResolveFromEventEvaluationRun(run *cerebrov1.FindingEvaluationRun, eventsProcessed uint32) bool {
	if !s.canResolveFromFindingEvaluationRun(run, false) {
		return false
	}
	if !s.requireTrustedResolution {
		return true
	}
	return run != nil && run.RuleApplicable != nil && run.GetRuleApplicable() && run.GetEventLimit() > 0 && eventsProcessed < run.GetEventLimit()
}

func (s *Service) acquireFindingEvaluationLease(ctx context.Context, runtimeID string, alreadyHeld bool) (context.Context, func() error, bool, error) {
	noop := func() error { return nil }
	if s == nil || !s.requireTrustedResolution {
		return ctx, noop, true, nil
	}
	if alreadyHeld {
		return ctx, noop, true, nil
	}
	leaser, ok := s.runtimeStore.(ports.SourceRuntimeLeaseStore)
	if !ok || leaser == nil {
		return ctx, noop, false, nil
	}
	ttl := s.findingEvaluationLeaseTTL
	if ttl <= 0 {
		ttl = defaultFindingEvaluationLeaseTTL
	}
	owner := "finding-evaluation:" + strings.TrimSpace(runtimeID) + ":" + fmt.Sprintf("%d", time.Now().UnixNano()) + ":" + randomFindingRunSuffix()
	acquired, err := leaser.AcquireSourceRuntimeLease(ctx, runtimeID, owner, ttl)
	if err != nil {
		return nil, nil, false, fmt.Errorf("acquire source runtime %q for finding evaluation: %w", runtimeID, err)
	}
	if !acquired {
		return nil, nil, false, fmt.Errorf("%w: source runtime %q is busy", ErrRuntimeUnavailable, runtimeID)
	}
	workCtx, cancelWork := context.WithCancel(ctx)
	renewCtx, cancelRenew := context.WithCancel(ctx)
	renewalDone := make(chan error, 1)
	renewalInterval := ttl / 3
	if renewalInterval <= 0 {
		renewalInterval = time.Nanosecond
	}
	go func() {
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				renewalDone <- nil
				return
			case <-ticker.C:
				renewed, renewErr := leaser.RenewSourceRuntimeLease(renewCtx, runtimeID, owner, ttl)
				if renewErr != nil {
					if renewCtx.Err() != nil {
						renewalDone <- nil
						return
					}
					cancelWork()
					renewalDone <- fmt.Errorf("renew source runtime %q during finding evaluation: %w", runtimeID, renewErr)
					return
				}
				if !renewed {
					if renewCtx.Err() != nil {
						renewalDone <- nil
						return
					}
					cancelWork()
					renewalDone <- fmt.Errorf("%w: source runtime %q lease was lost during finding evaluation", ErrRuntimeUnavailable, runtimeID)
					return
				}
			}
		}
	}()
	return workCtx, func() error {
		cancelRenew()
		renewalErr := <-renewalDone
		cancelWork()
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), findingEvaluationLeaseReleaseTimeout)
		defer cancel()
		if err := leaser.ReleaseSourceRuntimeLease(releaseCtx, runtimeID, owner); err != nil {
			return errors.Join(renewalErr, fmt.Errorf("release source runtime %q after finding evaluation: %w", runtimeID, err))
		}
		return renewalErr
	}, true, nil
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
	emitFindingEvaluationRunTelemetry(ctx, run, nil)
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
	emitFindingEvaluationRunTelemetry(ctx, run, evaluationErr)
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
	emitFindingEvaluationRunTelemetry(ctx, run, nil)
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
	emitFindingEvaluationRunTelemetry(ctx, run, evaluationErr)
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
	emitFindingEvaluationRunTelemetry(ctx, run, evaluationErr)
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

func emitFindingEvaluationRunTelemetry(ctx context.Context, run *cerebrov1.FindingEvaluationRun, evaluationErr error) {
	if run == nil {
		return
	}
	stage := findingEvaluationTelemetryStage(evaluationErr)
	failureStage := ""
	if evaluationErr != nil {
		failureStage = stage
	}
	ruleType := findingEvaluationRuleType(run)
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "run_id", Value: strings.TrimSpace(run.GetId())},
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(run.GetRuntimeId())},
		telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(run.GetRuleId())},
		telemetry.Field{Key: "status", Value: strings.TrimSpace(run.GetStatus())},
		telemetry.Field{Key: "finding_evaluation.stage", Value: stage},
		telemetry.Field{Key: "finding_evaluation.failure_stage", Value: failureStage},
		telemetry.Field{Key: "finding_evaluation.rule_type", Value: ruleType},
		telemetry.Field{Key: "event_limit", Value: run.GetEventLimit()},
		telemetry.Field{Key: "events_processed", Value: run.GetEventsProcessed()},
		telemetry.Field{Key: "events_matched", Value: run.GetEventsMatched()},
		telemetry.Field{Key: "findings_emitted", Value: run.GetFindingsEmitted()},
		telemetry.Field{Key: "graph_rule", Value: run.GetGraphRule()},
		telemetry.Field{Key: "graph_rows_read", Value: run.GetGraphRowsRead()},
	)
	if evaluationErr != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(evaluationErr)},
			telemetry.Field{Key: "error_fingerprint", Value: telemetry.ErrorFingerprint("finding_evaluation.run", evaluationErr, attrs)},
		))
	}
	telemetry.Event(ctx, "finding_evaluation.run", attrs)
	telemetry.IncrementMain(ctx, "finding_evaluation.run.count", 1)
	status := strings.TrimSpace(run.GetStatus())
	if strings.EqualFold(status, "completed") {
		telemetry.IncrementMain(ctx, "finding_evaluation."+ruleType+".completed.count", 1)
	} else {
		telemetry.IncrementMain(ctx, "finding_evaluation.run.non_completed.count", 1)
		telemetry.IncrementMain(ctx, "finding_evaluation."+ruleType+".failed.count", 1)
	}
	if run.GetFindingsEmitted() > 0 {
		telemetry.IncrementMain(ctx, "finding_evaluation.findings_emitted.count", int64(run.GetFindingsEmitted()))
	}
	if run.GetGraphRowsRead() > 0 {
		telemetry.IncrementMain(ctx, "finding_evaluation.graph_rows_read.count", int64(run.GetGraphRowsRead()))
	}
	telemetry.AnnotateMain(ctx, telemetry.Attrs(
		telemetry.Field{Key: "finding_evaluation.runtime_id", Value: strings.TrimSpace(run.GetRuntimeId())},
		telemetry.Field{Key: "finding_evaluation.rule_id", Value: strings.TrimSpace(run.GetRuleId())},
		telemetry.Field{Key: "finding_evaluation.status", Value: status},
		telemetry.Field{Key: "finding_evaluation.stage", Value: stage},
		telemetry.Field{Key: "finding_evaluation.failure_stage", Value: failureStage},
		telemetry.Field{Key: "finding_evaluation.rule_type", Value: ruleType},
		telemetry.Field{Key: "finding_evaluation.event_limit", Value: run.GetEventLimit()},
		telemetry.Field{Key: "finding_evaluation.events_processed", Value: run.GetEventsProcessed()},
		telemetry.Field{Key: "finding_evaluation.events_matched", Value: run.GetEventsMatched()},
		telemetry.Field{Key: "finding_evaluation.findings_emitted", Value: run.GetFindingsEmitted()},
		telemetry.Field{Key: "finding_evaluation.graph_rule", Value: run.GetGraphRule()},
		telemetry.Field{Key: "finding_evaluation.graph_rows_read", Value: run.GetGraphRowsRead()},
	))
}

func findingEvaluationRuleType(run *cerebrov1.FindingEvaluationRun) string {
	if run != nil && run.GetGraphRule() {
		return "graph_rule"
	}
	return "event_rule"
}

func findingEvaluationTelemetryStage(err error) string {
	if err == nil {
		return "finalize_run"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "persist finding evaluation run"):
		return "persist_run"
	case strings.Contains(message, "replay runtime"):
		return "replay"
	case strings.Contains(message, "execute graph rule"):
		return "graph_query"
	case strings.Contains(message, "evaluate graph rule"):
		return "graph_evaluate_rows"
	case strings.Contains(message, "evaluate finding rule"):
		return "evaluate_rule"
	case strings.Contains(message, "reconcile finding identity"):
		return "reconcile_identity"
	case strings.Contains(message, "persist finding"):
		return "upsert_finding"
	case strings.Contains(message, "build evidence"):
		return "build_evidence"
	case strings.Contains(message, "persist evidence"):
		return "persist_evidence"
	case strings.Contains(message, "action recommendations"):
		return "project_action_recommendations"
	case strings.Contains(message, "graph anchor") || strings.Contains(message, " finding ") && strings.Contains(message, " anchor"):
		return "project_anchor"
	case strings.Contains(message, "external refs"):
		return "project_external_refs"
	case strings.Contains(message, "resolve stale") || strings.Contains(message, "resolve retired"):
		return "resolve_stale"
	case strings.Contains(message, "counter-event close evidence"):
		return "persist_close_evidence"
	default:
		return "unknown"
	}
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
