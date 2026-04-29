package findings

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultEventLimit       = 100
	maxEventLimit           = 1000
	defaultEvidenceClaimCap = 100
)

var (
	// ErrRuntimeUnavailable indicates that the runtime, replay, or finding store boundary is unavailable.
	ErrRuntimeUnavailable = errors.New("finding runtime is unavailable")

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
	runtimeStore  ports.SourceRuntimeStore
	replayer      ports.EventReplayer
	store         ports.FindingStore
	runStore      ports.FindingEvaluationRunStore
	evidenceStore ports.FindingEvidenceStore
	claimStore    ports.ClaimStore
	rules         *Registry
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
	Limit       uint32
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

// ListRules returns the discoverable registered finding rule catalog.
func (s *Service) ListRules() *cerebrov1.ListFindingRulesResponse {
	if s == nil || s.rules == nil {
		return &cerebrov1.ListFindingRulesResponse{}
	}
	return &cerebrov1.ListFindingRulesResponse{
		Rules: s.rules.List(),
	}
}

// EvaluateSourceRuntime replays one runtime and persists findings for one selected registered rule.
func (s *Service) EvaluateSourceRuntime(ctx context.Context, request EvaluateRequest) (*EvaluateResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.claimStore == nil || s.rules == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	rule, err := s.selectRule(runtime, request.RuleID)
	if err != nil {
		return nil, err
	}
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	startedAt := time.Now().UTC()
	run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return nil, fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	events, err := s.replayer.Replay(ctx, ports.ReplayRequest{
		RuntimeID: runtimeID,
		Limit:     normalizedLimit,
	})
	if err != nil {
		evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
		return nil, s.finishFailedRun(ctx, run, 0, nil, evaluationErr)
	}
	result := &EvaluateResult{
		Runtime: runtime,
		Rule:    rule.Spec(),
		Run:     run,
	}
	evidenceIndex := make(map[string]int)
	var eventsEvaluated uint32
	for _, event := range events {
		emitted, err := rule.Evaluate(ctx, runtime, event)
		if err != nil {
			evaluationErr := fmt.Errorf("evaluate finding rule %q for event %q: %w", result.Rule.GetId(), event.GetId(), err)
			return nil, s.finishFailedRun(ctx, run, eventsEvaluated, findingIDs(result.Findings), evaluationErr)
		}
		eventsEvaluated++
		result.EventsEvaluated = eventsEvaluated
		for _, record := range emitted {
			if record == nil {
				continue
			}
			stored, err := s.store.UpsertFinding(ctx, record)
			if err != nil {
				evaluationErr := fmt.Errorf("persist finding for rule %q event %q: %w", result.Rule.GetId(), event.GetId(), err)
				return nil, s.finishFailedRun(ctx, run, eventsEvaluated, findingIDs(result.Findings), evaluationErr)
			}
			result.Findings = append(result.Findings, stored)
			evidence, err := s.buildFindingEvidence(ctx, stored, run)
			if err != nil {
				evaluationErr := fmt.Errorf("build evidence for finding %q: %w", stored.ID, err)
				return nil, s.finishFailedRun(ctx, run, eventsEvaluated, findingIDs(result.Findings), evaluationErr)
			}
			if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
				evaluationErr := fmt.Errorf("persist evidence for finding %q: %w", stored.ID, err)
				return nil, s.finishFailedRun(ctx, run, eventsEvaluated, findingIDs(result.Findings), evaluationErr)
			}
			if idx, ok := evidenceIndex[evidence.GetId()]; ok {
				result.Evidence[idx] = evidence
				continue
			}
			evidenceIndex[evidence.GetId()] = len(result.Evidence)
			result.Evidence = append(result.Evidence, evidence)
		}
	}
	if err := s.finishCompletedRun(ctx, run, eventsEvaluated, findingIDs(result.Findings)); err != nil {
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
		return nil, errors.New("source runtime id is required")
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	rules, err := s.selectRules(runtime, request.RuleIDs)
	if err != nil {
		return nil, err
	}
	normalizedLimit := normalizeEventLimit(request.EventLimit)
	startedAt := time.Now().UTC()
	states := make([]*ruleEvaluationState, 0, len(rules))
	result := &EvaluateRulesResult{
		Runtime:     runtime,
		Evaluations: make([]*RuleEvaluationResult, 0, len(rules)),
	}
	for _, rule := range rules {
		run := newFindingEvaluationRun(runtimeID, rule.Spec().GetId(), normalizedLimit, startedAt)
		if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
			evaluationErr := fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
			for _, state := range states {
				if failErr := s.markRuleEvaluationFailed(ctx, state, evaluationErr); failErr != nil {
					return nil, failErr
				}
			}
			return nil, evaluationErr
		}
		state := &ruleEvaluationState{
			rule: rule,
			result: &RuleEvaluationResult{
				Rule: rule.Spec(),
				Run:  run,
			},
		}
		states = append(states, state)
		result.Evaluations = append(result.Evaluations, state.result)
	}
	events, err := s.replayer.Replay(ctx, ports.ReplayRequest{
		RuntimeID: runtimeID,
		Limit:     normalizedLimit,
	})
	if err != nil {
		evaluationErr := fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
		for _, state := range states {
			if failErr := s.markRuleEvaluationFailed(ctx, state, evaluationErr); failErr != nil {
				return nil, failErr
			}
		}
		return nil, evaluationErr
	}
	result.EventsEvaluated = uint32(len(events))
	for _, event := range events {
		for _, state := range states {
			if state.failed {
				continue
			}
			state.eventsEvaluated++
			emitted, err := state.rule.Evaluate(ctx, runtime, event)
			if err != nil {
				if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("evaluate finding rule %q for event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
					return nil, failErr
				}
				continue
			}
			for _, record := range emitted {
				if record == nil {
					continue
				}
				stored, err := s.store.UpsertFinding(ctx, record)
				if err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("persist finding for rule %q event %q: %w", state.result.Rule.GetId(), event.GetId(), err)); failErr != nil {
						return nil, failErr
					}
					break
				}
				state.result.Findings = append(state.result.Findings, stored)
				evidence, err := s.buildFindingEvidence(ctx, stored, state.result.Run)
				if err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("build evidence for finding %q: %w", stored.ID, err)); failErr != nil {
						return nil, failErr
					}
					break
				}
				if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
					if failErr := s.markRuleEvaluationFailed(ctx, state, fmt.Errorf("persist evidence for finding %q: %w", stored.ID, err)); failErr != nil {
						return nil, failErr
					}
					break
				}
				state.result.Evidence = append(state.result.Evidence, evidence)
			}
		}
	}
	for _, state := range states {
		if state.failed {
			continue
		}
		if err := s.finishCompletedRun(ctx, state.result.Run, state.eventsEvaluated, findingIDs(state.result.Findings)); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// ListFindings loads persisted findings for one runtime.
func (s *Service) ListFindings(ctx context.Context, request ListRequest) (*ListResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		RuntimeID:   runtimeID,
		FindingID:   strings.TrimSpace(request.FindingID),
		RuleID:      strings.TrimSpace(request.RuleID),
		Severity:    strings.TrimSpace(request.Severity),
		Status:      strings.TrimSpace(request.Status),
		ResourceURN: strings.TrimSpace(request.ResourceURN),
		EventID:     strings.TrimSpace(request.EventID),
		Limit:       request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list findings for runtime %q: %w", runtimeID, err)
	}
	return &ListResult{Findings: findings}, nil
}

// ListEvaluationRuns loads persisted finding evaluation runs for one runtime.
func (s *Service) ListEvaluationRuns(ctx context.Context, request ListEvaluationRunsRequest) (*ListEvaluationRunsResult, error) {
	if s == nil || s.runtimeStore == nil || s.runStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
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
		return nil, errors.New("finding evaluation run id is required")
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
		return nil, errors.New("source runtime id is required")
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
		return nil, errors.New("finding evidence id is required")
	}
	evidence, err := s.evidenceStore.GetFindingEvidence(ctx, trimmedID)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

type ruleEvaluationState struct {
	rule            Rule
	result          *RuleEvaluationResult
	eventsEvaluated uint32
	failed          bool
}

func (s *Service) selectRule(runtime *cerebrov1.SourceRuntime, ruleID string) (Rule, error) {
	trimmedRuleID := strings.TrimSpace(ruleID)
	if trimmedRuleID != "" {
		rule, ok := s.rules.Get(trimmedRuleID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrRuleNotFound, trimmedRuleID)
		}
		if !rule.SupportsRuntime(runtime) {
			return nil, fmt.Errorf("%w: %s", ErrRuleUnsupported, trimmedRuleID)
		}
		return rule, nil
	}
	applicable := s.rules.ForRuntime(runtime)
	switch len(applicable) {
	case 0:
		return nil, fmt.Errorf("%w: %s", ErrRuleUnavailable, strings.TrimSpace(runtime.GetId()))
	case 1:
		return applicable[0], nil
	default:
		return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
	}
}

func (s *Service) selectRules(runtime *cerebrov1.SourceRuntime, ruleIDs []string) ([]Rule, error) {
	if len(ruleIDs) == 0 {
		applicable := s.rules.ForRuntime(runtime)
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
		if !rule.SupportsRuntime(runtime) {
			return nil, fmt.Errorf("%w: %s", ErrRuleUnsupported, trimmedID)
		}
		seen[trimmedID] = struct{}{}
		selected = append(selected, rule)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
	}
	return selected, nil
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

func newFindingEvaluationRun(runtimeID string, ruleID string, eventLimit uint32, startedAt time.Time) *cerebrov1.FindingEvaluationRun {
	normalizedStartedAt := startedAt.UTC()
	return &cerebrov1.FindingEvaluationRun{
		Id:         findingEvaluationRunID(runtimeID, ruleID, normalizedStartedAt),
		RuntimeId:  strings.TrimSpace(runtimeID),
		RuleId:     strings.TrimSpace(ruleID),
		Status:     "running",
		EventLimit: eventLimit,
		StartedAt:  timestamppb.New(normalizedStartedAt),
	}
}

func findingEvaluationRunID(runtimeID string, ruleID string, startedAt time.Time) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	prefix := replacer.Replace(strings.TrimSpace(runtimeID) + "-" + strings.TrimSpace(ruleID))
	return "finding-evaluation-run-" + prefix + "-" + fmt.Sprintf("%d", startedAt.UnixNano())
}

func (s *Service) finishCompletedRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, eventsEvaluated uint32, findingIDs []string) error {
	if run == nil {
		return nil
	}
	run.Status = "completed"
	run.EventsEvaluated = eventsEvaluated
	run.FindingsUpserted = uint32(len(findingIDs))
	run.FindingIds = append([]string(nil), findingIDs...)
	run.Error = ""
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	return nil
}

func (s *Service) finishFailedRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun, eventsEvaluated uint32, findingIDs []string, evaluationErr error) error {
	if run == nil {
		return evaluationErr
	}
	run.Status = "failed"
	run.EventsEvaluated = eventsEvaluated
	run.FindingsUpserted = uint32(len(findingIDs))
	run.FindingIds = append([]string(nil), findingIDs...)
	run.Error = strings.TrimSpace(evaluationErr.Error())
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return errors.Join(
			evaluationErr,
			fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err),
		)
	}
	return evaluationErr
}

func (s *Service) markRuleEvaluationFailed(ctx context.Context, state *ruleEvaluationState, evaluationErr error) error {
	if state == nil || state.result == nil || state.result.Run == nil {
		return evaluationErr
	}
	state.failed = true
	run := state.result.Run
	run.Status = "failed"
	run.EventsEvaluated = state.eventsEvaluated
	run.FindingsUpserted = uint32(len(state.result.Findings))
	run.FindingIds = append([]string(nil), findingIDs(state.result.Findings)...)
	run.Error = strings.TrimSpace(evaluationErr.Error())
	run.FinishedAt = timestamppb.New(time.Now().UTC())
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
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

func (s *Service) buildFindingEvidence(ctx context.Context, finding *ports.FindingRecord, run *cerebrov1.FindingEvaluationRun) (*cerebrov1.FindingEvidence, error) {
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
	createdAt := time.Now().UTC()
	return &cerebrov1.FindingEvidence{
		Id:            findingEvidenceID(finding.RuntimeID, finding.ID, run.GetId()),
		RuntimeId:     strings.TrimSpace(finding.RuntimeID),
		RuleId:        strings.TrimSpace(finding.RuleID),
		FindingId:     strings.TrimSpace(finding.ID),
		RunId:         strings.TrimSpace(run.GetId()),
		ClaimIds:      claimIDs,
		EventIds:      eventIDs,
		GraphRootUrns: graphRootURNs,
		CreatedAt:     timestamppb.New(createdAt),
	}, nil
}

func (s *Service) claimIDsForFinding(ctx context.Context, finding *ports.FindingRecord) ([]string, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	claimIDs := make([]string, 0, len(finding.EventIDs))
	for _, eventID := range uniqueSortedStrings(finding.EventIDs) {
		claims, err := s.claimStore.ListClaims(ctx, ports.ListClaimsRequest{
			RuntimeID:     strings.TrimSpace(finding.RuntimeID),
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

func findingEvidenceID(runtimeID string, findingID string, runID string) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	prefix := replacer.Replace(strings.TrimSpace(runtimeID) + "-" + strings.TrimSpace(findingID) + "-" + strings.TrimSpace(runID))
	return "finding-evidence-" + prefix
}
