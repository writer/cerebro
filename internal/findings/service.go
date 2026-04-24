package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultEventLimit = 100
	maxEventLimit     = 1000
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
type Service struct {
	runtimeStore ports.SourceRuntimeStore
	replayer     ports.EventReplayer
	store        ports.FindingStore
	rules        *Registry
}

// EvaluateRequest scopes one replay-backed finding evaluation.
type EvaluateRequest struct {
	RuntimeID  string
	RuleID     string
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
}

// ListResult reports one persisted finding query.
type ListResult struct {
	Findings []*ports.FindingRecord
}

// New constructs a replay-backed finding service with the built-in rule registry.
func New(runtimeStore ports.SourceRuntimeStore, replayer ports.EventReplayer, store ports.FindingStore) *Service {
	return NewWithRegistry(runtimeStore, replayer, store, Builtin())
}

// NewWithRegistry constructs a replay-backed finding service with one explicit rule registry.
func NewWithRegistry(runtimeStore ports.SourceRuntimeStore, replayer ports.EventReplayer, store ports.FindingStore, rules *Registry) *Service {
	return &Service{
		runtimeStore: runtimeStore,
		replayer:     replayer,
		store:        store,
		rules:        rules,
	}
}

// EvaluateSourceRuntime replays one runtime and persists findings for one selected registered rule.
func (s *Service) EvaluateSourceRuntime(ctx context.Context, request EvaluateRequest) (*EvaluateResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil || s.rules == nil {
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
	events, err := s.replayer.Replay(ctx, ports.ReplayRequest{
		RuntimeID: runtimeID,
		Limit:     normalizeEventLimit(request.EventLimit),
	})
	if err != nil {
		return nil, fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
	}
	result := &EvaluateResult{
		Runtime:         runtime,
		Rule:            rule.Spec(),
		EventsEvaluated: uint32(len(events)),
	}
	for _, event := range events {
		emitted, err := rule.Evaluate(ctx, runtime, event)
		if err != nil {
			return nil, fmt.Errorf("evaluate finding rule %q for event %q: %w", result.Rule.GetId(), event.GetId(), err)
		}
		for _, record := range emitted {
			if record == nil {
				continue
			}
			stored, err := s.store.UpsertFinding(ctx, record)
			if err != nil {
				return nil, fmt.Errorf("persist finding for rule %q event %q: %w", result.Rule.GetId(), event.GetId(), err)
			}
			result.Findings = append(result.Findings, stored)
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
