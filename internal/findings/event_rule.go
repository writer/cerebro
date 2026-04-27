package findings

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type eventRuleMatcher func(*cerebrov1.EventEnvelope) bool

type eventRuleBuilder func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error)

type eventRuleConfig struct {
	spec     *cerebrov1.RuleSpec
	sourceID string
	match    eventRuleMatcher
	build    eventRuleBuilder
}

type eventRule struct {
	config eventRuleConfig
}

func newEventRule(config eventRuleConfig) Rule {
	return &eventRule{config: config}
}

func (r *eventRule) Spec() *cerebrov1.RuleSpec {
	if r == nil || r.config.spec == nil {
		return nil
	}
	return proto.Clone(r.config.spec).(*cerebrov1.RuleSpec)
}

func (r *eventRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), strings.TrimSpace(r.config.sourceID))
}

func (r *eventRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || r.config.match == nil || r.config.build == nil {
		return nil, errors.New("finding event rule is not configured")
	}
	if runtime == nil {
		return nil, errors.New("source runtime is required")
	}
	if !r.config.match(event) {
		return nil, nil
	}
	record, err := r.config.build(ctx, runtime, event)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}
	return []*ports.FindingRecord{record}, nil
}
