package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type eventRuleMatcher func(*cerebrov1.EventEnvelope) bool

type eventRuleBuilder func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error)

type RuleDefinition struct {
	ID                 string
	Name               string
	Description        string
	SourceID           string
	EventKinds         []string
	OutputKind         string
	Severity           string
	Status             string
	Maturity           string
	Tags               []string
	References         []string
	FalsePositives     []string
	Runbook            string
	RequiredAttributes []string
	FingerprintFields  []string
	ControlRefs        []ports.FindingControlRef
}

type eventRuleConfig struct {
	definition RuleDefinition
	spec       *cerebrov1.RuleSpec
	sourceID   string
	match      eventRuleMatcher
	build      eventRuleBuilder
}

type eventRule struct {
	config eventRuleConfig
}

func newEventRule(config eventRuleConfig) Rule {
	if strings.TrimSpace(config.sourceID) == "" {
		config.sourceID = config.definition.SourceID
	}
	if config.spec == nil {
		config.spec = config.definition.RuleSpec()
	}
	return &eventRule{config: config}
}

func (d RuleDefinition) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("rule id is required")
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("rule %q name is required", d.ID)
	}
	if strings.TrimSpace(d.SourceID) == "" {
		return fmt.Errorf("rule %q source id is required", d.ID)
	}
	if strings.TrimSpace(d.OutputKind) == "" {
		return fmt.Errorf("rule %q output kind is required", d.ID)
	}
	return nil
}

func (d RuleDefinition) IsZero() bool {
	return strings.TrimSpace(d.ID) == "" &&
		strings.TrimSpace(d.Name) == "" &&
		strings.TrimSpace(d.SourceID) == "" &&
		strings.TrimSpace(d.OutputKind) == ""
}

func (d RuleDefinition) RuleSpec() *cerebrov1.RuleSpec {
	if strings.TrimSpace(d.ID) == "" && strings.TrimSpace(d.Name) == "" && strings.TrimSpace(d.OutputKind) == "" {
		return nil
	}
	return &cerebrov1.RuleSpec{
		Id:          strings.TrimSpace(d.ID),
		Name:        strings.TrimSpace(d.Name),
		Description: strings.TrimSpace(d.Description),
		InputStreamIds: []string{
			"source-runtime-replay",
		},
		OutputKinds: []string{
			strings.TrimSpace(d.OutputKind),
		},
	}
}

func (d RuleDefinition) AttributeMap() map[string]string {
	attributes := map[string]string{
		"maturity":  strings.TrimSpace(d.Maturity),
		"severity":  strings.TrimSpace(d.Severity),
		"source_id": strings.TrimSpace(d.SourceID),
		"status":    strings.TrimSpace(d.Status),
	}
	joinAttribute(attributes, "event_kinds", d.EventKinds)
	joinAttribute(attributes, "fingerprint_fields", d.FingerprintFields)
	joinAttribute(attributes, "false_positives", d.FalsePositives)
	joinAttribute(attributes, "references", d.References)
	joinAttribute(attributes, "required_attributes", d.RequiredAttributes)
	joinAttribute(attributes, "tags", d.Tags)
	if strings.TrimSpace(d.Runbook) != "" {
		attributes["runbook"] = strings.TrimSpace(d.Runbook)
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func joinAttribute(attributes map[string]string, key string, values []string) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) != 0 {
		attributes[key] = strings.Join(normalized, ",")
	}
}

func eventKindMatcher(kinds ...string) eventRuleMatcher {
	allowed := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		if trimmed := strings.ToLower(strings.TrimSpace(kind)); trimmed != "" {
			allowed[trimmed] = struct{}{}
		}
	}
	return func(event *cerebrov1.EventEnvelope) bool {
		if event == nil {
			return false
		}
		_, ok := allowed[strings.ToLower(strings.TrimSpace(event.GetKind()))]
		return ok
	}
}

func eventAttributes(event *cerebrov1.EventEnvelope) map[string]string {
	if event == nil {
		return nil
	}
	return event.GetAttributes()
}

func hasRequiredAttributes(event *cerebrov1.EventEnvelope, keys ...string) bool {
	attributes := eventAttributes(event)
	for _, key := range keys {
		if strings.TrimSpace(attributes[strings.TrimSpace(key)]) == "" {
			return false
		}
	}
	return true
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
	if !r.config.definition.IsZero() {
		if err := r.config.definition.Validate(); err != nil {
			return nil, err
		}
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
