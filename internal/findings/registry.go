package findings

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
)

// Rule evaluates replayed runtime events and emits persisted findings.
//
// The interface deliberately keeps source-specific detection logic out of Service so new
// platform findings can be added by registration instead of by adding more hardcoded branches
// to the replay path.
type Rule interface {
	primitives.Rule
	SupportsRuntime(*cerebrov1.SourceRuntime) bool
	Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error)
}

// Registry indexes finding rules by their stable identifier.
type Registry struct {
	rules map[string]Rule
}

// NewRegistry constructs a finding rule registry and rejects duplicate or invalid specs.
func NewRegistry(rules ...Rule) (*Registry, error) {
	indexed := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if rule == nil {
			return nil, fmt.Errorf("finding rule is required")
		}
		spec := rule.Spec()
		if spec == nil {
			return nil, fmt.Errorf("finding rule spec is required")
		}
		id := strings.TrimSpace(spec.GetId())
		if id == "" {
			return nil, fmt.Errorf("finding rule id is required")
		}
		if _, exists := indexed[id]; exists {
			return nil, fmt.Errorf("duplicate finding rule id %q", id)
		}
		indexed[id] = rule
	}
	return &Registry{rules: indexed}, nil
}

// Builtin returns the in-process finding rule registry for the rewrite skeleton.
//
// Keeping the built-in catalog in one place makes the current platform surface discoverable
// to clients and gives future rule packages one consistent registration seam.
func Builtin() *Registry {
	return &Registry{
		rules: map[string]Rule{
			githubDependabotOpenAlertRuleID:        newGitHubDependabotOpenAlertRule(),
			oktaPolicyRuleLifecycleTamperingRuleID: newOktaPolicyRuleLifecycleTamperingRule(),
		},
	}
}

// Get returns a registered finding rule by ID.
func (r *Registry) Get(id string) (Rule, bool) {
	if r == nil {
		return nil, false
	}
	rule, ok := r.rules[strings.TrimSpace(id)]
	return rule, ok
}

// List returns all registered rule specs sorted by ID.
func (r *Registry) List() []*cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.rules))
	for id := range r.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	specs := make([]*cerebrov1.RuleSpec, 0, len(ids))
	for _, id := range ids {
		specs = append(specs, r.rules[id].Spec())
	}
	return specs
}

// ForRuntime returns the registered rules that support one runtime, sorted by rule ID.
func (r *Registry) ForRuntime(runtime *cerebrov1.SourceRuntime) []Rule {
	if r == nil || runtime == nil {
		return nil
	}
	specs := r.List()
	rules := make([]Rule, 0, len(specs))
	for _, spec := range specs {
		rule, ok := r.rules[strings.TrimSpace(spec.GetId())]
		if !ok || !rule.SupportsRuntime(runtime) {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}
