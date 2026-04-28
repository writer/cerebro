package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubRule struct {
	spec               *cerebrov1.RuleSpec
	supportedSourceIDs map[string]struct{}
}

func (r *stubRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *stubRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	_, ok := r.supportedSourceIDs[runtime.GetSourceId()]
	return ok
}

func (r *stubRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func TestNewRegistryRejectsDuplicateRuleIDs(t *testing.T) {
	_, err := NewRegistry(
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-1"}},
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-1"}},
	)
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want non-nil")
	}
}

func TestRegistryGetAndListSortByRuleID(t *testing.T) {
	registry, err := NewRegistry(
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-b"}},
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-a"}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	rule, ok := registry.Get("rule-a")
	if !ok || rule == nil {
		t.Fatal("Get(rule-a) = nil, want rule")
	}
	specs := registry.List()
	if got := len(specs); got != 2 {
		t.Fatalf("len(List()) = %d, want 2", got)
	}
	if specs[0].GetId() != "rule-a" || specs[1].GetId() != "rule-b" {
		t.Fatalf("List() ids = [%q %q], want [rule-a rule-b]", specs[0].GetId(), specs[1].GetId())
	}
}

func TestRegistryForRuntimeFiltersSupportedRules(t *testing.T) {
	registry, err := NewRegistry(
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
			supportedSourceIDs: map[string]struct{}{"github": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	rules := registry.ForRuntime(&cerebrov1.SourceRuntime{SourceId: "okta"})
	if got := len(rules); got != 1 {
		t.Fatalf("len(ForRuntime()) = %d, want 1", got)
	}
	if got := rules[0].Spec().GetId(); got != "rule-a" {
		t.Fatalf("ForRuntime()[0].Spec().Id = %q, want rule-a", got)
	}
}

func TestBuiltinRulePacksFlattenIntoCatalog(t *testing.T) {
	packs := builtinRulePacks()
	if got := len(packs); got != 2 {
		t.Fatalf("len(builtinRulePacks()) = %d, want 2", got)
	}
	rules := flattenRulePacks(packs)
	if got := len(rules); got < 10 {
		t.Fatalf("len(flattenRulePacks()) = %d, want at least 10", got)
	}
	registry, err := NewRegistry(rules...)
	if err != nil {
		t.Fatalf("NewRegistry(flattenRulePacks()) error = %v", err)
	}
	if _, ok := registry.Get(githubDependabotOpenAlertRuleID); !ok {
		t.Fatalf("registry missing %q", githubDependabotOpenAlertRuleID)
	}
	if _, ok := registry.Get(githubSecretScanningDisabledRuleID); !ok {
		t.Fatalf("registry missing %q", githubSecretScanningDisabledRuleID)
	}
	if _, ok := registry.Get(oktaPolicyRuleLifecycleTamperingRuleID); !ok {
		t.Fatalf("registry missing %q", oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if _, ok := registry.Get(identityAdminPrivilegeGrantedRuleID); !ok {
		t.Fatalf("registry missing %q", identityAdminPrivilegeGrantedRuleID)
	}
}
