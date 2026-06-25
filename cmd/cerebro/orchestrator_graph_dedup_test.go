package main

import (
	"sort"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
)

func TestMarkOrchestratorTenantGraphRulesEvaluatedTracksRuleIDsPerTenant(t *testing.T) {
	evaluatedByTenant := map[string]map[string]struct{}{}

	markOrchestratorTenantGraphRulesEvaluated(evaluatedByTenant, "writer", &findings.EvaluateGraphRulesResult{
		Evaluations: []*findings.GraphRuleEvaluationResult{
			{Rule: &cerebrov1.RuleSpec{Id: "rule-a"}},
			{Rule: &cerebrov1.RuleSpec{Id: "rule-b"}},
			nil,
			{Rule: nil},
			{Rule: &cerebrov1.RuleSpec{Id: "  "}},
		},
	})

	got := orchestratorEvaluatedGraphRuleIDs(evaluatedByTenant["writer"])
	sort.Strings(got)
	if want := []string{"rule-a", "rule-b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("evaluated rule ids = %v, want %v", got, want)
	}

	// A second runtime in the same tenant accumulates without dropping prior ids.
	markOrchestratorTenantGraphRulesEvaluated(evaluatedByTenant, "writer", &findings.EvaluateGraphRulesResult{
		Evaluations: []*findings.GraphRuleEvaluationResult{{Rule: &cerebrov1.RuleSpec{Id: "rule-c"}}},
	})
	if got := len(evaluatedByTenant["writer"]); got != 3 {
		t.Fatalf("tenant rule count = %d, want 3", got)
	}

	// A different tenant is tracked independently.
	if got := orchestratorEvaluatedGraphRuleIDs(evaluatedByTenant["other"]); got != nil {
		t.Fatalf("untracked tenant ids = %v, want nil", got)
	}
}

func TestOrchestratorEvaluatedGraphRuleIDsEmpty(t *testing.T) {
	if got := orchestratorEvaluatedGraphRuleIDs(nil); got != nil {
		t.Fatalf("orchestratorEvaluatedGraphRuleIDs(nil) = %v, want nil", got)
	}
	if got := orchestratorEvaluatedGraphRuleIDs(map[string]struct{}{}); got != nil {
		t.Fatalf("orchestratorEvaluatedGraphRuleIDs(empty) = %v, want nil", got)
	}
}
