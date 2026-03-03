package policy

import "testing"

const maxQueryOnlyPoliciesBaseline = 504

func TestQueryOnlyPolicyCountDoesNotGrowBeyondBaseline(t *testing.T) {
	engine := NewEngine()
	if err := engine.LoadPolicies("../../policies"); err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	queryOnlyCount := len(engine.ListQueryPolicies())
	if queryOnlyCount > maxQueryOnlyPoliciesBaseline {
		t.Fatalf("query-only policy count grew beyond baseline: got %d, baseline %d", queryOnlyCount, maxQueryOnlyPoliciesBaseline)
	}
}
