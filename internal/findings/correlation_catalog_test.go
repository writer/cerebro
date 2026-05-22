package findings

import "testing"

func TestBuiltinFindingCorrelationPatternsLoad(t *testing.T) {
	patterns := BuiltinFindingCorrelationPatterns()
	if len(patterns) == 0 {
		t.Fatal("BuiltinFindingCorrelationPatterns() = 0, want checked-in patterns")
	}
	knownRuleIDs := map[string]struct{}{}
	for _, metadata := range BuiltinRuleMetadata() {
		knownRuleIDs[metadata.ID] = struct{}{}
	}
	if err := ValidateFindingCorrelationPatterns(patterns, knownRuleIDs); err != nil {
		t.Fatalf("ValidateFindingCorrelationPatterns() error = %v", err)
	}
	for _, pattern := range patterns {
		if len(pattern.Tests) == 0 {
			t.Fatalf("pattern %q has no catalog tests", pattern.ID)
		}
	}
}

func TestBuiltinFindingCorrelationPatternsReturnsIsolatedCopies(t *testing.T) {
	first := BuiltinFindingCorrelationPatterns()
	if len(first) == 0 || len(first[0].RuleIDs) == 0 || len(first[0].Tests) == 0 {
		t.Fatal("BuiltinFindingCorrelationPatterns() missing expected test data")
	}
	first[0].ID = "mutated"
	first[0].RuleIDs[0] = "mutated"
	first[0].Tests[0].Name = "mutated"

	second := BuiltinFindingCorrelationPatterns()
	if second[0].ID == "mutated" {
		t.Fatal("BuiltinFindingCorrelationPatterns() returned mutable cached pattern id")
	}
	if second[0].RuleIDs[0] == "mutated" {
		t.Fatal("BuiltinFindingCorrelationPatterns() returned mutable cached rule ids")
	}
	if second[0].Tests[0].Name == "mutated" {
		t.Fatal("BuiltinFindingCorrelationPatterns() returned mutable cached tests")
	}
}

func TestLoadFindingCorrelationPatternsRejectsIncompletePattern(t *testing.T) {
	_, err := LoadFindingCorrelationPatterns([]byte(`{"version":"test","patterns":[{"id":"bad","name":"Bad","rule_ids":["one"],"dimensions":["resource"],"window":"1h","score_bonus":1,"reasons":["x"],"tests":[{"name":"t","description":"d","expect_match":true}]}]}`))
	if err == nil {
		t.Fatal("LoadFindingCorrelationPatterns() error = nil, want validation error")
	}
}
