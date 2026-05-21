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

func TestLoadFindingCorrelationPatternsRejectsIncompletePattern(t *testing.T) {
	_, err := LoadFindingCorrelationPatterns([]byte(`{"version":"test","patterns":[{"id":"bad","name":"Bad","rule_ids":["one"],"dimensions":["resource"],"window":"1h","score_bonus":1,"reasons":["x"],"tests":[{"name":"t","description":"d","expect_match":true}]}]}`))
	if err == nil {
		t.Fatal("LoadFindingCorrelationPatterns() error = nil, want validation error")
	}
}
