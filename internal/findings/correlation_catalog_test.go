package findings

import (
	"testing"

	correlationruntime "github.com/writer/cerebro/internal/correlation/runtime"
)

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

func TestBuiltinFindingCorrelationPatternsIncludeRuntimeHints(t *testing.T) {
	patterns := BuiltinFindingCorrelationPatterns()
	byID := map[string]FindingCorrelationPattern{}
	for _, pattern := range patterns {
		byID[pattern.ID] = pattern
	}
	for _, hint := range correlationruntime.BuiltinHints() {
		pattern, ok := byID[hint.ID]
		if !ok {
			t.Fatalf("runtime hint %q missing from finding correlation patterns", hint.ID)
		}
		if got, want := pattern.Window, hint.Window; got != want {
			t.Fatalf("pattern %q Window = %v, want %v", hint.ID, got, want)
		}
		if !cloudStringSlicesEqual(pattern.RuleIDs, uniqueSortedStrings(hint.RuleIDs)) {
			t.Fatalf("pattern %q RuleIDs = %#v, want %#v", hint.ID, pattern.RuleIDs, uniqueSortedStrings(hint.RuleIDs))
		}
		if !cloudStringSlicesEqual(pattern.Dimensions, uniqueSortedStrings(hint.Dimensions)) {
			t.Fatalf("pattern %q Dimensions = %#v, want %#v", hint.ID, pattern.Dimensions, uniqueSortedStrings(hint.Dimensions))
		}
		if !cloudStringSlicesEqual(pattern.Reasons, uniqueSortedStrings(hint.Reasons)) {
			t.Fatalf("pattern %q Reasons = %#v, want %#v", hint.ID, pattern.Reasons, uniqueSortedStrings(hint.Reasons))
		}
	}
}

func TestBuiltinFindingCorrelationPatternsIncludeSupplyChainAndContainerGaps(t *testing.T) {
	patterns := BuiltinFindingCorrelationPatterns()
	byID := map[string]FindingCorrelationPattern{}
	for _, pattern := range patterns {
		byID[pattern.ID] = pattern
	}
	for _, patternID := range []string{
		"github-code-security-control-disabled-with-dependabot-alert",
		"container-image-promoted-vulnerability-with-trivy-scan",
		"runtime-active-threat-with-public-exposure",
	} {
		if _, ok := byID[patternID]; !ok {
			t.Fatalf("BuiltinFindingCorrelationPatterns() missing %q", patternID)
		}
	}
	if pattern := byID["container-image-promoted-vulnerability-with-trivy-scan"]; !cloudStringSlicesEqual(pattern.Dimensions, []string{compoundRiskKindContainerImage}) {
		t.Fatalf("container pattern Dimensions = %#v, want container_image", pattern.Dimensions)
	}
}

func TestLoadFindingCorrelationPatternsRejectsIncompletePattern(t *testing.T) {
	_, err := LoadFindingCorrelationPatterns([]byte(`{"version":"test","patterns":[{"id":"bad","name":"Bad","rule_ids":["one"],"dimensions":["resource"],"window":"1h","score_bonus":1,"reasons":["x"],"tests":[{"name":"t","description":"d","expect_match":true}]}]}`))
	if err == nil {
		t.Fatal("LoadFindingCorrelationPatterns() error = nil, want validation error")
	}
}
