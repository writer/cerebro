package findings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	correlationruntime "github.com/writer/cerebro/internal/correlation/runtime"

	_ "embed"
)

//go:embed correlation_patterns/builtin.json
var builtinCorrelationPatternCatalog []byte

var builtinCorrelationPatterns []FindingCorrelationPattern

func init() {
	patterns, err := loadBuiltinFindingCorrelationPatterns()
	if err != nil {
		panic(fmt.Sprintf("build builtin finding correlation patterns: %v", err))
	}
	builtinCorrelationPatterns = patterns
}

type correlationPatternCatalog struct {
	Version  string                  `json:"version"`
	Patterns []correlationPatternRaw `json:"patterns"`
}

type correlationPatternRaw struct {
	ID         string                          `json:"id"`
	Name       string                          `json:"name"`
	RuleIDs    []string                        `json:"rule_ids"`
	Dimensions []string                        `json:"dimensions"`
	Window     string                          `json:"window"`
	ScoreBonus int                             `json:"score_bonus"`
	Reasons    []string                        `json:"reasons"`
	Tests      []FindingCorrelationPatternTest `json:"tests"`
}

// BuiltinFindingCorrelationPatterns returns the checked-in declarative pattern catalog
// plus runtime correlation hints that enrich underlying state-anchored findings.
func BuiltinFindingCorrelationPatterns() []FindingCorrelationPattern {
	return cloneFindingCorrelationPatterns(builtinCorrelationPatterns)
}

// BuiltinFindingCorrelationPatternCatalogJSON returns the canonical checked-in catalog bytes.
func BuiltinFindingCorrelationPatternCatalogJSON() []byte {
	return append([]byte(nil), builtinCorrelationPatternCatalog...)
}

func LoadFindingCorrelationPatterns(data []byte) ([]FindingCorrelationPattern, error) {
	var catalog correlationPatternCatalog
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode correlation pattern catalog: %w", err)
	}
	if strings.TrimSpace(catalog.Version) == "" {
		return nil, fmt.Errorf("correlation pattern catalog version is required")
	}
	patterns := make([]FindingCorrelationPattern, 0, len(catalog.Patterns))
	seen := map[string]struct{}{}
	for _, raw := range catalog.Patterns {
		pattern, err := normalizeCorrelationPattern(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[pattern.ID]; ok {
			return nil, fmt.Errorf("duplicate correlation pattern id %q", pattern.ID)
		}
		seen[pattern.ID] = struct{}{}
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(i int, j int) bool {
		return patterns[i].ID < patterns[j].ID
	})
	return patterns, nil
}

func loadBuiltinFindingCorrelationPatterns() ([]FindingCorrelationPattern, error) {
	patterns, err := LoadFindingCorrelationPatterns(builtinCorrelationPatternCatalog)
	if err != nil {
		return nil, err
	}
	runtimePatterns, err := LoadRuntimeCorrelationPatterns(correlationruntime.BuiltinHints())
	if err != nil {
		return nil, err
	}
	return mergeFindingCorrelationPatterns(patterns, runtimePatterns)
}

func LoadRuntimeCorrelationPatterns(hints []correlationruntime.CorrelationHint) ([]FindingCorrelationPattern, error) {
	patterns := make([]FindingCorrelationPattern, 0, len(hints))
	for _, hint := range hints {
		tests := make([]FindingCorrelationPatternTest, 0, len(hint.Tests))
		for _, test := range hint.Tests {
			tests = append(tests, FindingCorrelationPatternTest{
				Name:        test.Name,
				Description: test.Description,
				ExpectMatch: test.ExpectMatch,
			})
		}
		pattern, err := normalizeCorrelationPattern(correlationPatternRaw{
			ID:         hint.ID,
			Name:       hint.Name,
			RuleIDs:    hint.RuleIDs,
			Dimensions: hint.Dimensions,
			Window:     hint.Window.String(),
			ScoreBonus: hint.ScoreBonus,
			Reasons:    hint.Reasons,
			Tests:      tests,
		})
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func mergeFindingCorrelationPatterns(groups ...[]FindingCorrelationPattern) ([]FindingCorrelationPattern, error) {
	merged := []FindingCorrelationPattern{}
	seen := map[string]struct{}{}
	for _, group := range groups {
		for _, pattern := range group {
			if _, ok := seen[pattern.ID]; ok {
				return nil, fmt.Errorf("duplicate correlation pattern id %q", pattern.ID)
			}
			seen[pattern.ID] = struct{}{}
			merged = append(merged, pattern)
		}
	}
	sort.Slice(merged, func(i int, j int) bool {
		return merged[i].ID < merged[j].ID
	})
	return merged, nil
}

func ValidateFindingCorrelationPatterns(patterns []FindingCorrelationPattern, knownRuleIDs map[string]struct{}) error {
	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		raw := correlationPatternRaw{
			ID:         pattern.ID,
			Name:       pattern.Name,
			RuleIDs:    pattern.RuleIDs,
			Dimensions: pattern.Dimensions,
			Window:     pattern.Window.String(),
			ScoreBonus: pattern.ScoreBonus,
			Reasons:    pattern.Reasons,
			Tests:      pattern.Tests,
		}
		normalized, err := normalizeCorrelationPattern(raw)
		if err != nil {
			return err
		}
		if _, ok := seen[normalized.ID]; ok {
			return fmt.Errorf("duplicate correlation pattern id %q", normalized.ID)
		}
		seen[normalized.ID] = struct{}{}
		for _, ruleID := range normalized.RuleIDs {
			if _, ok := knownRuleIDs[ruleID]; !ok {
				return fmt.Errorf("correlation pattern %q references unknown rule %q", normalized.ID, ruleID)
			}
		}
	}
	return nil
}

func normalizeCorrelationPattern(raw correlationPatternRaw) (FindingCorrelationPattern, error) {
	pattern := FindingCorrelationPattern{
		ID:         strings.TrimSpace(raw.ID),
		Name:       strings.TrimSpace(raw.Name),
		RuleIDs:    uniqueSortedStrings(raw.RuleIDs),
		Dimensions: uniqueSortedStrings(raw.Dimensions),
		ScoreBonus: raw.ScoreBonus,
		Reasons:    uniqueSortedStrings(raw.Reasons),
		Tests:      raw.Tests,
	}
	if pattern.ID == "" {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern id is required")
	}
	if pattern.Name == "" {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q name is required", pattern.ID)
	}
	if len(pattern.RuleIDs) < 2 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q requires at least two rule_ids", pattern.ID)
	}
	if len(pattern.Dimensions) == 0 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q requires dimensions", pattern.ID)
	}
	for _, dimension := range pattern.Dimensions {
		if !validCorrelationDimension(dimension) {
			return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q has invalid dimension %q", pattern.ID, dimension)
		}
	}
	windowText := strings.TrimSpace(raw.Window)
	if windowText == "" {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q window is required", pattern.ID)
	}
	window, err := time.ParseDuration(windowText)
	if err != nil {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q window is invalid: %w", pattern.ID, err)
	}
	if window <= 0 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q window must be positive", pattern.ID)
	}
	pattern.Window = window
	if pattern.ScoreBonus <= 0 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q score_bonus must be positive", pattern.ID)
	}
	if len(pattern.Reasons) == 0 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q requires reasons", pattern.ID)
	}
	if len(pattern.Tests) == 0 {
		return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q requires test cases", pattern.ID)
	}
	for idx, test := range pattern.Tests {
		if strings.TrimSpace(test.Name) == "" {
			return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q tests[%d].name is required", pattern.ID, idx)
		}
		if strings.TrimSpace(test.Description) == "" {
			return FindingCorrelationPattern{}, fmt.Errorf("correlation pattern %q tests[%d].description is required", pattern.ID, idx)
		}
	}
	return pattern, nil
}

func cloneFindingCorrelationPatterns(patterns []FindingCorrelationPattern) []FindingCorrelationPattern {
	if len(patterns) == 0 {
		return nil
	}
	cloned := make([]FindingCorrelationPattern, 0, len(patterns))
	for _, pattern := range patterns {
		cloned = append(cloned, FindingCorrelationPattern{
			ID:         pattern.ID,
			Name:       pattern.Name,
			RuleIDs:    cloneStringSlice(pattern.RuleIDs),
			Dimensions: cloneStringSlice(pattern.Dimensions),
			Window:     pattern.Window,
			ScoreBonus: pattern.ScoreBonus,
			Reasons:    cloneStringSlice(pattern.Reasons),
			Tests:      cloneFindingCorrelationPatternTests(pattern.Tests),
		})
	}
	return cloned
}

func cloneFindingCorrelationPatternTests(tests []FindingCorrelationPatternTest) []FindingCorrelationPatternTest {
	if len(tests) == 0 {
		return nil
	}
	cloned := make([]FindingCorrelationPatternTest, len(tests))
	copy(cloned, tests)
	return cloned
}

func validCorrelationDimension(value string) bool {
	switch value {
	case compoundRiskKindActor, compoundRiskKindResource, compoundRiskKindRepository, compoundRiskKindContainerImage, compoundRiskKindSource, compoundRiskKindType:
		return true
	default:
		return false
	}
}
