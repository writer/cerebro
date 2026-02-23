package graph

import (
	"strings"
	"testing"
)

func TestRuleRegistry_AllExpectedRulesRegistered(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	missing := reg.VerifyExpectedRules()
	if len(missing) > 0 {
		t.Errorf("expected rules not registered: %v", missing)
	}
}

func TestRuleRegistry_RuleValidation(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	errs := reg.Validate()
	if len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("validation error: %v", err)
		}
	}
}

func TestRuleRegistry_NoDuplicateIDs(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	rules := reg.GetAllRules()
	seen := make(map[string]bool)

	for _, rule := range rules {
		if seen[rule.Metadata.ID] {
			t.Errorf("duplicate rule ID: %s", rule.Metadata.ID)
		}
		seen[rule.Metadata.ID] = true
	}
}

func TestRuleRegistry_AllRulesHaveRequiredFields(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	for _, rule := range reg.GetAllRules() {
		if rule.Rule.ID == "" {
			t.Errorf("rule missing ID")
		}
		if rule.Rule.Name == "" {
			t.Errorf("rule %s missing name", rule.Rule.ID)
		}
		if rule.Rule.Description == "" {
			t.Errorf("rule %s missing description", rule.Rule.ID)
		}
		if rule.Rule.Severity == "" {
			t.Errorf("rule %s missing severity", rule.Rule.ID)
		}
		if rule.Rule.Detector == nil {
			t.Errorf("rule %s missing detector function", rule.Rule.ID)
		}
		if rule.Metadata.Category == "" {
			t.Errorf("rule %s missing category", rule.Rule.ID)
		}
	}
}

func TestRuleRegistry_AllRulesHaveTags(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	for _, rule := range reg.GetAllRules() {
		if len(rule.Rule.Tags) == 0 {
			t.Errorf("rule %s has no tags", rule.Rule.ID)
		}
	}
}

func TestRuleRegistry_ProviderSpecificRulesHaveProvider(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	providerCategories := map[RuleCategory]string{
		RuleCategoryAWS:        "aws",
		RuleCategoryGCP:        "gcp",
		RuleCategoryAzure:      "azure",
		RuleCategoryKubernetes: "k8s",
	}

	for _, rule := range reg.GetAllRules() {
		expectedProvider, isProviderSpecific := providerCategories[rule.Metadata.Category]
		if isProviderSpecific && rule.Metadata.Provider == "" {
			t.Errorf("rule %s in category %s should have provider %s", rule.Rule.ID, rule.Metadata.Category, expectedProvider)
		}
	}
}

func TestRuleRegistry_MinimumRulesPerCategory(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	stats := reg.Stats()

	minimums := map[RuleCategory]int{
		RuleCategoryCore:       3,
		RuleCategoryAWS:        3,
		RuleCategoryGCP:        3,
		RuleCategoryAzure:      2,
		RuleCategoryKubernetes: 3,
		RuleCategoryIdentity:   3,
	}

	for category, min := range minimums {
		if count := stats.ByCategory[category]; count < min {
			t.Errorf("category %s has %d rules, expected at least %d", category, count, min)
		}
	}
}

func TestRuleRegistry_AllCriticalRulesHaveMITREMapping(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	for _, rule := range reg.GetAllRules() {
		if rule.Rule.Severity == SeverityCritical && len(rule.Metadata.MITREIDs) == 0 {
			t.Errorf("critical rule %s should have MITRE ATT&CK mapping", rule.Rule.ID)
		}
	}
}

func TestRuleRegistry_Stats(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	stats := reg.Stats()

	if stats.TotalRules == 0 {
		t.Error("expected at least one rule registered")
	}

	t.Logf("Registry stats: %d total rules, %d enabled", stats.TotalRules, stats.EnabledCount)
	t.Logf("By category: %v", stats.ByCategory)
	t.Logf("By provider: %v", stats.ByProvider)
	t.Logf("By severity: %v", stats.BySeverity)
}

func TestRuleRegistry_RuleIDFormat(t *testing.T) {
	RegisterAllRules()
	reg := GlobalRegistry()

	for _, rule := range reg.GetAllRules() {
		id := rule.Rule.ID

		// Core rules should be TC### format
		if strings.HasPrefix(id, "TC") && !strings.Contains(id, "-") {
			if len(id) < 4 || len(id) > 5 {
				t.Errorf("core rule ID %s should be TC### format", id)
			}
		}

		// Provider rules should be TC-PROVIDER-### format
		if strings.Contains(id, "-") {
			parts := strings.Split(id, "-")
			if len(parts) < 3 {
				t.Errorf("provider rule ID %s should be TC-PROVIDER-### format", id)
			}
		}
	}
}

func TestNewToxicCombinationEngineFromRegistry(t *testing.T) {
	engine := NewToxicCombinationEngineFromRegistry()

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	if len(engine.rules) == 0 {
		t.Error("expected rules from registry")
	}

	// Should have same count as enabled rules in registry
	RegisterAllRules()
	enabledCount := GlobalRegistry().Stats().EnabledCount
	if len(engine.rules) != enabledCount {
		t.Errorf("engine has %d rules, registry has %d enabled", len(engine.rules), enabledCount)
	}
}

func TestRuleRegistry_DisabledRulesNotInEngine(t *testing.T) {
	// Create a new registry for this test
	reg := NewRuleRegistry()

	// Register an enabled and disabled rule
	enabledRule := &ToxicCombinationRule{
		ID:          "TEST-001",
		Name:        "Enabled Test Rule",
		Description: "Test rule that is enabled",
		Severity:    SeverityHigh,
		Tags:        []string{"test"},
		Detector:    func(g *Graph, n *Node) *ToxicCombination { return nil },
	}

	disabledRule := &ToxicCombinationRule{
		ID:          "TEST-002",
		Name:        "Disabled Test Rule",
		Description: "Test rule that is disabled",
		Severity:    SeverityMedium,
		Tags:        []string{"test"},
		Detector:    func(g *Graph, n *Node) *ToxicCombination { return nil },
	}

	reg.MustRegister(enabledRule, RuleMetadata{
		ID:       "TEST-001",
		Name:     "Enabled Test Rule",
		Category: RuleCategoryCore,
		Enabled:  true,
	})

	reg.MustRegister(disabledRule, RuleMetadata{
		ID:       "TEST-002",
		Name:     "Disabled Test Rule",
		Category: RuleCategoryCore,
		Enabled:  false,
	})

	enabled := reg.GetEnabledRules()
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled rule, got %d", len(enabled))
	}

	if enabled[0].ID != "TEST-001" {
		t.Errorf("expected enabled rule TEST-001, got %s", enabled[0].ID)
	}
}

func TestRuleRegistry_DuplicateRegistrationFails(t *testing.T) {
	reg := NewRuleRegistry()

	rule := &ToxicCombinationRule{
		ID:          "DUP-001",
		Name:        "Duplicate Test",
		Description: "Test duplicate registration",
		Severity:    SeverityHigh,
		Tags:        []string{"test"},
		Detector:    func(g *Graph, n *Node) *ToxicCombination { return nil },
	}

	meta := RuleMetadata{
		ID:       "DUP-001",
		Name:     "Duplicate Test",
		Category: RuleCategoryCore,
		Enabled:  true,
	}

	// First registration should succeed
	if err := reg.Register(rule, meta); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second registration should fail
	if err := reg.Register(rule, meta); err == nil {
		t.Error("expected duplicate registration to fail")
	}
}

func TestRuleRegistry_InvalidRuleRejected(t *testing.T) {
	reg := NewRuleRegistry()

	tests := []struct {
		name string
		rule *ToxicCombinationRule
		meta RuleMetadata
	}{
		{
			name: "nil rule",
			rule: nil,
			meta: RuleMetadata{ID: "NIL-001", Name: "Nil", Category: RuleCategoryCore},
		},
		{
			name: "missing rule ID",
			rule: &ToxicCombinationRule{
				Name:        "No ID",
				Description: "Missing ID",
				Severity:    SeverityHigh,
				Tags:        []string{"test"},
				Detector:    func(g *Graph, n *Node) *ToxicCombination { return nil },
			},
			meta: RuleMetadata{ID: "NOID-001", Name: "No ID", Category: RuleCategoryCore},
		},
		{
			name: "missing detector",
			rule: &ToxicCombinationRule{
				ID:          "NODET-001",
				Name:        "No Detector",
				Description: "Missing detector",
				Severity:    SeverityHigh,
				Tags:        []string{"test"},
			},
			meta: RuleMetadata{ID: "NODET-001", Name: "No Detector", Category: RuleCategoryCore},
		},
		{
			name: "invalid severity",
			rule: &ToxicCombinationRule{
				ID:          "BADSEV-001",
				Name:        "Bad Severity",
				Description: "Invalid severity",
				Severity:    "super-critical",
				Tags:        []string{"test"},
				Detector:    func(g *Graph, n *Node) *ToxicCombination { return nil },
			},
			meta: RuleMetadata{ID: "BADSEV-001", Name: "Bad Severity", Category: RuleCategoryCore},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := reg.Register(tt.rule, tt.meta); err == nil {
				t.Errorf("expected registration to fail for %s", tt.name)
			}
		})
	}
}
