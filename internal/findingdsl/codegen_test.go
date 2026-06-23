package findingdsl

import (
	"strings"
	"testing"
)

func TestGenerateEventRule(t *testing.T) {
	rule := PolicyFindingRule{
		Metadata: PolicyRuleMetadata{
			ID:          "example.risky_config",
			Name:        "Risky Configuration Detected",
			Description: "Detects when a configuration is set to a risky value.",
			Tags:        []string{"configuration", "security"},
		},
		Spec: PolicyFindingRuleSpec{
			Severity: "high",
			Input: PolicyRuleInput{
				EventKinds:     []string{"config.change"},
				RequiredFields: []string{"resource_urn", "config_key", "config_value"},
			},
			Assert: PolicyRuleAssert{
				All: []PolicyRuleAssertion{
					{Field: "config_value", Op: "ne", Value: ""},
					{Field: "risk_level", Op: "eq", Value: "high"},
				},
			},
			Evidence: PolicyRuleEvidence{
				FingerprintFields: []string{"resource_urn", "config_key"},
			},
			Frameworks: []PolicyFramework{
				{Name: "CIS", Controls: []string{"1.1", "1.2"}},
			},
		},
	}

	result, err := GenerateEventRule(rule)
	if err != nil {
		t.Fatalf("GenerateEventRule: %v", err)
	}

	if result.RuleID != "example.risky_config" {
		t.Errorf("RuleID = %q, want %q", result.RuleID, "example.risky_config")
	}
	if result.Constructor != "newExampleRiskyConfigRule" {
		t.Errorf("Constructor = %q, want %q", result.Constructor, "newExampleRiskyConfigRule")
	}
	if !strings.Contains(result.RuleFile, "package findings") {
		t.Error("expected package findings declaration")
	}
	if !strings.Contains(result.RuleFile, `exampleRiskyConfigRuleID = "example.risky_config"`) {
		t.Error("expected rule ID constant")
	}
	if !strings.Contains(result.RuleFile, "matchesExampleRiskyConfig") {
		t.Error("expected match function")
	}
	if !strings.Contains(result.RuleFile, "exampleRiskyConfigFinding") {
		t.Error("expected build function")
	}
	if !strings.Contains(result.RuleFile, `requiredAttributeValue(event, "risk_level") != "high"`) {
		t.Error("expected assertion condition for risk_level eq")
	}
	if !strings.Contains(result.RuleFile, `requiredAttributeValue(event, "config_value") == ""`) {
		t.Error("expected assertion condition for config_value ne")
	}
	if !strings.Contains(result.RuleFile, `Framework: "CIS"`) {
		t.Error("expected CIS framework control ref")
	}
	if !strings.Contains(result.TestFile, "TestExampleRiskyConfigFixture") {
		t.Error("expected test function")
	}
}

func TestGenerateEventRuleMissingID(t *testing.T) {
	rule := PolicyFindingRule{}
	_, err := GenerateEventRule(rule)
	if err == nil {
		t.Error("expected error for missing metadata.id")
	}
}

func TestGenerateEventRuleMissingEventKinds(t *testing.T) {
	rule := PolicyFindingRule{
		Metadata: PolicyRuleMetadata{ID: "test.rule"},
		Spec: PolicyFindingRuleSpec{
			Severity: "low",
		},
	}
	_, err := GenerateEventRule(rule)
	if err == nil {
		t.Error("expected error for missing event kinds")
	}
}
