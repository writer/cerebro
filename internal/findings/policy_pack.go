package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

const pilotPolicyRuleID = "ai-agent-tool-allowlist-required"

// BuiltinWithPolicyOverrides replaces supported compiled policy entries with
// verified declarative values while retaining kernel-owned evaluation code.
func BuiltinWithPolicyOverrides(overrides map[string][]byte) (*Registry, error) {
	for ruleID := range overrides {
		if ruleID != pilotPolicyRuleID {
			return nil, fmt.Errorf("policy override %q is not supported", ruleID)
		}
	}
	rules := flattenRulePacks(builtinRulePacks())
	for ruleID, payload := range overrides {
		replacement, err := policyRuleFromYAML(ruleID, payload)
		if err != nil {
			return nil, err
		}
		replaced := false
		for index, rule := range rules {
			if rule != nil && rule.Spec() != nil && rule.Spec().GetId() == ruleID {
				rules[index] = replacement
				replaced = true
				break
			}
		}
		if !replaced {
			return nil, fmt.Errorf("compiled policy %q is not registered", ruleID)
		}
	}
	return NewRegistry(rules...)
}

func policyRuleFromYAML(ruleID string, payload []byte) (Rule, error) {
	parsed, issues, err := findingdsl.ParsePolicyRuleYAML("policies/ai/"+ruleID+".yaml", payload)
	if err != nil {
		return nil, err
	}
	if len(issues) != 0 {
		return nil, fmt.Errorf("policy %s failed validation: %v", ruleID, issues)
	}
	if strings.TrimSpace(parsed.Metadata.ID) != ruleID {
		return nil, fmt.Errorf("policy id %q does not match selected rule %q", parsed.Metadata.ID, ruleID)
	}
	config, ok := compiledPolicyRuleConfig(ruleID)
	if !ok {
		return nil, fmt.Errorf("compiled policy %q is not available", ruleID)
	}
	config.Definition.Name = strings.TrimSpace(parsed.Metadata.Name)
	config.Definition.Description = strings.TrimSpace(parsed.Metadata.Description)
	config.Definition.Severity = strings.ToUpper(strings.TrimSpace(parsed.Spec.Severity))
	config.Definition.Tags = sortedPolicyStrings(parsed.Metadata.Tags)
	config.Definition.References = sortedPolicyStrings(parsed.Metadata.References)
	config.Definition.ControlRefs = policyControlRefs(parsed)
	config.Definition.MITREAttack = policyMITREAttackRefs(parsed)
	config.Definition.Runbook = policyRunbook(parsed)
	config.Conditions = append([]string(nil), parsed.Spec.Match.Conditions...)
	config.Resource = strings.TrimSpace(parsed.Spec.Resource)
	config.ResourceType = strings.TrimSpace(parsed.Spec.ResourceType)
	if config.ResourceType == "" {
		config.ResourceType = config.Resource
	}
	config.Category = strings.TrimSpace(parsed.Domain)
	config.EvidenceMode = strings.TrimSpace(parsed.Spec.Match.ConditionFormat)
	config.Enabled = parsed.Spec.Enabled == nil || *parsed.Spec.Enabled
	return newPolicyCatalogRule(config), nil
}

func compiledPolicyRuleConfig(ruleID string) (policyRuleConfig, bool) {
	for _, config := range generatedPolicyRuleCatalog {
		if config.Definition.ID == ruleID {
			return normalizePolicyRuleConfig(config), true
		}
	}
	return policyRuleConfig{}, false
}

func policyControlRefs(rule findingdsl.PolicyFindingRule) []ports.FindingControlRef {
	var refs []ports.FindingControlRef
	for _, framework := range rule.Spec.Frameworks {
		for _, control := range framework.Controls {
			refs = append(refs, ports.FindingControlRef{FrameworkName: strings.TrimSpace(framework.Name), ControlID: strings.TrimSpace(control)})
		}
	}
	return refs
}

func policyMITREAttackRefs(rule findingdsl.PolicyFindingRule) []MITREAttackRef {
	refs := make([]MITREAttackRef, 0, len(rule.Spec.MITREAttack))
	for _, attack := range rule.Spec.MITREAttack {
		refs = append(refs, MITREAttackRef{Tactic: strings.TrimSpace(attack.Tactic), Technique: strings.TrimSpace(attack.Technique)})
	}
	return refs
}

func policyRunbook(rule findingdsl.PolicyFindingRule) string {
	steps := append([]string{strings.TrimSpace(rule.Spec.Remediation.Summary)}, rule.Spec.Remediation.Steps...)
	var normalized []string
	for _, step := range steps {
		if step = strings.TrimSpace(step); step != "" {
			normalized = append(normalized, step)
		}
	}
	return strings.Join(normalized, " ")
}

func sortedPolicyStrings(values []string) []string {
	result := append([]string(nil), values...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return result
}
