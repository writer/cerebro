package findingdsl

import (
	"fmt"
	"path/filepath"
	"strings"
)

type NewPolicyRuleInput struct {
	ID              string
	Domain          string
	Name            string
	Description     string
	References      []string
	Severity        string
	Effect          string
	Resource        string
	ResourceType    string
	Conditions      []string
	Query           string
	Graph           PolicyRuleGraphFinding
	Tags            []string
	RiskCategories  []string
	Frameworks      []PolicyFramework
	Remediation     string
	RemediationStep []string
}

func NewPolicyRule(input NewPolicyRuleInput) PolicyFindingRule {
	severity := strings.TrimSpace(input.Severity)
	if severity == "" {
		severity = "medium"
	}
	effect := strings.TrimSpace(input.Effect)
	if effect == "" && len(trimStrings(input.Conditions)) != 0 {
		effect = "forbid"
	}
	rule := PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:          strings.TrimSpace(input.ID),
			Name:        strings.TrimSpace(input.Name),
			Description: strings.TrimSpace(input.Description),
			Tags:        trimStrings(input.Tags),
			References:  trimStrings(input.References),
		},
		Spec: PolicyFindingRuleSpec{
			Severity:       severity,
			Effect:         effect,
			Resource:       strings.TrimSpace(input.Resource),
			ResourceType:   strings.TrimSpace(input.ResourceType),
			Match:          PolicyRuleMatch{Conditions: trimStrings(input.Conditions), Query: strings.TrimSpace(input.Query)},
			Graph:          input.Graph,
			Remediation:    PolicyRuleRemediation{Summary: strings.TrimSpace(input.Remediation), Steps: trimStrings(input.RemediationStep)},
			RiskCategories: trimStrings(input.RiskCategories),
			Frameworks:     normalizeFrameworks(input.Frameworks),
		},
	}
	if len(rule.Spec.Match.Conditions) != 0 {
		rule.Spec.Match.ConditionFormat = "cel"
	}
	if domain := strings.TrimSpace(input.Domain); domain != "" {
		rule.RelPath = PolicyRuleRelPath(domain, rule.Metadata.ID)
		rule.Domain = domain
	}
	return NormalizePolicyRule(rule)
}

func NormalizePolicyRule(rule PolicyFindingRule) PolicyFindingRule {
	rule.APIVersion = firstNonEmpty(strings.TrimSpace(rule.APIVersion), APIVersion)
	rule.Kind = firstNonEmpty(strings.TrimSpace(rule.Kind), KindPolicyFindingRule)
	rule.Metadata.ID = strings.TrimSpace(rule.Metadata.ID)
	rule.Metadata.Name = strings.TrimSpace(rule.Metadata.Name)
	rule.Metadata.Description = strings.TrimSpace(rule.Metadata.Description)
	rule.Metadata.LastModified = strings.TrimSpace(rule.Metadata.LastModified)
	rule.Metadata.Tags = trimStrings(rule.Metadata.Tags)
	rule.Metadata.References = trimStrings(rule.Metadata.References)
	rule.Spec.Severity = strings.TrimSpace(rule.Spec.Severity)
	rule.Spec.Category = strings.TrimSpace(rule.Spec.Category)
	rule.Spec.Effect = strings.TrimSpace(rule.Spec.Effect)
	rule.Spec.Principal = strings.TrimSpace(rule.Spec.Principal)
	rule.Spec.Action = strings.TrimSpace(rule.Spec.Action)
	rule.Spec.Resource = strings.TrimSpace(rule.Spec.Resource)
	rule.Spec.ResourceType = strings.TrimSpace(rule.Spec.ResourceType)
	rule.Spec.Match.Conditions = trimStrings(rule.Spec.Match.Conditions)
	rule.Spec.Match.ConditionFormat = strings.TrimSpace(rule.Spec.Match.ConditionFormat)
	if strings.EqualFold(rule.Spec.Match.ConditionFormat, "cel") {
		rule.Spec.Match.ConditionFormat = "cel"
	}
	rule.Spec.Match.Query = strings.TrimSpace(rule.Spec.Match.Query)
	rule.Spec.Remediation.Summary = strings.TrimSpace(rule.Spec.Remediation.Summary)
	rule.Spec.Remediation.Steps = trimStrings(rule.Spec.Remediation.Steps)
	rule.Spec.RiskCategories = trimStrings(rule.Spec.RiskCategories)
	rule.Spec.Frameworks = normalizeFrameworks(rule.Spec.Frameworks)
	rule.Spec.Graph.Query = strings.TrimSpace(rule.Spec.Graph.Query)
	rule.Spec.Graph.RequiredColumns = trimStrings(rule.Spec.Graph.RequiredColumns)
	rule.Spec.Graph.Params = normalizeGraphParams(rule.Spec.Graph.Params)
	for idx := range rule.Spec.MITREAttack {
		rule.Spec.MITREAttack[idx].Tactic = strings.TrimSpace(rule.Spec.MITREAttack[idx].Tactic)
		rule.Spec.MITREAttack[idx].Technique = strings.TrimSpace(rule.Spec.MITREAttack[idx].Technique)
	}
	return rule
}

func FormatPolicyRuleYAML(rule PolicyFindingRule) ([]byte, error) {
	return MarshalPolicyRuleYAML(NormalizePolicyRule(rule))
}

func PolicyRuleRelPath(domain string, id string) string {
	return filepath.ToSlash(filepath.Join("policies", strings.TrimSpace(domain), strings.TrimSpace(id)+".yaml"))
}

func ParseFrameworkSpec(value string) (PolicyFramework, error) {
	name, controls, ok := strings.Cut(value, ":")
	if !ok {
		return PolicyFramework{}, fmt.Errorf("framework %q must use name:control[,control] format", value)
	}
	framework := PolicyFramework{Name: strings.TrimSpace(name)}
	for _, control := range strings.Split(controls, ",") {
		if trimmed := strings.TrimSpace(control); trimmed != "" {
			framework.Controls = append(framework.Controls, trimmed)
		}
	}
	if framework.Name == "" || len(framework.Controls) == 0 {
		return PolicyFramework{}, fmt.Errorf("framework %q must include name and at least one control", value)
	}
	return framework, nil
}

func normalizeFrameworks(frameworks []PolicyFramework) []PolicyFramework {
	out := make([]PolicyFramework, 0, len(frameworks))
	for _, framework := range frameworks {
		normalized := PolicyFramework{Name: strings.TrimSpace(framework.Name), Controls: trimStrings(framework.Controls)}
		if normalized.Name != "" || len(normalized.Controls) != 0 {
			out = append(out, normalized)
		}
	}
	return out
}

func normalizeGraphParams(params map[string]any) map[string]any {
	if len(params) == 0 {
		return nil
	}
	normalized := map[string]any{}
	for key, value := range params {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			normalized[trimmed] = value
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
