package findingdsl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion            = "cerebro.writer.com/v1alpha1"
	KindPolicyFindingRule = "PolicyFindingRule"
	ControlMappingRelPath = "policies/cerebro/control-mapping.json"
)

type Issue struct {
	Path    string
	Message string
}

type PolicyFindingRule struct {
	APIVersion string                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                `json:"kind" yaml:"kind"`
	Metadata   PolicyRuleMetadata    `json:"metadata" yaml:"metadata"`
	Spec       PolicyFindingRuleSpec `json:"spec" yaml:"spec"`
	RelPath    string                `json:"-" yaml:"-"`
	Domain     string                `json:"-" yaml:"-"`
}

type PolicyRuleMetadata struct {
	ID           string   `json:"id" yaml:"id"`
	Name         string   `json:"name" yaml:"name"`
	Description  string   `json:"description" yaml:"description"`
	LastModified string   `json:"lastModified,omitempty" yaml:"lastModified,omitempty"`
	Tags         []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

type PolicyFindingRuleSpec struct {
	Severity       string                `json:"severity" yaml:"severity"`
	Category       string                `json:"category,omitempty" yaml:"category,omitempty"`
	Effect         string                `json:"effect,omitempty" yaml:"effect,omitempty"`
	Principal      string                `json:"principal,omitempty" yaml:"principal,omitempty"`
	Action         string                `json:"action,omitempty" yaml:"action,omitempty"`
	Resource       string                `json:"resource,omitempty" yaml:"resource,omitempty"`
	ResourceType   string                `json:"resourceType,omitempty" yaml:"resourceType,omitempty"`
	Match          PolicyRuleMatch       `json:"match" yaml:"match"`
	Remediation    PolicyRuleRemediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	RiskCategories []string              `json:"riskCategories,omitempty" yaml:"riskCategories,omitempty"`
	Frameworks     []PolicyFramework     `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	MITREAttack    []PolicyMITREAttack   `json:"mitreAttack,omitempty" yaml:"mitreAttack,omitempty"`
	Enabled        *bool                 `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

type PolicyRuleMatch struct {
	Conditions      []string `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	ConditionFormat string   `json:"conditionFormat,omitempty" yaml:"conditionFormat,omitempty"`
	Query           string   `json:"query,omitempty" yaml:"query,omitempty"`
}

type PolicyRuleRemediation struct {
	Summary string   `json:"summary,omitempty" yaml:"summary,omitempty"`
	Steps   []string `json:"steps,omitempty" yaml:"steps,omitempty"`
}

type PolicyFramework struct {
	Name     string   `json:"name" yaml:"name"`
	Controls []string `json:"controls" yaml:"controls"`
}

type PolicyMITREAttack struct {
	Tactic    string `json:"tactic" yaml:"tactic"`
	Technique string `json:"technique" yaml:"technique"`
}

type LegacyPolicy struct {
	ID               string              `json:"id"`
	LastModified     string              `json:"last_modified"`
	Name             string              `json:"name"`
	Description      string              `json:"description"`
	Effect           string              `json:"effect"`
	Principal        string              `json:"principal"`
	Action           string              `json:"action"`
	Resource         string              `json:"resource"`
	ResourceType     string              `json:"resource_type"`
	Conditions       []string            `json:"conditions"`
	ConditionFormat  string              `json:"condition_format"`
	Query            string              `json:"query"`
	Severity         string              `json:"severity"`
	Category         string              `json:"category"`
	Tags             []string            `json:"tags"`
	Remediation      string              `json:"remediation"`
	RemediationSteps []string            `json:"remediation_steps"`
	RiskCategories   []string            `json:"risk_categories"`
	Frameworks       []PolicyFramework   `json:"frameworks"`
	MITREAttack      []PolicyMITREAttack `json:"mitre_attack"`
	Enabled          *bool               `json:"enabled"`
}

func PolicyDomain(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) >= 2 && parts[0] == "policies" {
		return strings.TrimSpace(parts[1])
	}
	return "policy"
}

func LoadPolicyRules(root string) ([]PolicyFindingRule, []Issue, error) {
	root = filepath.Clean(root)
	policiesRoot := filepath.Join(root, "policies")
	var rules []PolicyFindingRule
	var issues []Issue
	err := filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel := slashRel(root, path)
		if rel == ControlMappingRelPath {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" {
			issues = append(issues, Issue{Path: rel, Message: "legacy JSON policy files are not allowed; use PolicyFindingRule DSL YAML"})
			return nil
		}
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, Issue{Path: rel, Message: "symlinked policy files are not allowed"})
			return nil
		}
		rule, parseIssues, err := LoadPolicyRuleFile(root, path)
		if err != nil {
			return err
		}
		issues = append(issues, parseIssues...)
		if len(parseIssues) == 0 {
			rules = append(rules, rule)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("policies directory not found")
		}
		return nil, nil, err
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Metadata.ID == rules[j].Metadata.ID {
			return rules[i].RelPath < rules[j].RelPath
		}
		return rules[i].Metadata.ID < rules[j].Metadata.ID
	})
	return rules, issues, nil
}

func LoadPolicyRuleFile(root string, path string) (PolicyFindingRule, []Issue, error) {
	root = filepath.Clean(root)
	rel, err := safeRel(root, path)
	if err != nil {
		return PolicyFindingRule{}, nil, err
	}
	content, err := fs.ReadFile(os.DirFS(root), rel)
	if err != nil {
		return PolicyFindingRule{}, nil, fmt.Errorf("read %s: %w", rel, err)
	}
	var rule PolicyFindingRule
	if parseErr := yaml.Unmarshal(content, &rule); parseErr != nil {
		return policyRuleIssue(rel, "invalid PolicyFindingRule YAML: "+parseErr.Error())
	}
	rule.RelPath = rel
	rule.Domain = PolicyDomain(rel)
	return rule, ValidatePolicyRule(rule), nil
}

func policyRuleIssue(path string, message string) (PolicyFindingRule, []Issue, error) {
	return PolicyFindingRule{}, []Issue{{Path: path, Message: message}}, nil
}

func ValidatePolicyRule(rule PolicyFindingRule) []Issue {
	path := rule.RelPath
	if path == "" {
		path = "<policy-rule>"
	}
	var issues []Issue
	if strings.TrimSpace(rule.APIVersion) != APIVersion {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("apiVersion must be %q", APIVersion)})
	}
	if strings.TrimSpace(rule.Kind) != KindPolicyFindingRule {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("kind must be %q", KindPolicyFindingRule)})
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "metadata.id", value: rule.Metadata.ID},
		{name: "metadata.name", value: rule.Metadata.Name},
		{name: "metadata.description", value: rule.Metadata.Description},
		{name: "spec.severity", value: rule.Spec.Severity},
	} {
		if strings.TrimSpace(field.value) == "" {
			issues = append(issues, Issue{Path: path, Message: field.name + " is required"})
		}
	}
	if severity := strings.ToUpper(strings.TrimSpace(rule.Spec.Severity)); severity != "" && !stringSetContains([]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, severity) {
		issues = append(issues, Issue{Path: path, Message: "spec.severity must be one of info, low, medium, high, critical"})
	}
	hasConditions := len(trimStrings(rule.Spec.Match.Conditions)) != 0
	hasQuery := strings.TrimSpace(rule.Spec.Match.Query) != ""
	if !hasConditions && !hasQuery {
		issues = append(issues, Issue{Path: path, Message: "spec.match.conditions or spec.match.query is required"})
	}
	if hasConditions {
		if strings.TrimSpace(rule.Spec.Effect) == "" {
			issues = append(issues, Issue{Path: path, Message: "spec.effect is required for CEL policy rules"})
		}
		if format := strings.TrimSpace(rule.Spec.Match.ConditionFormat); format != "" && !strings.EqualFold(format, "cel") {
			issues = append(issues, Issue{Path: path, Message: "spec.match.conditionFormat must be cel when present"})
		}
	}
	issues = append(issues, validateStringArray(path, "metadata.tags", rule.Metadata.Tags)...)
	issues = append(issues, validateStringArray(path, "spec.riskCategories", rule.Spec.RiskCategories)...)
	issues = append(issues, validateFrameworks(path, rule.Spec.Frameworks)...)
	return issues
}

func FromLegacyPolicy(rel string, legacy LegacyPolicy) PolicyFindingRule {
	return PolicyFindingRule{
		APIVersion: APIVersion,
		Kind:       KindPolicyFindingRule,
		Metadata: PolicyRuleMetadata{
			ID:           legacy.ID,
			Name:         legacy.Name,
			Description:  legacy.Description,
			LastModified: legacy.LastModified,
			Tags:         trimStrings(legacy.Tags),
		},
		Spec: PolicyFindingRuleSpec{
			Severity:       legacy.Severity,
			Category:       legacy.Category,
			Effect:         legacy.Effect,
			Principal:      legacy.Principal,
			Action:         legacy.Action,
			Resource:       legacy.Resource,
			ResourceType:   legacy.ResourceType,
			Match:          PolicyRuleMatch{Conditions: trimStrings(legacy.Conditions), ConditionFormat: legacy.ConditionFormat, Query: legacy.Query},
			Remediation:    PolicyRuleRemediation{Summary: legacy.Remediation, Steps: trimStrings(legacy.RemediationSteps)},
			RiskCategories: trimStrings(legacy.RiskCategories),
			Frameworks:     legacy.Frameworks,
			MITREAttack:    legacy.MITREAttack,
			Enabled:        legacy.Enabled,
		},
		RelPath: strings.TrimSpace(rel),
		Domain:  PolicyDomain(rel),
	}
}

func DecodeLegacyPolicy(content []byte) (LegacyPolicy, error) {
	var legacy LegacyPolicy
	if err := json.Unmarshal(content, &legacy); err != nil {
		return LegacyPolicy{}, err
	}
	return legacy, nil
}

func (rule PolicyFindingRule) LegacyPolicy() LegacyPolicy {
	return LegacyPolicy{
		ID:               rule.Metadata.ID,
		LastModified:     rule.Metadata.LastModified,
		Name:             rule.Metadata.Name,
		Description:      rule.Metadata.Description,
		Effect:           rule.Spec.Effect,
		Principal:        rule.Spec.Principal,
		Action:           rule.Spec.Action,
		Resource:         rule.Spec.Resource,
		ResourceType:     rule.Spec.ResourceType,
		Conditions:       trimStrings(rule.Spec.Match.Conditions),
		ConditionFormat:  rule.Spec.Match.ConditionFormat,
		Query:            rule.Spec.Match.Query,
		Severity:         rule.Spec.Severity,
		Category:         rule.Spec.Category,
		Tags:             trimStrings(rule.Metadata.Tags),
		Remediation:      rule.Spec.Remediation.Summary,
		RemediationSteps: trimStrings(rule.Spec.Remediation.Steps),
		RiskCategories:   trimStrings(rule.Spec.RiskCategories),
		Frameworks:       rule.Spec.Frameworks,
		MITREAttack:      rule.Spec.MITREAttack,
		Enabled:          rule.Spec.Enabled,
	}
}

func MarshalPolicyRuleYAML(rule PolicyFindingRule) ([]byte, error) {
	rule.RelPath = ""
	rule.Domain = ""
	return yaml.Marshal(rule)
}

func validateFrameworks(path string, frameworks []PolicyFramework) []Issue {
	if len(frameworks) == 0 {
		return []Issue{{Path: path, Message: "spec.frameworks is required"}}
	}
	var issues []Issue
	for idx, framework := range frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.frameworks[%d].name is required", idx)})
		}
		if len(framework.Controls) == 0 {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.frameworks[%d].controls is required", idx)})
		}
		for controlIdx, control := range framework.Controls {
			if strings.TrimSpace(control) == "" {
				issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.frameworks[%d].controls[%d] is required", idx, controlIdx)})
			}
		}
	}
	return issues
}

func validateStringArray(path string, field string, values []string) []Issue {
	for idx, value := range values {
		if strings.TrimSpace(value) == "" {
			return []Issue{{Path: path, Message: fmt.Sprintf("%s[%d] must be non-empty", field, idx)}}
		}
	}
	return nil
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func stringSetContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func safeRel(root string, path string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve policy root: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve policy path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", fmt.Errorf("resolve policy path relative to root: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("policy path %q escapes policy root %q", path, root)
	}
	return filepath.ToSlash(rel), nil
}
