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
	Severity       string                 `json:"severity" yaml:"severity"`
	Category       string                 `json:"category,omitempty" yaml:"category,omitempty"`
	Effect         string                 `json:"effect,omitempty" yaml:"effect,omitempty"`
	Principal      string                 `json:"principal,omitempty" yaml:"principal,omitempty"`
	Action         string                 `json:"action,omitempty" yaml:"action,omitempty"`
	Resource       string                 `json:"resource,omitempty" yaml:"resource,omitempty"`
	ResourceType   string                 `json:"resourceType,omitempty" yaml:"resourceType,omitempty"`
	Match          PolicyRuleMatch        `json:"match" yaml:"match"`
	Remediation    PolicyRuleRemediation  `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	RiskCategories []string               `json:"riskCategories,omitempty" yaml:"riskCategories,omitempty"`
	Frameworks     []PolicyFramework      `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	MITREAttack    []PolicyMITREAttack    `json:"mitreAttack,omitempty" yaml:"mitreAttack,omitempty"`
	Input          PolicyRuleInput        `json:"input,omitempty" yaml:"input,omitempty"`
	Assert         PolicyRuleAssert       `json:"assert,omitempty" yaml:"assert,omitempty"`
	Context        PolicyRuleContext      `json:"context,omitempty" yaml:"context,omitempty"`
	Evidence       PolicyRuleEvidence     `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Audit          PolicyRuleAudit        `json:"audit,omitempty" yaml:"audit,omitempty"`
	Verification   PolicyRuleVerification `json:"verification,omitempty" yaml:"verification,omitempty"`
	Actions        PolicyRuleActions      `json:"actions,omitempty" yaml:"actions,omitempty"`
	Enabled        *bool                  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
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

type PolicyRuleInput struct {
	SourceKinds          []string            `json:"sourceKinds,omitempty" yaml:"sourceKinds,omitempty"`
	EventKinds           []string            `json:"eventKinds,omitempty" yaml:"eventKinds,omitempty"`
	RequiredClaims       []string            `json:"requiredClaims,omitempty" yaml:"requiredClaims,omitempty"`
	RequiredFields       []string            `json:"requiredFields,omitempty" yaml:"requiredFields,omitempty"`
	RequiredFieldsByKind map[string][]string `json:"requiredFieldsByKind,omitempty" yaml:"requiredFieldsByKind,omitempty"`
	FreshnessSLA         string              `json:"freshnessSLA,omitempty" yaml:"freshnessSLA,omitempty"`
}

type PolicyRuleAssert struct {
	All []PolicyRuleAssertion `json:"all,omitempty" yaml:"all,omitempty"`
	Any []PolicyRuleAssertion `json:"any,omitempty" yaml:"any,omitempty"`
}

type PolicyRuleAssertion struct {
	Field string `json:"field,omitempty" yaml:"field,omitempty"`
	Op    string `json:"op,omitempty" yaml:"op,omitempty"`
	Value any    `json:"value,omitempty" yaml:"value,omitempty"`
}

type PolicyRuleContext struct {
	Graph               PolicyRuleGraphContext         `json:"graph,omitempty" yaml:"graph,omitempty"`
	SeverityAdjustments []PolicyRuleSeverityAdjustment `json:"severityAdjustments,omitempty" yaml:"severityAdjustments,omitempty"`
}

type PolicyRuleGraphContext struct {
	Anchors []string `json:"anchors,omitempty" yaml:"anchors,omitempty"`
	Enrich  []string `json:"enrich,omitempty" yaml:"enrich,omitempty"`
}

type PolicyRuleSeverityAdjustment struct {
	When  string `json:"when,omitempty" yaml:"when,omitempty"`
	Set   string `json:"set,omitempty" yaml:"set,omitempty"`
	Delta string `json:"delta,omitempty" yaml:"delta,omitempty"`
}

type PolicyRuleEvidence struct {
	Type              string   `json:"type,omitempty" yaml:"type,omitempty"`
	AssessmentMethods []string `json:"assessmentMethods,omitempty" yaml:"assessmentMethods,omitempty"`
	RequiredForAudit  bool     `json:"requiredForAudit,omitempty" yaml:"requiredForAudit,omitempty"`
	FreshnessSLA      string   `json:"freshnessSLA,omitempty" yaml:"freshnessSLA,omitempty"`
	AcceptableSources []string `json:"acceptableSources,omitempty" yaml:"acceptableSources,omitempty"`
	RequiredFields    []string `json:"requiredFields,omitempty" yaml:"requiredFields,omitempty"`
	FingerprintFields []string `json:"fingerprintFields,omitempty" yaml:"fingerprintFields,omitempty"`
}

type PolicyRuleAudit struct {
	EvidenceType       string                         `json:"evidenceType,omitempty" yaml:"evidenceType,omitempty"`
	AssessmentMethods  []string                       `json:"assessmentMethods,omitempty" yaml:"assessmentMethods,omitempty"`
	FreshnessSLA       string                         `json:"freshnessSLA,omitempty" yaml:"freshnessSLA,omitempty"`
	AuditorStatement   string                         `json:"auditorStatement,omitempty" yaml:"auditorStatement,omitempty"`
	AuditorGuidance    string                         `json:"auditorGuidance,omitempty" yaml:"auditorGuidance,omitempty"`
	RiskStatement      string                         `json:"riskStatement,omitempty" yaml:"riskStatement,omitempty"`
	RemediationIntent  string                         `json:"remediationIntent,omitempty" yaml:"remediationIntent,omitempty"`
	AcceptableEvidence []PolicyRuleAcceptableEvidence `json:"acceptableEvidence,omitempty" yaml:"acceptableEvidence,omitempty"`
	ExceptionPolicy    PolicyRuleExceptionPolicy      `json:"exceptionPolicy,omitempty" yaml:"exceptionPolicy,omitempty"`
	ExceptionGuidance  []string                       `json:"exceptionGuidance,omitempty" yaml:"exceptionGuidance,omitempty"`
	FalsePositives     []string                       `json:"falsePositives,omitempty" yaml:"falsePositives,omitempty"`
}

type PolicyRuleAcceptableEvidence struct {
	Source string   `json:"source,omitempty" yaml:"source,omitempty"`
	Fields []string `json:"fields,omitempty" yaml:"fields,omitempty"`
}

type PolicyRuleExceptionPolicy struct {
	MaxAge           string `json:"maxAge,omitempty" yaml:"maxAge,omitempty"`
	RequiresApproval bool   `json:"requiresApproval,omitempty" yaml:"requiresApproval,omitempty"`
}

type PolicyRuleVerification struct {
	Fixtures         []PolicyRuleVerificationFixture `json:"fixtures,omitempty" yaml:"fixtures,omitempty"`
	MutationChecks   []string                        `json:"mutationChecks,omitempty" yaml:"mutationChecks,omitempty"`
	RemediationCheck PolicyRuleRemediationCheck      `json:"remediationCheck,omitempty" yaml:"remediationCheck,omitempty"`
}

type PolicyRuleVerificationFixture struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Expect      string `json:"expect,omitempty" yaml:"expect,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type PolicyRuleRemediationCheck struct {
	RerunAfter     string `json:"rerunAfter,omitempty" yaml:"rerunAfter,omitempty"`
	ExpectedStatus string `json:"expectedStatus,omitempty" yaml:"expectedStatus,omitempty"`
}

type PolicyRuleActions struct {
	Owner        PolicyRuleActionOwner        `json:"owner,omitempty" yaml:"owner,omitempty"`
	Remediation  PolicyRuleActionRemediation  `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Effort       string                       `json:"effort,omitempty" yaml:"effort,omitempty"`
	BlastRadius  PolicyRuleActionBlastRadius  `json:"blastRadius,omitempty" yaml:"blastRadius,omitempty"`
	Verification PolicyRuleActionVerification `json:"verification,omitempty" yaml:"verification,omitempty"`
}

type PolicyRuleActionOwner struct {
	From     string `json:"from,omitempty" yaml:"from,omitempty"`
	Fallback string `json:"fallback,omitempty" yaml:"fallback,omitempty"`
}

type PolicyRuleActionRemediation struct {
	Type  string   `json:"type,omitempty" yaml:"type,omitempty"`
	Steps []string `json:"steps,omitempty" yaml:"steps,omitempty"`
}

type PolicyRuleActionBlastRadius struct {
	EstimateFrom string `json:"estimateFrom,omitempty" yaml:"estimateFrom,omitempty"`
}

type PolicyRuleActionVerification struct {
	RerunPolicy bool `json:"rerunPolicy,omitempty" yaml:"rerunPolicy,omitempty"`
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
	seenIDs := map[string]string{}
	for _, rule := range rules {
		policyID := strings.TrimSpace(rule.Metadata.ID)
		if policyID == "" {
			continue
		}
		if existing := seenIDs[policyID]; existing != "" {
			issues = append(issues, Issue{Path: rule.RelPath, Message: fmt.Sprintf("duplicate metadata.id %q also used by %s", policyID, existing)})
			continue
		}
		seenIDs[policyID] = rule.RelPath
	}
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
	hasAssert := policyAssertConfigured(rule.Spec.Assert)
	if !hasConditions && !hasQuery && !hasAssert {
		issues = append(issues, Issue{Path: path, Message: "spec.match.conditions, spec.match.query, or spec.assert is required"})
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
	issues = append(issues, validatePolicyRuleContract(path, rule.Spec)...)
	return issues
}

func validatePolicyRuleContract(path string, spec PolicyFindingRuleSpec) []Issue {
	var issues []Issue
	issues = append(issues, validateStringArray(path, "spec.input.sourceKinds", spec.Input.SourceKinds)...)
	issues = append(issues, validateStringArray(path, "spec.input.eventKinds", spec.Input.EventKinds)...)
	issues = append(issues, validateStringArray(path, "spec.input.requiredClaims", spec.Input.RequiredClaims)...)
	issues = append(issues, validateStringArray(path, "spec.input.requiredFields", spec.Input.RequiredFields)...)
	issues = append(issues, validateStringArrayMap(path, "spec.input.requiredFieldsByKind", spec.Input.RequiredFieldsByKind)...)
	issues = append(issues, validateDurationField(path, "spec.input.freshnessSLA", spec.Input.FreshnessSLA)...)
	issues = append(issues, validateAssertions(path, "spec.assert.all", spec.Assert.All)...)
	issues = append(issues, validateAssertions(path, "spec.assert.any", spec.Assert.Any)...)
	issues = append(issues, validateStringArray(path, "spec.context.graph.anchors", spec.Context.Graph.Anchors)...)
	issues = append(issues, validateStringArray(path, "spec.context.graph.enrich", spec.Context.Graph.Enrich)...)
	issues = append(issues, validateSeverityAdjustments(path, spec.Context.SeverityAdjustments)...)
	issues = append(issues, validatePolicyRuleEvidence(path, spec.Evidence)...)
	issues = append(issues, validatePolicyRuleAudit(path, spec.Audit)...)
	issues = append(issues, validatePolicyRuleVerification(path, spec.Verification)...)
	issues = append(issues, validatePolicyRuleActions(path, spec.Actions)...)
	return issues
}

func policyAssertConfigured(assert PolicyRuleAssert) bool {
	return len(assert.All) != 0 || len(assert.Any) != 0
}

func validateAssertions(path string, field string, assertions []PolicyRuleAssertion) []Issue {
	var issues []Issue
	for idx, assertion := range assertions {
		if strings.TrimSpace(assertion.Field) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d].field is required", field, idx)})
		}
		op := strings.ToLower(strings.TrimSpace(assertion.Op))
		if op == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d].op is required", field, idx)})
			continue
		}
		if !stringSetContains([]string{"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists", "is_true", "is_false"}, op) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d].op must be one of eq, ne, in, not_in, gt, gte, lt, lte, exists, is_true, is_false", field, idx)})
		}
	}
	return issues
}

func validateSeverityAdjustments(path string, adjustments []PolicyRuleSeverityAdjustment) []Issue {
	var issues []Issue
	for idx, adjustment := range adjustments {
		if strings.TrimSpace(adjustment.When) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.context.severityAdjustments[%d].when is required", idx)})
		}
		if strings.TrimSpace(adjustment.Set) == "" && strings.TrimSpace(adjustment.Delta) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.context.severityAdjustments[%d].set or delta is required", idx)})
		}
		if set := strings.ToUpper(strings.TrimSpace(adjustment.Set)); set != "" && !stringSetContains([]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, set) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.context.severityAdjustments[%d].set must be one of info, low, medium, high, critical", idx)})
		}
	}
	return issues
}

func validatePolicyRuleEvidence(path string, evidence PolicyRuleEvidence) []Issue {
	var issues []Issue
	issues = append(issues, validateAssessmentMethods(path, "spec.evidence.assessmentMethods", evidence.AssessmentMethods)...)
	issues = append(issues, validateDurationField(path, "spec.evidence.freshnessSLA", evidence.FreshnessSLA)...)
	issues = append(issues, validateStringArray(path, "spec.evidence.acceptableSources", evidence.AcceptableSources)...)
	issues = append(issues, validateStringArray(path, "spec.evidence.requiredFields", evidence.RequiredFields)...)
	issues = append(issues, validateFingerprintFields(path, "spec.evidence.fingerprintFields", evidence.FingerprintFields)...)
	return issues
}

func validatePolicyRuleAudit(path string, audit PolicyRuleAudit) []Issue {
	var issues []Issue
	issues = append(issues, validateAssessmentMethods(path, "spec.audit.assessmentMethods", audit.AssessmentMethods)...)
	issues = append(issues, validateDurationField(path, "spec.audit.freshnessSLA", audit.FreshnessSLA)...)
	issues = append(issues, validateDurationField(path, "spec.audit.exceptionPolicy.maxAge", audit.ExceptionPolicy.MaxAge)...)
	issues = append(issues, validateStringArray(path, "spec.audit.exceptionGuidance", audit.ExceptionGuidance)...)
	issues = append(issues, validateStringArray(path, "spec.audit.falsePositives", audit.FalsePositives)...)
	for idx, evidence := range audit.AcceptableEvidence {
		if strings.TrimSpace(evidence.Source) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.audit.acceptableEvidence[%d].source is required", idx)})
		}
		issues = append(issues, validateStringArray(path, fmt.Sprintf("spec.audit.acceptableEvidence[%d].fields", idx), evidence.Fields)...)
	}
	return issues
}

func validatePolicyRuleVerification(path string, verification PolicyRuleVerification) []Issue {
	var issues []Issue
	issues = append(issues, validateStringArray(path, "spec.verification.mutationChecks", verification.MutationChecks)...)
	for idx, fixture := range verification.Fixtures {
		if strings.TrimSpace(fixture.Name) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.verification.fixtures[%d].name is required", idx)})
		}
		expect := strings.ToLower(strings.TrimSpace(fixture.Expect))
		if expect == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.verification.fixtures[%d].expect is required", idx)})
			continue
		}
		if !stringSetContains([]string{"finding", "pass"}, expect) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.verification.fixtures[%d].expect must be finding or pass", idx)})
		}
	}
	if status := strings.TrimSpace(verification.RemediationCheck.ExpectedStatus); status != "" && !stringSetContains([]string{"pass", "finding", "closed", "open"}, strings.ToLower(status)) {
		issues = append(issues, Issue{Path: path, Message: "spec.verification.remediationCheck.expectedStatus must be pass, finding, closed, or open"})
	}
	return issues
}

func validatePolicyRuleActions(path string, actions PolicyRuleActions) []Issue {
	var issues []Issue
	issues = append(issues, validateStringArray(path, "spec.actions.remediation.steps", actions.Remediation.Steps)...)
	if effort := strings.ToLower(strings.TrimSpace(actions.Effort)); effort != "" && !stringSetContains([]string{"low", "medium", "high"}, effort) {
		issues = append(issues, Issue{Path: path, Message: "spec.actions.effort must be low, medium, or high"})
	}
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
	var issues []Issue
	for idx, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d] must be non-empty", field, idx)})
		}
	}
	return issues
}

func validateStringArrayMap(path string, field string, values map[string][]string) []Issue {
	var issues []Issue
	for key, entries := range values {
		if strings.TrimSpace(key) == "" {
			issues = append(issues, Issue{Path: path, Message: field + " keys must be non-empty"})
			continue
		}
		issues = append(issues, validateStringArray(path, field+"."+key, entries)...)
	}
	return issues
}

func validateAssessmentMethods(path string, field string, values []string) []Issue {
	var issues []Issue
	issues = append(issues, validateStringArray(path, field, values)...)
	for idx, value := range values {
		method := strings.ToLower(strings.TrimSpace(value))
		if method == "" {
			continue
		}
		if !stringSetContains([]string{"examine", "test", "interview", "observe"}, method) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d] must be one of examine, test, interview, observe", field, idx)})
		}
	}
	return issues
}

func validateDurationField(path string, field string, value string) []Issue {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	digitEnd := 0
	for digitEnd < len(trimmed) && trimmed[digitEnd] >= '0' && trimmed[digitEnd] <= '9' {
		digitEnd++
	}
	if digitEnd == 0 || digitEnd == len(trimmed) {
		return []Issue{{Path: path, Message: field + " must use a duration like 24h, 14d, or 2w"}}
	}
	switch strings.ToLower(strings.TrimSpace(trimmed[digitEnd:])) {
	case "s", "m", "h", "d", "w":
		return nil
	default:
		return []Issue{{Path: path, Message: field + " must use units s, m, h, d, or w"}}
	}
}

func validateFingerprintFields(path string, field string, values []string) []Issue {
	var issues []Issue
	issues = append(issues, validateStringArray(path, field, values)...)
	for idx, value := range values {
		if unstableFingerprintField(value) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s[%d] must not use event IDs, timestamps, run IDs, cursors, display names, or labels", field, idx)})
		}
	}
	return issues
}

func unstableFingerprintField(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "event_id", "event_ids", "occurred_at", "observed_at", "timestamp", "ts", "run_id", "cursor", "page_token", "display_name", "name", "label":
		return true
	default:
		return false
	}
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
