package rulecatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

// MaxDocumentBytes bounds one authored rule document.
const MaxDocumentBytes = 256 << 10

// Document formats accepted by the editor.
const (
	FormatYAML = "yaml"
	FormatJSON = "json"
)

// Issue is one authoring problem. Errors block saving; warnings do not.
type Issue struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ValidationResult reports whether a document is a valid custom rule and
// returns its canonical YAML and JSON forms plus a catalog preview.
type ValidationResult struct {
	Valid   bool    `json:"valid"`
	Issues  []Issue `json:"issues"`
	YAML    string  `json:"yaml,omitempty"`
	JSON    string  `json:"json,omitempty"`
	Preview *Detail `json:"preview,omitempty"`
}

// TestResult reports how a document evaluates against one sample resource.
type TestResult struct {
	Valid     bool    `json:"valid"`
	Issues    []Issue `json:"issues"`
	Evaluated bool    `json:"evaluated"`
	Matched   bool    `json:"matched"`
	Message   string  `json:"message"`
}

// CustomMetadata carries store-owned attribution for a saved custom rule.
type CustomMetadata struct {
	CreatedBy string
	UpdatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// customRelPath keeps parser diagnostics and the policy domain stable for
// authored rules, which never live in the checked-in policies tree.
const customRelPath = "policies/custom/rule.yaml"

// ParseDocument decodes one YAML or JSON PolicyFindingRule and returns
// blocking issues. Built-in IDs are reserved so custom rules cannot shadow them.
func ParseDocument(format string, content string) (findingdsl.PolicyFindingRule, []Issue) {
	if len(content) > MaxDocumentBytes {
		return findingdsl.PolicyFindingRule{}, []Issue{errorIssue(fmt.Sprintf("document exceeds %d KiB", MaxDocumentBytes>>10))}
	}
	if strings.TrimSpace(content) == "" {
		return findingdsl.PolicyFindingRule{}, []Issue{errorIssue("document is empty")}
	}
	payload := []byte(content)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatYAML:
	case FormatJSON:
		var rule findingdsl.PolicyFindingRule
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&rule); err != nil {
			return findingdsl.PolicyFindingRule{}, []Issue{errorIssue("invalid PolicyFindingRule JSON: " + err.Error())}
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return findingdsl.PolicyFindingRule{}, []Issue{errorIssue("PolicyFindingRule JSON must contain one document")}
		}
		converted, err := findingdsl.MarshalPolicyRuleYAML(rule)
		if err != nil {
			return findingdsl.PolicyFindingRule{}, []Issue{errorIssue("convert JSON rule: " + err.Error())}
		}
		payload = converted
	default:
		return findingdsl.PolicyFindingRule{}, []Issue{errorIssue("format must be yaml or json")}
	}
	rule, parseIssues, err := findingdsl.ParsePolicyRuleYAML(customRelPath, payload)
	if err != nil {
		return findingdsl.PolicyFindingRule{}, []Issue{errorIssue(err.Error())}
	}
	issues := make([]Issue, 0, len(parseIssues))
	for _, issue := range parseIssues {
		issues = append(issues, errorIssue(issue.Message))
	}
	if id := strings.TrimSpace(rule.Metadata.ID); id != "" && IsBuiltinID(id) {
		issues = append(issues, errorIssue(fmt.Sprintf("metadata.id %q is used by a built-in rule; choose a new id", id)))
	}
	return rule, issues
}

// Validate parses, validates, and lints a document without saving it.
func Validate(format string, content string) ValidationResult {
	rule, issues := ParseDocument(format, content)
	result := ValidationResult{Issues: issues}
	if HasErrors(issues) {
		return result
	}
	for _, issue := range findingdsl.LintPolicyRule(rule) {
		result.Issues = append(result.Issues, Issue{Severity: "warning", Message: issue.Message})
	}
	yamlDocument, jsonDocument, err := CanonicalDocuments(rule)
	if err != nil {
		result.Issues = append(result.Issues, errorIssue(err.Error()))
		return result
	}
	preview := CustomDetail(rule, yamlDocument, CustomMetadata{})
	result.Valid = true
	result.YAML = yamlDocument
	result.JSON = jsonDocument
	result.Preview = &preview
	return result
}

// SampleResource is the resource attribute document a rule test evaluates.
type SampleResource map[string]any

// Test evaluates a document's CEL conditions against one sample resource.
func Test(format string, content string, resource SampleResource) TestResult {
	rule, issues := ParseDocument(format, content)
	result := TestResult{Issues: issues}
	if HasErrors(issues) {
		result.Message = "Fix the validation errors before testing."
		return result
	}
	result.Valid = true
	if len(rule.Spec.Match.Conditions) == 0 {
		result.Message = "Sample testing supports CEL condition rules. Graph and SQL rules are checked against collected data when live evaluation runs."
		return result
	}
	if resource == nil {
		resource = SampleResource{}
	}
	matched, err := findingdsl.EvaluatePolicyRuleTestCase(rule, findingdsl.PolicyRuleTestCase{Name: "sample", Resource: resource})
	if err != nil {
		result.Issues = append(result.Issues, errorIssue("evaluate conditions: "+err.Error()))
		result.Message = "The conditions could not be evaluated against the sample resource."
		return result
	}
	result.Evaluated = true
	result.Matched = matched
	if matched {
		result.Message = "The sample resource matches every condition, so this rule would raise a finding."
	} else {
		result.Message = "The sample resource does not match, so this rule would not raise a finding."
	}
	return result
}

// CanonicalDocuments renders a parsed rule as normalized YAML and indented JSON.
func CanonicalDocuments(rule findingdsl.PolicyFindingRule) (string, string, error) {
	normalized := findingdsl.NormalizePolicyRule(rule)
	yamlDocument, err := findingdsl.MarshalPolicyRuleYAML(normalized)
	if err != nil {
		return "", "", fmt.Errorf("render rule YAML: %w", err)
	}
	jsonDocument, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("render rule JSON: %w", err)
	}
	return string(yamlDocument), string(jsonDocument), nil
}

// StoredCustomDetail renders a saved custom rule. Stored documents were
// validated on save, so only parse failures are reported here.
func StoredCustomDetail(record ports.CustomFindingRule) (Detail, error) {
	rule, issues, err := findingdsl.ParsePolicyRuleYAML(customRelPath, []byte(record.Document))
	if err != nil {
		return Detail{}, err
	}
	if strings.TrimSpace(rule.Metadata.ID) == "" {
		messages := make([]string, 0, len(issues))
		for _, issue := range issues {
			messages = append(messages, issue.Message)
		}
		return Detail{}, fmt.Errorf("stored custom rule %q cannot be parsed: %s", record.ID, strings.Join(messages, "; "))
	}
	return CustomDetail(rule, record.Document, CustomMetadata{
		CreatedBy: record.CreatedBy,
		UpdatedBy: record.UpdatedBy,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}), nil
}

// CustomDetail builds the catalog view of a custom rule.
func CustomDetail(rule findingdsl.PolicyFindingRule, document string, metadata CustomMetadata) Detail {
	spec := rule.Spec
	resourceType := firstNonEmpty(spec.ResourceType, spec.Resource)
	classification := ClassifyPolicy(spec.Category, resourceType, rule.Metadata.Tags, spec.Input.SourceKinds)
	evaluation := EvaluationCEL
	detection := DetectionPosture
	switch {
	case strings.TrimSpace(spec.Graph.Query) != "":
		evaluation = EvaluationGraph
		detection = DetectionCorrelation
		classification = correlateUnanchoredGraph(classification)
	case strings.TrimSpace(spec.Match.Query) != "":
		evaluation = EvaluationSQL
	}
	if classification.Domain == DomainCorrelation {
		detection = DetectionCorrelation
	}
	controls := []ControlRef{}
	for _, framework := range spec.Frameworks {
		for _, control := range framework.Controls {
			controls = append(controls, ControlRef{Framework: strings.TrimSpace(framework.Name), Control: strings.TrimSpace(control)})
		}
	}
	mitre := make([]MITRERef, 0, len(spec.MITREAttack))
	for _, ref := range spec.MITREAttack {
		mitre = append(mitre, MITRERef{Tactic: strings.TrimSpace(ref.Tactic), Technique: strings.TrimSpace(ref.Technique)})
	}
	description := strings.TrimSpace(rule.Metadata.Description)
	steps := append([]string(nil), spec.Remediation.Steps...)
	if len(steps) == 0 {
		steps = append(steps, spec.Actions.Remediation.Steps...)
	}
	detail := Detail{
		Entry: Entry{
			ID:              strings.TrimSpace(rule.Metadata.ID),
			Name:            strings.TrimSpace(rule.Metadata.Name),
			Summary:         description,
			Severity:        normalizeSeverity(spec.Severity),
			Origin:          OriginCustom,
			Domain:          classification.Domain,
			Posture:         classification.Posture,
			Provider:        classification.Provider,
			Category:        strings.TrimSpace(spec.Category),
			ResourceType:    resourceType,
			Evaluation:      evaluation,
			Detection:       detection,
			Enabled:         spec.Enabled == nil || *spec.Enabled,
			Maturity:        "custom",
			Tags:            append([]string(nil), rule.Metadata.Tags...),
			Frameworks:      frameworkNames(controls),
			MITRETechniques: mitreTechniques(mitre),
		},
		Description:       description,
		AttackDescription: attackDescription(description, spec.Audit.RiskStatement, mitre),
		Remediation:       firstNonEmpty(spec.Remediation.Summary, spec.Audit.RemediationIntent),
		RemediationSteps:  steps,
		FalsePositives:    append([]string(nil), spec.Audit.FalsePositives...),
		References:        append([]string(nil), rule.Metadata.References...),
		ControlRefs:       controls,
		MITREAttack:       mitre,
		Conditions:        append([]string(nil), spec.Match.Conditions...),
		Query:             strings.TrimSpace(spec.Match.Query),
		GraphQuery:        strings.TrimSpace(spec.Graph.Query),
		GraphSourceKinds:  append([]string(nil), spec.Input.SourceKinds...),
		FingerprintFields: append([]string(nil), spec.Evidence.FingerprintFields...),
		Document:          document,
		Editable:          true,
		Testable:          len(spec.Match.Conditions) != 0,
		Authorship: Authorship{
			CreatedBy: strings.TrimSpace(metadata.CreatedBy),
			UpdatedBy: strings.TrimSpace(metadata.UpdatedBy),
		},
	}
	if !metadata.CreatedAt.IsZero() {
		detail.CreatedAt = metadata.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !metadata.UpdatedAt.IsZero() {
		detail.UpdatedAt = metadata.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return detail
}

func errorIssue(message string) Issue {
	return Issue{Severity: "error", Message: strings.TrimSpace(message)}
}

// HasErrors reports whether any issue blocks saving.
func HasErrors(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}
