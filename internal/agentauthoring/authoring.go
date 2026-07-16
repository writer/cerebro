package agentauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/sourcegen"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

var (
	ErrRuntimeUnavailable  = errors.New("agent authoring runtime is unavailable")
	ErrInvalidRequest      = errors.New("invalid agent authoring request")
	ErrDraftValidationFail = errors.New("agent authoring draft failed validation")
)

type StructuredDraftRequest struct {
	Kind       string         `json:"kind"`
	Prompt     string         `json:"prompt"`
	SchemaJSON string         `json:"schema_json,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
}

type StructuredDraftModel interface {
	DraftJSON(context.Context, StructuredDraftRequest) ([]byte, error)
}

type Service struct {
	Model     StructuredDraftModel
	OutputDir string
}

type PolicyRuleDraftRequest struct {
	Prompt  string
	Context map[string]any
}

type PolicyRuleDraftResult struct {
	Rule       findingdsl.PolicyFindingRule `json:"rule"`
	YAML       []byte                       `json:"yaml,omitempty"`
	Issues     []findingdsl.Issue           `json:"issues,omitempty"`
	SchemaJSON []byte                       `json:"schema_json,omitempty"`
}

type PolicyBundleDraftRequest struct {
	Prompt  string
	Domain  string
	Context map[string]any
}

type PolicyBundleDraftResult struct {
	Rule       findingdsl.PolicyFindingRule   `json:"rule"`
	PolicyPath string                         `json:"policy_path"`
	PolicyYAML []byte                         `json:"policy_yaml"`
	Suite      findingdsl.PolicyRuleTestSuite `json:"suite"`
	TestPath   string                         `json:"test_path"`
	TestYAML   []byte                         `json:"test_yaml"`
	Proof      policyauthor.ProofResult       `json:"proof"`
}

type ConnectorDefinitionDraftRequest struct {
	Prompt    string
	TenantID  string
	OutputDir string
	Context   map[string]any
}

type ConnectorDefinitionDraftResult struct {
	Definition connectordefinitions.Definition        `json:"definition"`
	Report     connectordefinitions.SupportReport     `json:"support_report"`
	Plan       *sourcegen.Result                      `json:"sourcegen_plan,omitempty"`
	Checks     []connectordefinitions.ValidationCheck `json:"checks,omitempty"`
}

func (s Service) DraftPolicyRule(ctx context.Context, request PolicyRuleDraftRequest) (*PolicyRuleDraftResult, error) {
	if s.Model == nil {
		return nil, ErrRuntimeUnavailable
	}
	prompt := strings.TrimSpace(request.Prompt)
	if prompt == "" {
		return nil, fmt.Errorf("%w: prompt is required", ErrInvalidRequest)
	}
	schema, err := findingdsl.PolicyRuleJSONSchema()
	if err != nil {
		return nil, err
	}
	raw, err := s.Model.DraftJSON(ctx, StructuredDraftRequest{
		Kind:       "policy_finding_rule",
		Prompt:     prompt,
		SchemaJSON: string(schema),
		Context:    request.Context,
	})
	if err != nil {
		return nil, err
	}
	var rule findingdsl.PolicyFindingRule
	decoderErr := json.Unmarshal(raw, &rule)
	if decoderErr != nil {
		return nil, fmt.Errorf("%w: decode policy rule draft: %w", ErrDraftValidationFail, decoderErr)
	}
	rule = findingdsl.NormalizePolicyRule(rule)
	issues := findingdsl.ValidatePolicyRule(rule)
	result := &PolicyRuleDraftResult{Rule: rule, Issues: issues, SchemaJSON: schema}
	if len(issues) != 0 {
		return result, fmt.Errorf("%w: policy rule has %d validation issue(s)", ErrDraftValidationFail, len(issues))
	}
	yamlBytes, err := findingdsl.FormatPolicyRuleYAML(rule)
	if err != nil {
		return result, fmt.Errorf("%w: format policy rule draft: %w", ErrDraftValidationFail, err)
	}
	result.YAML = yamlBytes
	return result, nil
}

// DraftPolicyBundle authors a schema-bound policy from the model response,
// derives executable tests, and proves them against authored and weakened rules.
func (s Service) DraftPolicyBundle(ctx context.Context, request PolicyBundleDraftRequest) (*PolicyBundleDraftResult, error) {
	contextValues := make(map[string]any, len(request.Context)+1)
	for key, value := range request.Context {
		contextValues[key] = value
	}
	contextValues["test_author_contract"] = map[string]any{
		"condition_shape": `cmp_eq(path(resource, "field"), scalar)`,
		"required_cases":  []string{"finding", "passing"},
		"proof":           "generated suite must reject a policy with its first condition removed",
	}
	draft, err := s.DraftPolicyRule(ctx, PolicyRuleDraftRequest{Prompt: request.Prompt, Context: contextValues})
	if err != nil {
		return nil, err
	}
	artifacts, err := policyauthor.ArtifactsForRule(request.Domain, draft.Rule)
	if err != nil {
		return nil, fmt.Errorf("%w: author policy bundle: %w", ErrDraftValidationFail, err)
	}
	proof, err := policyauthor.Prove(artifacts)
	result := &PolicyBundleDraftResult{Rule: artifacts.Rule, PolicyPath: artifacts.PolicyPath, PolicyYAML: artifacts.PolicyYAML, Suite: artifacts.Suite, TestPath: artifacts.TestPath, TestYAML: artifacts.TestYAML, Proof: proof}
	if err != nil {
		return result, fmt.Errorf("%w: prove policy bundle: %w", ErrDraftValidationFail, err)
	}
	return result, nil
}

func (s Service) DraftConnectorDefinition(ctx context.Context, request ConnectorDefinitionDraftRequest) (*ConnectorDefinitionDraftResult, error) {
	if s.Model == nil {
		return nil, ErrRuntimeUnavailable
	}
	prompt := strings.TrimSpace(request.Prompt)
	if prompt == "" {
		return nil, fmt.Errorf("%w: prompt is required", ErrInvalidRequest)
	}
	raw, err := s.Model.DraftJSON(ctx, StructuredDraftRequest{
		Kind:    "connector_definition",
		Prompt:  prompt,
		Context: request.Context,
	})
	if err != nil {
		return nil, err
	}
	var definition connectordefinitions.Definition
	if err := json.Unmarshal(raw, &definition); err != nil {
		return nil, fmt.Errorf("%w: decode connector definition draft: %w", ErrDraftValidationFail, err)
	}
	if strings.TrimSpace(definition.TenantID) == "" {
		definition.TenantID = strings.TrimSpace(request.TenantID)
	}
	definition, err = connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, fmt.Errorf("%w: normalize connector definition draft: %w", ErrDraftValidationFail, err)
	}
	report, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
	if err != nil {
		return nil, fmt.Errorf("%w: classify connector definition draft: %w", ErrDraftValidationFail, err)
	}
	result := &ConnectorDefinitionDraftResult{Definition: definition, Report: report, Checks: definition.Validation.Checks}
	if definition.Validation.Status == connectordefinitions.ValidationBlocked {
		return result, fmt.Errorf("%w: connector definition validation is blocked", ErrDraftValidationFail)
	}
	if report.Verdict != connectordefinitions.SupportVerdictSupported {
		return result, fmt.Errorf("%w: connector definition is outside the generic grammar", ErrDraftValidationFail)
	}
	outputDir := firstNonEmpty(strings.TrimSpace(request.OutputDir), strings.TrimSpace(s.OutputDir), ".")
	plan, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition: definition,
		OutputDir:  outputDir,
		DryRun:     true,
	})
	if err != nil {
		return result, fmt.Errorf("%w: generate sourcegen dry-run plan: %w", ErrDraftValidationFail, err)
	}
	result.Plan = plan
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
