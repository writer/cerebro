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
