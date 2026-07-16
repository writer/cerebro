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
	Model            StructuredDraftModel
	OutputDir        string
	PolicyGraphStore findingdsl.PolicyGraphTestStore
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
	Prompt        string
	Domain        string
	Context       map[string]any
	GraphEvidence *policyauthor.GraphEvidence
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
		if key == "source_evidence" {
			contextValues[key] = newPolicyAuthoringEvidenceRedactor().redact(normalizePolicyAuthoringEvidence(value), "")
			continue
		}
		contextValues[key] = value
	}
	if request.GraphEvidence != nil {
		graphContext, err := policyauthor.GraphEvidenceModelContext(*request.GraphEvidence)
		if err != nil {
			return nil, fmt.Errorf("%w: graph evidence: %w", ErrInvalidRequest, err)
		}
		contextValues["graph_evidence"] = graphContext
	}
	contextValues["test_author_contract"] = map[string]any{
		"condition_shape": `cmp_eq(path(resource, "field"), scalar)`,
		"required_cases":  []string{"finding", "passing"},
		"proof":           "generated suite must reject a policy with its first condition removed",
		"grounding": map[string]any{
			"input":         "source event attributes and projected entity and relation contracts",
			"preserve":      []string{"source kinds", "entity types", "relations", "risk-relevant state"},
			"redact":        []string{"tenant IDs", "account IDs", "resource ARNs", "session names", "endpoints", "secret names", "secret references"},
			"current_state": "stateful findings must use authoritative inventory state; historical audit state supplies provenance only",
			"causality":     "graph passing fixtures must retain the same nodes and remove exactly one policy-critical edge",
		},
	}
	draft, err := s.DraftPolicyRule(ctx, PolicyRuleDraftRequest{Prompt: request.Prompt, Context: contextValues})
	if err != nil {
		return nil, err
	}
	var artifacts policyauthor.Artifacts
	if request.GraphEvidence != nil {
		artifacts, err = policyauthor.ArtifactsForRuleWithGraphEvidence(request.Domain, draft.Rule, request.GraphEvidence)
	} else {
		artifacts, err = policyauthor.ArtifactsForRule(request.Domain, draft.Rule)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: author policy bundle: %w", ErrDraftValidationFail, err)
	}
	var proof policyauthor.ProofResult
	if request.GraphEvidence != nil && s.PolicyGraphStore != nil {
		proof, err = policyauthor.ProveWithGraphStore(ctx, artifacts, s.PolicyGraphStore)
	} else {
		proof, err = policyauthor.Prove(artifacts)
	}
	result := &PolicyBundleDraftResult{Rule: artifacts.Rule, PolicyPath: artifacts.PolicyPath, PolicyYAML: artifacts.PolicyYAML, Suite: artifacts.Suite, TestPath: artifacts.TestPath, TestYAML: artifacts.TestYAML, Proof: proof}
	if err != nil {
		return result, fmt.Errorf("%w: prove policy bundle: %w", ErrDraftValidationFail, err)
	}
	return result, nil
}

func normalizePolicyAuthoringEvidence(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "<redacted>"
	}
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return "<redacted>"
	}
	return normalized
}

type policyAuthoringEvidenceRedactor struct {
	identifiers map[string]string
	nextID      int
	nextKey     int
}

func newPolicyAuthoringEvidenceRedactor() *policyAuthoringEvidenceRedactor {
	return &policyAuthoringEvidenceRedactor{identifiers: map[string]string{}}
}

func (r *policyAuthoringEvidenceRedactor) redact(value any, key string) any {
	normalizedKey := strings.ToLower(strings.TrimSpace(key))
	if policyAuthoringEvidenceIdentifierKey(normalizedKey) {
		canonical, err := json.Marshal(value)
		if err != nil {
			return "<redacted>"
		}
		raw := string(canonical)
		if token, ok := r.identifiers[raw]; ok {
			return token
		}
		r.nextID++
		token := fmt.Sprintf("aws-ref-%d", r.nextID)
		r.identifiers[raw] = token
		return token
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			redacted[r.redactKey(childKey)] = r.redact(childValue, childKey)
		}
		return redacted
	case []any:
		redacted := make([]any, 0, len(typed))
		for _, childValue := range typed {
			redacted = append(redacted, r.redact(childValue, key))
		}
		return redacted
	default:
		if policyAuthoringEvidenceSafeKey(normalizedKey) {
			return typed
		}
		return "<redacted>"
	}
}

func (r *policyAuthoringEvidenceRedactor) redactKey(key string) string {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if strings.Contains(normalized, "arn:") || strings.Contains(normalized, "@") || hasTwelveDigitSequence(normalized) {
		r.nextKey++
		return fmt.Sprintf("evidence-key-%d", r.nextKey)
	}
	return key
}

func hasTwelveDigitSequence(value string) bool {
	digits := 0
	for _, character := range value {
		if character >= '0' && character <= '9' {
			digits++
			if digits >= 12 {
				return true
			}
			continue
		}
		digits = 0
	}
	return false
}

func policyAuthoringEvidenceSafeKey(key string) bool {
	if strings.HasPrefix(key, "has_") || strings.HasSuffix(key, "_count") {
		return true
	}
	switch key {
	case "provider", "source_kind", "source_kinds", "entity_type", "entity_types", "relation", "relations", "event_type", "resource_type", "status", "state", "last_status", "observed_last_status", "role_usage":
		return true
	default:
		return false
	}
}

func policyAuthoringEvidenceIdentifierKey(key string) bool {
	return key == "urn" || key == "arn" || key == "tenant_id" || key == "account_id" || key == "resource_id" || key == "actor_id" || strings.HasSuffix(key, "_urn") || strings.HasSuffix(key, "_arn") || strings.HasSuffix(key, "_id")
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
