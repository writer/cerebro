package graphagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go"
)

const maxBedrockConverseTokens int32 = 1<<31 - 1

var errBedrockNoText = errors.New("bedrock response contained no text")

type BedrockRuntimeInvoker interface {
	Converse(context.Context, *bedrockruntime.ConverseInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

type BedrockLLMClient struct {
	client         BedrockRuntimeInvoker
	defaultModel   string
	sonnetModel    string
	opusModel      string
	haikuModel     string
	maxTokens      int
	temperature    float64
	temperatureSet bool
}

type BedrockConfig struct {
	DefaultModel   string
	SonnetModel    string
	OpusModel      string
	HaikuModel     string
	Region         string
	MaxTokens      int
	Temperature    float64
	TemperatureSet bool
	Runtime        BedrockRuntimeInvoker
}

type BedrockAccessDeniedError struct {
	Code string
}

func (e *BedrockAccessDeniedError) Error() string {
	code := strings.TrimSpace(e.Code)
	if code == "" {
		code = "AccessDeniedException"
	}
	return fmt.Sprintf("%s: bedrock access denied (%s); grant bedrock:InvokeModel for the configured graph-agent model", ErrLLMAccessDenied, code)
}

func (e *BedrockAccessDeniedError) Unwrap() error {
	return ErrLLMAccessDenied
}

type BedrockInvocationError struct {
	cause error
}

func (e *BedrockInvocationError) Error() string {
	return ErrRuntimeUnavailable.Error() + ": bedrock invocation failed"
}

func (e *BedrockInvocationError) Unwrap() []error {
	return []error{ErrRuntimeUnavailable, e.cause}
}

func NewBedrockLLMClient(ctx context.Context, llmConfig BedrockConfig) (*BedrockLLMClient, error) {
	client := llmConfig.Runtime
	if client == nil {
		loadOptions := []func(*awsconfig.LoadOptions) error{}
		if region := strings.TrimSpace(llmConfig.Region); region != "" {
			loadOptions = append(loadOptions, awsconfig.WithRegion(region))
		}
		awsConfig, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
		if err != nil {
			return nil, fmt.Errorf("load AWS config for Bedrock: %w", err)
		}
		client = bedrockruntime.NewFromConfig(awsConfig)
	}
	if strings.TrimSpace(llmConfig.DefaultModel) == "" {
		llmConfig.DefaultModel = DefaultModel
	}
	if llmConfig.MaxTokens <= 0 {
		llmConfig.MaxTokens = 1200
	}
	return &BedrockLLMClient{
		client:         client,
		defaultModel:   strings.TrimSpace(llmConfig.DefaultModel),
		sonnetModel:    strings.TrimSpace(llmConfig.SonnetModel),
		opusModel:      strings.TrimSpace(llmConfig.OpusModel),
		haikuModel:     strings.TrimSpace(llmConfig.HaikuModel),
		maxTokens:      llmConfig.MaxTokens,
		temperature:    llmConfig.Temperature,
		temperatureSet: llmConfig.TemperatureSet,
	}, nil
}

func (c *BedrockLLMClient) DraftCypher(ctx context.Context, req DraftRequest) (*DraftResponse, error) {
	prompt := draftPrompt(req)
	modelID, err := c.modelID(req.Model)
	if err != nil {
		return nil, err
	}
	text, err := c.invokeMessages(ctx, modelID, prompt, c.maxTokens)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Rationale string        `json:"rationale"`
		Plan      *AskQueryPlan `json:"plan"`
		Cypher    *string       `json:"cypher"`
		Refusal   string        `json:"refusal"`
	}
	if err := json.Unmarshal(extractJSONObject(text), &payload); err != nil {
		return nil, fmt.Errorf("parse draft response JSON: %w", err)
	}
	response := &DraftResponse{Rationale: strings.TrimSpace(payload.Rationale), Plan: payload.Plan, Refusal: strings.TrimSpace(payload.Refusal)}
	if payload.Cypher != nil {
		response.Cypher = strings.TrimSpace(*payload.Cypher)
	}
	return response, nil
}

func (c *BedrockLLMClient) Summarize(ctx context.Context, req SummarizeRequest) (string, error) {
	modelID, err := c.modelID(req.Model)
	if err != nil {
		return "", err
	}
	return c.invokeMessages(ctx, modelID, summarizePrompt(req), c.maxTokens)
}

func (c *BedrockLLMClient) Probe(ctx context.Context) error {
	_, err := c.invokeMessages(ctx, c.defaultModel, "Reply with OK if this Bedrock model is callable.", 16)
	return err
}

func (c *BedrockLLMClient) modelID(requested string) (string, error) {
	return configuredModelID(requested, c.defaultModel, c.sonnetModel, c.opusModel, c.haikuModel)
}

func (c *BedrockLLMClient) invokeMessages(ctx context.Context, modelID string, prompt string, maxTokens int) (string, error) {
	maxTokens32, err := bedrockConverseMaxTokens(maxTokens)
	if err != nil {
		return "", err
	}
	inferenceConfig := &bedrocktypes.InferenceConfiguration{
		MaxTokens: &maxTokens32,
	}
	if c.temperatureSet {
		temperature32 := float32(c.temperature)
		inferenceConfig.Temperature = &temperature32
	}
	out, err := c.client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(modelID),
		Messages: []bedrocktypes.Message{{
			Role: bedrocktypes.ConversationRoleUser,
			Content: []bedrocktypes.ContentBlock{
				&bedrocktypes.ContentBlockMemberText{Value: prompt},
			},
		}},
		InferenceConfig: inferenceConfig,
	})
	if err != nil {
		return "", classifyBedrockInvokeError(err)
	}
	var text strings.Builder
	message, ok := out.Output.(*bedrocktypes.ConverseOutputMemberMessage)
	if ok && message != nil {
		for _, part := range message.Value.Content {
			partText := bedrockContentText(part)
			if strings.TrimSpace(partText) == "" {
				continue
			}
			if text.Len() > 0 {
				text.WriteString("\n")
			}
			text.WriteString(partText)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return "", errBedrockNoText
	}
	return strings.TrimSpace(text.String()), nil
}

func bedrockConverseMaxTokens(maxTokens int) (int32, error) {
	if maxTokens <= 0 {
		return 0, fmt.Errorf("bedrock max tokens must be greater than zero")
	}
	if maxTokens > int(maxBedrockConverseTokens) {
		return 0, fmt.Errorf("bedrock max tokens exceeds supported limit")
	}
	return int32(maxTokens), nil
}

func bedrockContentText(part bedrocktypes.ContentBlock) string {
	switch typed := part.(type) {
	case *bedrocktypes.ContentBlockMemberText:
		if typed == nil {
			return ""
		}
		return typed.Value
	default:
		return ""
	}
}

func classifyBedrockInvokeError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && bedrockAccessDeniedCode(apiErr.ErrorCode()) {
		return &BedrockAccessDeniedError{Code: apiErr.ErrorCode()}
	}
	return &BedrockInvocationError{cause: err}
}

func bedrockAccessDeniedCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	default:
		return false
	}
}

func draftPrompt(req DraftRequest) string {
	var history bytes.Buffer
	for _, item := range req.History {
		fmt.Fprintf(&history, "- %s: %s\n", item.Role, item.Content)
	}
	probe := "No graph probe was collected."
	if req.Probe != nil {
		if raw, err := json.Marshal(req.Probe); err == nil {
			probe = string(raw)
		}
	}
	return fmt.Sprintf(`You generate safe, read-only Neo4j Cypher for a security graph.

Question: %s
Tenant parameter: $tenant_id
Scope URN parameter, if present: $scope_urn
Requested model alias: %s

%s

%s

Graph probe context:
%s

Conversation history:
%s

Return ONLY compact JSON:
{"rationale":"short explanation","plan":{"intent":"top_risk_findings","confidence":0.8,"limit":25,"filters":{}},"cypher":"MATCH ... LIMIT 25","refusal":""}
All plan.filters values must be JSON strings, even for numbers or booleans (for example {"risk_score":"50"}).

If the question asks for mutation, deletion, credential disclosure, or anything unsafe, return:
{"rationale":"why refused","plan":{"intent":"raw_cypher","confidence":0},"cypher":null,"refusal":"safe refusal message"}

Preferred plan intents: aggregate_findings_by_source, top_risk_findings, explain_finding, identity_bridge, connector_health, raw_cypher.
Use a deterministic intent whenever the question matches one; the backend will convert that plan into canonical Cypher.`, req.Question, normalizeModel(req.Model), req.Schema, req.Guardrail, probe, history.String())
}

func summarizePrompt(req SummarizeRequest) string {
	rows, _ := json.Marshal(req.Rows)
	return fmt.Sprintf(`Summarize the graph query result for an operator.

Question: %s
Cypher:
%s

Rows JSON:
%s

Write concise markdown. Cite important entity URNs inline exactly as returned. Do not invent data.`, req.Question, req.Cypher, rows)
}

func extractJSONObject(text string) []byte {
	trimmed := strings.TrimSpace(text)
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end >= start {
		return []byte(trimmed[start : end+1])
	}
	return []byte(trimmed)
}
