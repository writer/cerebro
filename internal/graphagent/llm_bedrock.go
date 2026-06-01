package graphagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

type BedrockLLMClient struct {
	client       *bedrockruntime.Client
	defaultModel string
	sonnetModel  string
	opusModel    string
	haikuModel   string
	maxTokens    int
	temperature  float64
}

type BedrockConfig struct {
	DefaultModel string
	SonnetModel  string
	OpusModel    string
	HaikuModel   string
	MaxTokens    int
	Temperature  float64
}

func NewBedrockLLMClient(ctx context.Context, llmConfig BedrockConfig) (*BedrockLLMClient, error) {
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config for Bedrock: %w", err)
	}
	if llmConfig.DefaultModel == "" {
		llmConfig.DefaultModel = DefaultModel
	}
	if llmConfig.MaxTokens <= 0 {
		llmConfig.MaxTokens = 1200
	}
	return &BedrockLLMClient{
		client:       bedrockruntime.NewFromConfig(awsConfig),
		defaultModel: strings.TrimSpace(llmConfig.DefaultModel),
		sonnetModel:  strings.TrimSpace(llmConfig.SonnetModel),
		opusModel:    strings.TrimSpace(llmConfig.OpusModel),
		haikuModel:   strings.TrimSpace(llmConfig.HaikuModel),
		maxTokens:    llmConfig.MaxTokens,
		temperature:  llmConfig.Temperature,
	}, nil
}

func (c *BedrockLLMClient) DraftCypher(ctx context.Context, req DraftRequest) (*DraftResponse, error) {
	prompt := draftPrompt(req)
	text, err := c.invokeMessages(ctx, c.modelID(req.Model), prompt, c.maxTokens)
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
	return c.invokeMessages(ctx, c.modelID(req.Model), summarizePrompt(req), c.maxTokens)
}

func (c *BedrockLLMClient) modelID(requested string) string {
	switch normalizeModel(requested) {
	case "claude-sonnet-4-6":
		return firstNonEmpty(c.sonnetModel, c.defaultModel)
	case "claude-opus-4-7":
		return firstNonEmpty(c.opusModel, c.defaultModel)
	case "claude-haiku-4-5-20251001":
		return firstNonEmpty(c.haikuModel, c.defaultModel)
	default:
		if strings.TrimSpace(requested) != "" {
			return strings.TrimSpace(requested)
		}
		return c.defaultModel
	}
}

func (c *BedrockLLMClient) invokeMessages(ctx context.Context, modelID string, prompt string, maxTokens int) (string, error) {
	body := map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        maxTokens,
		"temperature":       c.temperature,
		"messages": []map[string]any{{
			"role": "user",
			"content": []map[string]string{{
				"type": "text",
				"text": prompt,
			}},
		}},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	out, err := c.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        payload,
	})
	if err != nil {
		return "", fmt.Errorf("invoke Bedrock model: %w", err)
	}
	var response struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(out.Body, &response); err != nil {
		return "", fmt.Errorf("parse Bedrock response: %w", err)
	}
	var text strings.Builder
	for _, part := range response.Content {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			if text.Len() > 0 {
				text.WriteString("\n")
			}
			text.WriteString(part.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return "", fmt.Errorf("bedrock response contained no text")
	}
	return strings.TrimSpace(text.String()), nil
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
