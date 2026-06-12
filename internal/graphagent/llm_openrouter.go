package graphagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	openRouterBaseURL      = "https://openrouter.ai/api/v1/chat/completions"
	defaultOpenRouterModel = "anthropic/claude-sonnet-4.6"
)

// HTTPDoer abstracts HTTP POST so graphagent stays outside the net/http boundary.
type HTTPDoer interface {
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (statusCode int, respBody []byte, err error)
}

type OpenRouterLLMClient struct {
	apiKey       string
	httpDoer     HTTPDoer
	defaultModel string
	sonnetModel  string
	opusModel    string
	haikuModel   string
	maxTokens    int
	temperature  float64
}

type OpenRouterConfig struct {
	APIKey       string
	HTTPDoer     HTTPDoer
	DefaultModel string
	SonnetModel  string
	OpusModel    string
	HaikuModel   string
	MaxTokens    int
	Temperature  float64
}

func NewOpenRouterLLMClient(cfg OpenRouterConfig) (*OpenRouterLLMClient, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("%w: CEREBRO_OPENROUTER_API_KEY is required for the openrouter LLM provider", ErrRuntimeUnavailable)
	}
	if cfg.HTTPDoer == nil {
		return nil, fmt.Errorf("%w: HTTPDoer is required for the openrouter LLM provider", ErrRuntimeUnavailable)
	}
	if cfg.DefaultModel == "" {
		cfg.DefaultModel = defaultOpenRouterModel
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1200
	}
	return &OpenRouterLLMClient{
		apiKey:       strings.TrimSpace(cfg.APIKey),
		httpDoer:     cfg.HTTPDoer,
		defaultModel: strings.TrimSpace(cfg.DefaultModel),
		sonnetModel:  strings.TrimSpace(cfg.SonnetModel),
		opusModel:    strings.TrimSpace(cfg.OpusModel),
		haikuModel:   strings.TrimSpace(cfg.HaikuModel),
		maxTokens:    cfg.MaxTokens,
		temperature:  cfg.Temperature,
	}, nil
}

func (c *OpenRouterLLMClient) DraftCypher(ctx context.Context, req DraftRequest) (*DraftResponse, error) {
	prompt := draftPrompt(req)
	text, err := c.chat(ctx, c.modelID(req.Model), prompt, c.maxTokens)
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

func (c *OpenRouterLLMClient) Summarize(ctx context.Context, req SummarizeRequest) (string, error) {
	return c.chat(ctx, c.modelID(req.Model), summarizePrompt(req), c.maxTokens)
}

func (c *OpenRouterLLMClient) modelID(requested string) string {
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

func (c *OpenRouterLLMClient) chat(ctx context.Context, model string, prompt string, maxTokens int) (string, error) {
	body := map[string]any{
		"model":       model,
		"max_tokens":  maxTokens,
		"temperature": c.temperature,
		"messages": []map[string]any{{
			"role":    "user",
			"content": prompt,
		}},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + c.apiKey,
		"HTTP-Referer":  "https://cerebro.writer.com",
		"X-Title":       "Cerebro Graph Agent",
	}
	statusCode, respBody, err := c.httpDoer.Post(ctx, openRouterBaseURL, headers, payload)
	if err != nil {
		return "", fmt.Errorf("openrouter request failed: %w", err)
	}
	if statusCode != 200 {
		if statusCode == 401 || statusCode == 403 {
			message := openRouterErrorMessage(respBody)
			if message != "" {
				return "", fmt.Errorf("%w: openrouter authentication failed (%d): %s; check CEREBRO_OPENROUTER_API_KEY", ErrLLMAuthenticationFailed, statusCode, message)
			}
			return "", fmt.Errorf("%w: openrouter authentication failed (%d); check CEREBRO_OPENROUTER_API_KEY", ErrLLMAuthenticationFailed, statusCode)
		}
		return "", fmt.Errorf("openrouter returned %d: %s", statusCode, truncateStr(string(respBody), 200))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse openrouter response: %w", err)
	}
	if result.Error != nil && result.Error.Message != "" {
		return "", fmt.Errorf("openrouter error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 || strings.TrimSpace(result.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("openrouter response contained no text")
	}
	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

func openRouterErrorMessage(respBody []byte) string {
	var result struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err == nil && result.Error != nil {
		return truncateStr(strings.TrimSpace(result.Error.Message), 200)
	}
	return ""
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
