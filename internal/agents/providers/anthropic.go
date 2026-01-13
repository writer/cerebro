package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/writerinternal/cerebro/internal/agents"
)

// AnthropicProvider implements LLMProvider for Claude
type AnthropicProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

type AnthropicConfig struct {
	APIKey  string
	Model   string
	BaseURL string
}

func NewAnthropicProvider(cfg AnthropicConfig) *AnthropicProvider {
	if cfg.Model == "" {
		cfg.Model = "claude-sonnet-4-20250514"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com"
	}
	return &AnthropicProvider{
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		baseURL: cfg.BaseURL,
		client:  &http.Client{},
	}
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
	System    string             `json:"system,omitempty"`
}

type anthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type anthropicTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type anthropicResponse struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Role         string `json:"role"`
	Content      []anthropicContent `json:"content"`
	Model        string `json:"model"`
	StopReason   string `json:"stop_reason"`
	Usage        anthropicUsage `json:"usage"`
}

type anthropicContent struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func (p *AnthropicProvider) Complete(ctx context.Context, messages []agents.Message, tools []agents.Tool) (*agents.Response, error) {
	// Convert messages
	var anthropicMsgs []anthropicMessage
	var systemPrompt string

	for _, m := range messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}
		anthropicMsgs = append(anthropicMsgs, anthropicMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	// Convert tools
	var anthropicTools []anthropicTool
	for _, t := range tools {
		anthropicTools = append(anthropicTools, anthropicTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.Parameters,
		})
	}

	req := anthropicRequest{
		Model:     p.model,
		MaxTokens: 4096,
		Messages:  anthropicMsgs,
		Tools:     anthropicTools,
		System:    systemPrompt,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var anthropicResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Convert response
	result := &agents.Response{
		Message: agents.Message{
			Role: "assistant",
		},
		Usage: agents.Usage{
			PromptTokens:     anthropicResp.Usage.InputTokens,
			CompletionTokens: anthropicResp.Usage.OutputTokens,
			TotalTokens:      anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		},
		FinishReason: anthropicResp.StopReason,
	}

	for _, c := range anthropicResp.Content {
		switch c.Type {
		case "text":
			result.Message.Content = c.Text
		case "tool_use":
			result.Message.ToolCalls = append(result.Message.ToolCalls, agents.ToolCall{
				ID:        c.ID,
				Name:      c.Name,
				Arguments: c.Input,
			})
		}
	}

	return result, nil
}

func (p *AnthropicProvider) Stream(ctx context.Context, messages []agents.Message, tools []agents.Tool) (<-chan agents.StreamEvent, error) {
	events := make(chan agents.StreamEvent)
	
	go func() {
		defer close(events)
		
		// For now, use non-streaming and emit as single event
		resp, err := p.Complete(ctx, messages, tools)
		if err != nil {
			events <- agents.StreamEvent{Error: err, Done: true}
			return
		}
		
		events <- agents.StreamEvent{
			Type:    "message",
			Content: resp.Message.Content,
			Done:    true,
		}
	}()
	
	return events, nil
}
