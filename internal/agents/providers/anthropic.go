package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/agents"
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
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
	System    string             `json:"system,omitempty"`
	Stream    bool               `json:"stream,omitempty"`
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
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Role       string             `json:"role"`
	Content    []anthropicContent `json:"content"`
	Model      string             `json:"model"`
	StopReason string             `json:"stop_reason"`
	Usage      anthropicUsage     `json:"usage"`
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
	anthropicMsgs := make([]anthropicMessage, 0, len(messages))
	var systemPrompt string

	for _, m := range messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}

		// Handle tool results specially for Anthropic
		if m.Role == "tool" {
			anthropicMsgs = append(anthropicMsgs, anthropicMessage{
				Role: "user", // Anthropic uses 'user' role for tool results
				Content: []map[string]interface{}{
					{
						"type":        "tool_result",
						"tool_use_id": m.Name, // We store tool_use_id in Message.Name
						"content":     m.Content,
					},
				},
			})
			continue
		}

		// Handle assistant messages with tool calls
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			var content []interface{}
			if m.Content != "" {
				content = append(content, map[string]interface{}{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				// Parse arguments if they are json.RawMessage
				var input interface{}
				if err := json.Unmarshal(tc.Arguments, &input); err != nil {
					// Fallback if not valid JSON, though it should be
					input = map[string]interface{}{}
				}

				content = append(content, map[string]interface{}{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": input,
				})
			}
			anthropicMsgs = append(anthropicMsgs, anthropicMessage{
				Role:    "assistant",
				Content: content,
			})
			continue
		}

		anthropicMsgs = append(anthropicMsgs, anthropicMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	// Convert tools
	anthropicTools := make([]anthropicTool, 0, len(tools))
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("API error %d (body unreadable: %v)", resp.StatusCode, readErr)
		}
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
	events := make(chan agents.StreamEvent, 100)

	// Convert messages
	anthropicMsgs := make([]anthropicMessage, 0, len(messages))
	var systemPrompt string

	for _, m := range messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}

		// Handle tool results specially for Anthropic
		if m.Role == "tool" {
			anthropicMsgs = append(anthropicMsgs, anthropicMessage{
				Role: "user", // Anthropic uses 'user' role for tool results
				Content: []map[string]interface{}{
					{
						"type":        "tool_result",
						"tool_use_id": m.Name, // We store tool_use_id in Message.Name
						"content":     m.Content,
					},
				},
			})
			continue
		}

		// Handle assistant messages with tool calls
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			var content []interface{}
			if m.Content != "" {
				content = append(content, map[string]interface{}{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				// Parse arguments if they are json.RawMessage
				var input interface{}
				if err := json.Unmarshal(tc.Arguments, &input); err != nil {
					// Fallback if not valid JSON, though it should be
					input = map[string]interface{}{}
				}

				content = append(content, map[string]interface{}{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": input,
				})
			}
			anthropicMsgs = append(anthropicMsgs, anthropicMessage{
				Role:    "assistant",
				Content: content,
			})
			continue
		}

		anthropicMsgs = append(anthropicMsgs, anthropicMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	// Convert tools
	anthropicTools := make([]anthropicTool, 0, len(tools))
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
		Stream:    true,
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
	httpReq.Header.Set("Accept", "text/event-stream")

	go func() {
		defer close(events)

		resp, err := p.client.Do(httpReq)
		if err != nil {
			events <- agents.StreamEvent{Error: err, Done: true}
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				events <- agents.StreamEvent{Error: fmt.Errorf("API error %d (body unreadable: %v)", resp.StatusCode, readErr), Done: true}
				return
			}
			events <- agents.StreamEvent{Error: fmt.Errorf("API error %d: %s", resp.StatusCode, string(body)), Done: true}
			return
		}

		// Parse SSE stream
		reader := newSSEReader(resp.Body)
		for {
			select {
			case <-ctx.Done():
				events <- agents.StreamEvent{Error: ctx.Err(), Done: true}
				return
			default:
			}

			event, err := reader.Next()
			if errors.Is(err, io.EOF) {
				events <- agents.StreamEvent{Done: true}
				return
			}
			if err != nil {
				events <- agents.StreamEvent{Error: err, Done: true}
				return
			}

			// Handle Anthropic streaming events
			switch event.Event {
			case "content_block_delta":
				var data struct {
					Delta struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"delta"`
				}
				if err := json.Unmarshal([]byte(event.Data), &data); err != nil {
					continue
				}
				if data.Delta.Type == "text_delta" {
					events <- agents.StreamEvent{
						Type:    "delta",
						Content: data.Delta.Text,
					}
				}
			case "message_stop":
				events <- agents.StreamEvent{Done: true}
				return
			case "error":
				var data struct {
					Error struct {
						Type    string `json:"type"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal([]byte(event.Data), &data); err == nil {
					events <- agents.StreamEvent{
						Error: fmt.Errorf("anthropic error: %s", data.Error.Message),
						Done:  true,
					}
					return
				}
			}
		}
	}()

	return events, nil
}
