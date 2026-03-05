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

// OpenAIProvider implements LLMProvider for OpenAI/GPT models
type OpenAIProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

type OpenAIConfig struct {
	APIKey  string
	Model   string
	BaseURL string
}

func NewOpenAIProvider(cfg OpenAIConfig) *OpenAIProvider {
	if cfg.Model == "" {
		cfg.Model = "gpt-4o"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com"
	}
	return &OpenAIProvider{
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		baseURL: cfg.BaseURL,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

type openaiRequest struct {
	Model    string          `json:"model"`
	Messages []openaiMessage `json:"messages"`
	Tools    []openaiTool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream,omitempty"`
}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openaiTool struct {
	Type     string         `json:"type"`
	Function openaiFunction `json:"function"`
}

type openaiFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type openaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openaiResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int           `json:"index"`
		Message      openaiMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func (p *OpenAIProvider) Complete(ctx context.Context, messages []agents.Message, tools []agents.Tool) (*agents.Response, error) {
	// Convert messages
	openaiMsgs := make([]openaiMessage, 0, len(messages))
	for _, m := range messages {
		openaiMsgs = append(openaiMsgs, openaiMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	// Convert tools
	openaiTools := make([]openaiTool, 0, len(tools))
	for _, t := range tools {
		openaiTools = append(openaiTools, openaiTool{
			Type: "function",
			Function: openaiFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}

	req := openaiRequest{
		Model:    p.model,
		Messages: openaiMsgs,
		Tools:    openaiTools,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("API error %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var openaiResp openaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(openaiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := openaiResp.Choices[0]
	result := &agents.Response{
		Message: agents.Message{
			Role:    "assistant",
			Content: choice.Message.Content,
		},
		Usage: agents.Usage{
			PromptTokens:     openaiResp.Usage.PromptTokens,
			CompletionTokens: openaiResp.Usage.CompletionTokens,
			TotalTokens:      openaiResp.Usage.TotalTokens,
		},
		FinishReason: choice.FinishReason,
	}

	for _, tc := range choice.Message.ToolCalls {
		result.Message.ToolCalls = append(result.Message.ToolCalls, agents.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: json.RawMessage(tc.Function.Arguments),
		})
	}

	return result, nil
}

func (p *OpenAIProvider) Stream(ctx context.Context, messages []agents.Message, tools []agents.Tool) (<-chan agents.StreamEvent, error) {
	events := make(chan agents.StreamEvent, 100)

	// Convert messages
	openaiMsgs := make([]openaiMessage, 0, len(messages))
	for _, m := range messages {
		openaiMsgs = append(openaiMsgs, openaiMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	// Convert tools
	openaiTools := make([]openaiTool, 0, len(tools))
	for _, t := range tools {
		openaiTools = append(openaiTools, openaiTool{
			Type: "function",
			Function: openaiFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}

	req := openaiRequest{
		Model:    p.model,
		Messages: openaiMsgs,
		Tools:    openaiTools,
		Stream:   true,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
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
				events <- agents.StreamEvent{Error: fmt.Errorf("API error %d (body unreadable: %w)", resp.StatusCode, readErr), Done: true}
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

			// OpenAI sends [DONE] to signal completion
			if event.Data == "[DONE]" {
				events <- agents.StreamEvent{Done: true}
				return
			}

			// Parse OpenAI streaming chunk
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(event.Data), &chunk); err != nil {
				continue
			}

			if len(chunk.Choices) > 0 {
				delta := chunk.Choices[0].Delta
				if delta.Content != "" {
					events <- agents.StreamEvent{Type: "delta", Content: delta.Content}
				}
				if chunk.Choices[0].FinishReason == "stop" {
					events <- agents.StreamEvent{Done: true}
					return
				}
			}
		}
	}()

	return events, nil
}
