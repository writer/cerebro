package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/agents"
)

func TestNewAnthropicProvider_Defaults(t *testing.T) {
	p := NewAnthropicProvider(AnthropicConfig{
		APIKey: "test-key",
	})

	if p.model != "claude-sonnet-4-20250514" {
		t.Errorf("expected default model 'claude-sonnet-4-20250514', got '%s'", p.model)
	}
	if p.baseURL != "https://api.anthropic.com" {
		t.Errorf("expected default baseURL 'https://api.anthropic.com', got '%s'", p.baseURL)
	}
	if p.apiKey != "test-key" {
		t.Errorf("expected apiKey 'test-key', got '%s'", p.apiKey)
	}
}

func TestNewAnthropicProvider_CustomConfig(t *testing.T) {
	p := NewAnthropicProvider(AnthropicConfig{
		APIKey:  "custom-key",
		Model:   "claude-3-opus",
		BaseURL: "https://custom.api.com",
	})

	if p.model != "claude-3-opus" {
		t.Errorf("expected model 'claude-3-opus', got '%s'", p.model)
	}
	if p.baseURL != "https://custom.api.com" {
		t.Errorf("expected baseURL 'https://custom.api.com', got '%s'", p.baseURL)
	}
}

func TestAnthropicProvider_Complete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("expected /v1/messages, got %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("expected x-api-key header")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("expected anthropic-version header")
		}

		resp := anthropicResponse{
			ID:   "msg_123",
			Type: "message",
			Role: "assistant",
			Content: []anthropicContent{
				{Type: "text", Text: "Hello, I'm Claude!"},
			},
			Model:      "claude-sonnet-4-20250514",
			StopReason: "end_turn",
			Usage: anthropicUsage{
				InputTokens:  10,
				OutputTokens: 20,
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewAnthropicProvider(AnthropicConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	messages := []agents.Message{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "Hello!"},
	}

	resp, err := p.Complete(context.Background(), messages, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Message.Role != "assistant" {
		t.Errorf("expected role 'assistant', got '%s'", resp.Message.Role)
	}
	if resp.Message.Content != "Hello, I'm Claude!" {
		t.Errorf("expected content 'Hello, I'm Claude!', got '%s'", resp.Message.Content)
	}
	if resp.Usage.PromptTokens != 10 {
		t.Errorf("expected prompt tokens 10, got %d", resp.Usage.PromptTokens)
	}
	if resp.Usage.CompletionTokens != 20 {
		t.Errorf("expected completion tokens 20, got %d", resp.Usage.CompletionTokens)
	}
	if resp.Usage.TotalTokens != 30 {
		t.Errorf("expected total tokens 30, got %d", resp.Usage.TotalTokens)
	}
}

func TestAnthropicProvider_Complete_WithTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req anthropicRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if len(req.Tools) != 1 {
			t.Errorf("expected 1 tool, got %d", len(req.Tools))
		}
		if req.Tools[0].Name != "search" {
			t.Errorf("expected tool name 'search', got '%s'", req.Tools[0].Name)
		}

		resp := anthropicResponse{
			ID:   "msg_123",
			Type: "message",
			Role: "assistant",
			Content: []anthropicContent{
				{
					Type:  "tool_use",
					ID:    "tool_123",
					Name:  "search",
					Input: json.RawMessage(`{"query":"test"}`),
				},
			},
			StopReason: "tool_use",
			Usage:      anthropicUsage{InputTokens: 5, OutputTokens: 10},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewAnthropicProvider(AnthropicConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	tools := []agents.Tool{
		{
			Name:        "search",
			Description: "Search for information",
			Parameters:  map[string]interface{}{"type": "object"},
		},
	}

	resp, err := p.Complete(context.Background(), []agents.Message{{Role: "user", Content: "Search"}}, tools)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Message.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.Message.ToolCalls))
	}
	if resp.Message.ToolCalls[0].Name != "search" {
		t.Errorf("expected tool name 'search', got '%s'", resp.Message.ToolCalls[0].Name)
	}
}

func TestAnthropicProvider_Complete_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error": "invalid api key"}`)); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()

	p := NewAnthropicProvider(AnthropicConfig{
		APIKey:  "invalid-key",
		BaseURL: server.URL,
	})

	_, err := p.Complete(context.Background(), []agents.Message{{Role: "user", Content: "Hello"}}, nil)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestAnthropicProvider_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proper SSE format response for testing
		w.Header().Set("Content-Type", "text/event-stream")

		// 1. Send content delta
		data := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Streamed response"}}`
		if _, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", data); err != nil {
			t.Fatalf("write sse delta: %v", err)
		}

		// 2. Send message stop
		if _, err := fmt.Fprintf(w, "event: message_stop\ndata: {}\n\n"); err != nil {
			t.Fatalf("write sse stop: %v", err)
		}
	}))
	defer server.Close()

	p := NewAnthropicProvider(AnthropicConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	events, err := p.Stream(context.Background(), []agents.Message{{Role: "user", Content: "Hello"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fullContent string
	var lastEvent agents.StreamEvent
	for event := range events {
		lastEvent = event
		if event.Type == "delta" {
			fullContent += event.Content
		}
	}

	if !lastEvent.Done {
		t.Error("expected Done to be true")
	}
	if fullContent != "Streamed response" {
		t.Errorf("expected content 'Streamed response', got '%s'", fullContent)
	}
}

func TestNewOpenAIProvider_Defaults(t *testing.T) {
	p := NewOpenAIProvider(OpenAIConfig{
		APIKey: "test-key",
	})

	if p.model != "gpt-4o" {
		t.Errorf("expected default model 'gpt-4o', got '%s'", p.model)
	}
	if p.baseURL != "https://api.openai.com" {
		t.Errorf("expected default baseURL 'https://api.openai.com', got '%s'", p.baseURL)
	}
}

func TestOpenAIProvider_Complete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("expected /v1/chat/completions, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Authorization header")
		}

		resp := openaiResponse{
			ID:      "chatcmpl-123",
			Object:  "chat.completion",
			Created: 1677858242,
			Model:   "gpt-4o",
			Choices: []struct {
				Index        int           `json:"index"`
				Message      openaiMessage `json:"message"`
				FinishReason string        `json:"finish_reason"`
			}{
				{
					Index:        0,
					Message:      openaiMessage{Role: "assistant", Content: "Hello from GPT!"},
					FinishReason: "stop",
				},
			},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     10,
				CompletionTokens: 15,
				TotalTokens:      25,
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	messages := []agents.Message{
		{Role: "user", Content: "Hello!"},
	}

	resp, err := p.Complete(context.Background(), messages, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Message.Content != "Hello from GPT!" {
		t.Errorf("expected content 'Hello from GPT!', got '%s'", resp.Message.Content)
	}
	if resp.Usage.TotalTokens != 25 {
		t.Errorf("expected total tokens 25, got %d", resp.Usage.TotalTokens)
	}
}

func TestOpenAIProvider_Complete_NoChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			ID: "chatcmpl-123",
			Choices: []struct {
				Index        int           `json:"index"`
				Message      openaiMessage `json:"message"`
				FinishReason string        `json:"finish_reason"`
			}{},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	_, err := p.Complete(context.Background(), []agents.Message{{Role: "user", Content: "Hi"}}, nil)
	if err == nil {
		t.Error("expected error for no choices, got nil")
	}
}

func TestOpenAIProvider_Complete_WithToolCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			ID: "chatcmpl-123",
			Choices: []struct {
				Index        int           `json:"index"`
				Message      openaiMessage `json:"message"`
				FinishReason string        `json:"finish_reason"`
			}{
				{
					Index: 0,
					Message: openaiMessage{
						Role: "assistant",
						ToolCalls: []openaiToolCall{
							{
								ID:   "call_123",
								Type: "function",
								Function: struct {
									Name      string `json:"name"`
									Arguments string `json:"arguments"`
								}{
									Name:      "get_weather",
									Arguments: `{"location":"NYC"}`,
								},
							},
						},
					},
					FinishReason: "tool_calls",
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	resp, err := p.Complete(context.Background(), []agents.Message{{Role: "user", Content: "Weather?"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Message.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.Message.ToolCalls))
	}
	if resp.Message.ToolCalls[0].Name != "get_weather" {
		t.Errorf("expected tool name 'get_weather', got '%s'", resp.Message.ToolCalls[0].Name)
	}
}

func TestOpenAIProvider_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			ID: "chatcmpl-123",
			Choices: []struct {
				Index        int           `json:"index"`
				Message      openaiMessage `json:"message"`
				FinishReason string        `json:"finish_reason"`
			}{
				{
					Message:      openaiMessage{Role: "assistant", Content: "Streamed!"},
					FinishReason: "stop",
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	events, err := p.Stream(context.Background(), []agents.Message{{Role: "user", Content: "Hi"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var lastEvent agents.StreamEvent
	for event := range events {
		lastEvent = event
	}

	if !lastEvent.Done {
		t.Error("expected Done to be true")
	}
}
