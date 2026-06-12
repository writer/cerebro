package graphagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type stubHTTPDoer struct {
	statusCode  int
	body        []byte
	err         error
	lastURL     string
	lastHeaders map[string]string
	lastBody    []byte
}

func (s *stubHTTPDoer) Post(_ context.Context, url string, headers map[string]string, body []byte) (int, []byte, error) {
	s.lastURL = url
	s.lastHeaders = headers
	s.lastBody = append(s.lastBody[:0], body...)
	return s.statusCode, s.body, s.err
}

func TestNewOpenRouterLLMClient_MissingAPIKey(t *testing.T) {
	_, err := NewOpenRouterLLMClient(OpenRouterConfig{HTTPDoer: &stubHTTPDoer{}})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("expected ErrRuntimeUnavailable, got: %v", err)
	}
}

func TestNewOpenRouterLLMClient_MissingHTTPDoer(t *testing.T) {
	_, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key"})
	if err == nil {
		t.Fatal("expected error for missing HTTPDoer")
	}
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("expected ErrRuntimeUnavailable, got: %v", err)
	}
}

func TestOpenRouterLLMClient_DraftCypher(t *testing.T) {
	respBody, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"message": map[string]string{
				"content": `{"rationale":"test rationale","cypher":"MATCH (n) RETURN n LIMIT 5","refusal":""}`,
			},
		}},
	})
	doer := &stubHTTPDoer{statusCode: 200, body: respBody}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{
		APIKey:    "test-key",
		HTTPDoer:  doer,
		MaxTokens: 100,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show all nodes",
		Model:    "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("draft cypher: %v", err)
	}
	if resp.Rationale != "test rationale" {
		t.Errorf("expected 'test rationale', got %q", resp.Rationale)
	}
	if resp.Cypher != "MATCH (n) RETURN n LIMIT 5" {
		t.Errorf("unexpected cypher: %q", resp.Cypher)
	}
	if doer.lastHeaders["Authorization"] != "Bearer test-key" {
		t.Errorf("expected Bearer test-key, got %s", doer.lastHeaders["Authorization"])
	}
	if doer.lastURL != openRouterBaseURL {
		t.Errorf("expected URL %s, got %s", openRouterBaseURL, doer.lastURL)
	}
	assertOpenRouterRequestModel(t, doer.lastBody, defaultOpenRouterModel)
}

func TestOpenRouterLLMClient_MapsAnthropicAliasToOpenRouterModel(t *testing.T) {
	respBody, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"message": map[string]string{
				"content": `{"rationale":"ok","cypher":"MATCH (n) RETURN n","refusal":""}`,
			},
		}},
	})
	doer := &stubHTTPDoer{statusCode: 200, body: respBody}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show nodes",
		Model:    DefaultModel,
	})
	if err != nil {
		t.Fatalf("draft cypher: %v", err)
	}
	assertOpenRouterRequestModel(t, doer.lastBody, "anthropic/claude-sonnet-4.6")
}

func TestOpenRouterLLMClient_Summarize(t *testing.T) {
	respBody, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"message": map[string]string{
				"content": "Summary of results.",
			},
		}},
	})
	doer := &stubHTTPDoer{statusCode: 200, body: respBody}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	text, err := client.Summarize(context.Background(), SummarizeRequest{
		TenantID: "test",
		Question: "Show nodes",
		Cypher:   "MATCH (n) RETURN n",
		Rows:     []map[string]any{{"urn": "test"}},
	})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if text != "Summary of results." {
		t.Errorf("unexpected summary: %q", text)
	}
}

func TestOpenRouterLLMClient_ErrorResponse(t *testing.T) {
	doer := &stubHTTPDoer{statusCode: 429, body: []byte(`{"error":{"message":"rate limited"}}`)}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show nodes",
	})
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
}

func TestOpenRouterLLMClient_AuthenticationFailure(t *testing.T) {
	doer := &stubHTTPDoer{statusCode: 401, body: []byte(`{"error":{"message":"Missing Authentication header","code":401}}`)}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-secret-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show nodes",
	})
	if err == nil {
		t.Fatal("expected error for auth failure")
	}
	if !errors.Is(err, ErrLLMAuthenticationFailed) {
		t.Fatalf("error = %v, want ErrLLMAuthenticationFailed", err)
	}
	var authErr *OpenRouterAuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %T, want OpenRouterAuthenticationError", err)
	}
	if authErr.StatusCode != 401 {
		t.Fatalf("status code = %d, want 401", authErr.StatusCode)
	}
	if authErr.ProviderMessage != "Missing Authentication header" {
		t.Fatalf("provider message = %q, want Missing Authentication header", authErr.ProviderMessage)
	}
	if authErr.CredentialEnvVar != "CEREBRO_OPENROUTER_API_KEY" {
		t.Fatalf("credential env var = %q, want CEREBRO_OPENROUTER_API_KEY", authErr.CredentialEnvVar)
	}
	if strings.Contains(err.Error(), "test-secret-key") {
		t.Fatalf("error leaked API key: %v", err)
	}
}

func TestOpenRouterLLMClient_Probe(t *testing.T) {
	respBody, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"message": map[string]string{"content": "OK"},
		}},
	})
	doer := &stubHTTPDoer{statusCode: 200, body: respBody}
	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := ProbeLLM(context.Background(), client); err != nil {
		t.Fatalf("ProbeLLM() error = %v", err)
	}
	assertOpenRouterRequestModel(t, doer.lastBody, defaultOpenRouterModel)
}

func FuzzOpenRouterAuthErrorClassification(f *testing.F) {
	f.Add(401, `{"error":{"message":"Missing Authentication header","code":401}}`)
	f.Add(403, `{"error":{"message":"No auth credentials found"}}`)
	f.Add(401, `not-json`)
	f.Add(403, `{"error":{"message":""}}`)
	f.Add(429, `{"error":{"message":"Missing Authentication header"}}`)
	f.Add(500, strings.Repeat("x", 512))
	f.Fuzz(func(t *testing.T, statusCode int, body string) {
		if statusCode < 100 || statusCode > 599 {
			t.Skip()
		}
		apiKey := "test-secret-key"
		doer := &stubHTTPDoer{statusCode: statusCode, body: []byte(body)}
		client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: apiKey, HTTPDoer: doer})
		if err != nil {
			t.Fatalf("create client: %v", err)
		}
		_, err = client.chat(context.Background(), defaultOpenRouterModel, "hello", 16)
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), apiKey) || strings.Contains(err.Error(), "Bearer "+apiKey) {
			t.Fatalf("error leaked API key: %v", err)
		}
		var authErr *OpenRouterAuthenticationError
		isAuth := errors.Is(err, ErrLLMAuthenticationFailed)
		hasAuthErr := errors.As(err, &authErr)
		if statusCode == 401 || statusCode == 403 {
			if !isAuth || !hasAuthErr {
				t.Fatalf("status %d error = %T %v, want auth classification", statusCode, err, err)
			}
			if authErr.StatusCode != statusCode {
				t.Fatalf("auth status = %d, want %d", authErr.StatusCode, statusCode)
			}
			if authErr.CredentialEnvVar != "CEREBRO_OPENROUTER_API_KEY" {
				t.Fatalf("credential env var = %q", authErr.CredentialEnvVar)
			}
			if len(authErr.ProviderMessage) > 203 {
				t.Fatalf("provider message too long: %d", len(authErr.ProviderMessage))
			}
			return
		}
		if isAuth || hasAuthErr {
			t.Fatalf("status %d incorrectly classified auth error: %v", statusCode, err)
		}
	})
}

func TestOpenRouterLLMClient_HTTPDoerError(t *testing.T) {
	doer := &stubHTTPDoer{err: fmt.Errorf("connection refused")}

	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show nodes",
	})
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

func assertOpenRouterRequestModel(t *testing.T, body []byte, want string) {
	t.Helper()
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal OpenRouter request body: %v", err)
	}
	if payload.Model != want {
		t.Fatalf("OpenRouter model = %q, want %q", payload.Model, want)
	}
}
