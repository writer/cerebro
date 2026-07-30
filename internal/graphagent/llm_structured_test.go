package graphagent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestBedrockLLMClientDraftStructuredJSONUsesConfiguredBudget(t *testing.T) {
	runtime := &stubBedrockRuntime{text: "result:\n```json\n{\"kind\":\"PolicyFindingRule\"}\n```"}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{DefaultModel: "configured-model", Runtime: runtime, MaxTokens: 321})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := client.DraftStructuredJSON(context.Background(), StructuredJSONRequest{
		Kind: "policy_finding_rule", Prompt: "author one policy", SchemaJSON: `{"type":"object"}`, Context: map[string]any{"relation": "depends_on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"kind":"PolicyFindingRule"}` {
		t.Fatalf("payload = %s", payload)
	}
	if got := aws.ToString(runtime.lastInput.ModelId); got != "configured-model" {
		t.Fatalf("model = %q", got)
	}
	if got := aws.ToInt32(runtime.lastInput.InferenceConfig.MaxTokens); got != minStructuredJSONMaxTokens {
		t.Fatalf("max tokens = %d", got)
	}
}

func TestBedrockLLMClientDraftStructuredJSONUsesBoundedRequestBudget(t *testing.T) {
	runtime := &stubBedrockRuntime{text: `{"lane":"lookup"}`}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{
		DefaultModel: "configured-model",
		Runtime:      runtime,
		MaxTokens:    4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DraftStructuredJSON(context.Background(), StructuredJSONRequest{
		Kind: "slack_turn_route", MaxTokens: 256, Prompt: "route", SchemaJSON: `{"type":"object"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToInt32(runtime.lastInput.InferenceConfig.MaxTokens); got != 256 {
		t.Fatalf("max tokens = %d, want 256", got)
	}
}

func TestOpenRouterLLMClientDraftStructuredJSONUsesConfiguredRequest(t *testing.T) {
	response, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": `{"kind":"PolicyFindingRule"}`}}}})
	doer := &stubHTTPDoer{statusCode: 200, body: response}
	client, err := NewOpenRouterLLMClient(OpenRouterConfig{APIKey: "test-key", HTTPDoer: doer, DefaultModel: "configured-model", MaxTokens: 222})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := client.DraftStructuredJSON(context.Background(), StructuredJSONRequest{Kind: "policy_finding_rule", Prompt: "author one policy", SchemaJSON: `{"type":"object"}`})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"kind":"PolicyFindingRule"}` {
		t.Fatalf("payload = %s", payload)
	}
	var body map[string]any
	if err := json.Unmarshal(doer.lastBody, &body); err != nil {
		t.Fatal(err)
	}
	if body["model"] != "configured-model" || body["max_tokens"] != float64(minStructuredJSONMaxTokens) {
		t.Fatalf("request body = %#v", body)
	}
}

func TestStructuredJSONTokenBudgetPreservesHigherConfiguredLimit(t *testing.T) {
	if got := structuredJSONTokenBudget(6000, 0); got != 6000 {
		t.Fatalf("budget = %d, want configured 6000", got)
	}
	if got := structuredJSONTokenBudget(6000, 9000); got != 9000 {
		t.Fatalf("budget = %d, want trusted request budget 9000", got)
	}
	if got := structuredJSONTokenBudget(6000, 32); got != 128 {
		t.Fatalf("budget = %d, want bounded floor 128", got)
	}
	if got := structuredJSONTokenBudget(6000, 50000); got != maxStructuredJSONMaxTokens {
		t.Fatalf("budget = %d, want hard ceiling %d", got, maxStructuredJSONMaxTokens)
	}
}

func TestStubLLMClientDraftStructuredJSONRecordsRequest(t *testing.T) {
	client := &StubLLMClient{StructuredResponse: []byte(`{"ok":true}`)}
	payload, err := client.DraftStructuredJSON(context.Background(), StructuredJSONRequest{TenantID: "tenant-a", Kind: "policy_finding_rule"})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"ok":true}` || len(client.StructuredRequests) != 1 || client.StructuredRequests[0].TenantID != "tenant-a" {
		t.Fatalf("payload = %s requests = %#v", payload, client.StructuredRequests)
	}
}

func TestInstrumentedLLMClientPreservesStructuredCapabilityWithoutLoggingContent(t *testing.T) {
	prompt := "private operator intent"
	schema := `{"private_schema":true}`
	response := `{"private_response":true}`
	client := instrumentLLMClient("openrouter", &StubLLMClient{StructuredResponse: []byte(response)})
	structured, ok := client.(StructuredJSONClient)
	if !ok {
		t.Fatal("instrumented client dropped StructuredJSONClient capability")
	}
	stderr := captureGraphAgentStderr(t, func() {
		payload, err := structured.DraftStructuredJSON(context.Background(), StructuredJSONRequest{
			TenantID: "tenant-a", Kind: "policy_finding_rule", Prompt: prompt, SchemaJSON: schema, Context: map[string]any{"private_context": true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != response {
			t.Fatalf("payload = %s", payload)
		}
	})
	for _, required := range []string{`"name":"graphagent.llm.structured_json"`, `"gen_ai.operation.name":"structured_json"`, `"graphagent.structured.kind":"policy_finding_rule"`} {
		if !strings.Contains(stderr, required) {
			t.Fatalf("telemetry missing %q: %s", required, stderr)
		}
	}
	for _, forbidden := range []string{prompt, schema, response, "private_context"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("telemetry contains %q: %s", forbidden, stderr)
		}
	}
}

func TestInstrumentationDoesNotInventStructuredCapability(t *testing.T) {
	client := instrumentLLMClient("custom", llmWithoutStructured{})
	if _, ok := client.(StructuredJSONClient); ok {
		t.Fatal("instrumentation invented structured capability")
	}
}

type llmWithoutStructured struct{}

func (llmWithoutStructured) DraftCypher(context.Context, DraftRequest) (*DraftResponse, error) {
	return &DraftResponse{}, nil
}

func (llmWithoutStructured) Summarize(context.Context, SummarizeRequest) (string, error) {
	return "", nil
}
