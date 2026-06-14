package graphagent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go"
)

type stubBedrockRuntime struct {
	text      string
	err       error
	lastInput *bedrockruntime.ConverseInput
}

func (s *stubBedrockRuntime) Converse(_ context.Context, input *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	s.lastInput = input
	if s.err != nil {
		return nil, s.err
	}
	return &bedrockruntime.ConverseOutput{
		Output: &bedrocktypes.ConverseOutputMemberMessage{Value: bedrocktypes.Message{
			Content: []bedrocktypes.ContentBlock{&bedrocktypes.ContentBlockMemberText{Value: s.text}},
		}},
	}, nil
}

type stubBedrockAPIError struct {
	code    string
	message string
}

func (e stubBedrockAPIError) Error() string {
	return e.code + ": " + e.ErrorMessage()
}

func (e stubBedrockAPIError) ErrorCode() string {
	return e.code
}

func (e stubBedrockAPIError) ErrorMessage() string {
	if strings.TrimSpace(e.message) != "" {
		return e.message
	}
	return "denied"
}

func (e stubBedrockAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}

func TestBedrockLLMClient_DraftCypherUsesInferenceProfile(t *testing.T) {
	runtime := &stubBedrockRuntime{text: `{"rationale":"ok","cypher":"MATCH (n) RETURN n LIMIT 5","refusal":""}`}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{
		DefaultModel: "us.anthropic.claude-sonnet-4-6",
		Runtime:      runtime,
		MaxTokens:    100,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.DraftCypher(context.Background(), DraftRequest{
		TenantID: "test",
		Question: "Show risky assets",
		Model:    DefaultModel,
	})
	if err != nil {
		t.Fatalf("draft cypher: %v", err)
	}
	if resp.Rationale != "ok" || resp.Cypher != "MATCH (n) RETURN n LIMIT 5" {
		t.Fatalf("draft response = %#v", resp)
	}
	if got := aws.ToString(runtime.lastInput.ModelId); got != "us.anthropic.claude-sonnet-4-6" {
		t.Fatalf("model id = %q, want inference profile", got)
	}
	if runtime.lastInput.InferenceConfig == nil || aws.ToInt32(runtime.lastInput.InferenceConfig.MaxTokens) != 100 {
		t.Fatalf("max_tokens = %#v, want 100", runtime.lastInput.InferenceConfig)
	}
	if len(runtime.lastInput.Messages) != 1 || len(runtime.lastInput.Messages[0].Content) != 1 {
		t.Fatalf("messages = %#v", runtime.lastInput.Messages)
	}
	if !strings.Contains(bedrockContentText(runtime.lastInput.Messages[0].Content[0]), "Show risky assets") {
		t.Fatalf("request message did not include question: %#v", runtime.lastInput.Messages)
	}
}

func TestBedrockLLMClient_Probe(t *testing.T) {
	runtime := &stubBedrockRuntime{text: "OK"}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{DefaultModel: "us.anthropic.claude-sonnet-4-6", Runtime: runtime})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := ProbeLLM(context.Background(), client); err != nil {
		t.Fatalf("ProbeLLM() error = %v", err)
	}
	if got := aws.ToString(runtime.lastInput.ModelId); got != "us.anthropic.claude-sonnet-4-6" {
		t.Fatalf("probe model id = %q, want default model", got)
	}
	if !strings.Contains(bedrockContentText(runtime.lastInput.Messages[0].Content[0]), "Bedrock model is callable") {
		t.Fatalf("probe message = %#v", runtime.lastInput.Messages)
	}
}

func TestBedrockLLMClient_AccessDeniedClassification(t *testing.T) {
	runtime := &stubBedrockRuntime{err: stubBedrockAPIError{code: "AccessDeniedException"}}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{DefaultModel: "us.anthropic.claude-sonnet-4-6", Runtime: runtime})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.Summarize(context.Background(), SummarizeRequest{TenantID: "test", Question: "hello"})
	if err == nil {
		t.Fatal("expected access denied error")
	}
	if !errors.Is(err, ErrLLMAccessDenied) {
		t.Fatalf("error = %v, want ErrLLMAccessDenied", err)
	}
	var denied *BedrockAccessDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %T, want BedrockAccessDeniedError", err)
	}
	if denied.Code != "AccessDeniedException" {
		t.Fatalf("access code = %q", denied.Code)
	}
	if strings.Contains(fmt.Sprint(err), "arn:aws") {
		t.Fatalf("access error leaked ARN: %v", err)
	}
}

func TestBedrockLLMClient_SanitizesGenericProviderErrors(t *testing.T) {
	runtime := &stubBedrockRuntime{err: stubBedrockAPIError{
		code:    "ResourceNotFoundException",
		message: "model arn:aws:bedrock:us-east-1:123456789012:inference-profile/private-model not found; RequestID: req-123",
	}}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{DefaultModel: "us.anthropic.claude-sonnet-4-6", Runtime: runtime})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.Summarize(context.Background(), SummarizeRequest{TenantID: "test", Question: "hello"})
	if err == nil {
		t.Fatal("expected provider error")
	}
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("error = %v, want ErrRuntimeUnavailable", err)
	}
	var invocationErr *BedrockInvocationError
	if !errors.As(err, &invocationErr) {
		t.Fatalf("error = %T, want BedrockInvocationError", err)
	}
	sanitized := fmt.Sprint(err)
	for _, forbidden := range []string{"arn:aws", "req-123", "ResourceNotFoundException", "private-model"} {
		if strings.Contains(sanitized, forbidden) {
			t.Fatalf("sanitized error leaked %q: %v", forbidden, err)
		}
	}
}

func TestBedrockLLMClient_EmptyTextResponseFails(t *testing.T) {
	runtime := &stubBedrockRuntime{text: " "}
	client, err := NewBedrockLLMClient(context.Background(), BedrockConfig{DefaultModel: "us.anthropic.claude-sonnet-4-6", Runtime: runtime})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.Summarize(context.Background(), SummarizeRequest{TenantID: "test", Question: "hello"})
	if err == nil {
		t.Fatal("expected empty text response error")
	}
	if !errors.Is(err, errBedrockNoText) {
		t.Fatalf("error = %v, want errBedrockNoText", err)
	}
}
