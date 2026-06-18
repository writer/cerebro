package graphagent

import (
	"context"
	"fmt"
	"strings"
)

const DefaultModel = "claude-sonnet-4-6"

type HistoryMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type DraftRequest struct {
	TenantID  string
	Question  string
	ScopeURN  string
	Model     string
	History   []HistoryMessage
	MaxRows   int
	Schema    string
	Guardrail string
	Probe     *GraphProbe
}

type DraftResponse struct {
	Rationale string        `json:"rationale"`
	Plan      *AskQueryPlan `json:"plan,omitempty"`
	Cypher    string        `json:"cypher,omitempty"`
	Refusal   string        `json:"refusal,omitempty"`
}

type SummarizeRequest struct {
	TenantID string
	Question string
	ScopeURN string
	Model    string
	Cypher   string
	Rows     []map[string]any
	History  []HistoryMessage
}

type LLMClient interface {
	DraftCypher(context.Context, DraftRequest) (*DraftResponse, error)
	Summarize(context.Context, SummarizeRequest) (string, error)
}

type LLMProber interface {
	Probe(context.Context) error
}

type LLMConfig struct {
	Provider    string
	Model       string
	SonnetModel string
	OpusModel   string
	HaikuModel  string
	Region      string
	MaxTokens   int
	Temperature float64
}

type LLMConfigWithSecrets struct {
	LLMConfig
	OpenRouterAPIKey string
	HTTPDoer         HTTPDoer
}

func NewLLMClient(ctx context.Context, cfg LLMConfig) (LLMClient, error) {
	return NewLLMClientWithSecrets(ctx, LLMConfigWithSecrets{LLMConfig: cfg})
}

func NewLLMClientWithSecrets(ctx context.Context, cfg LLMConfigWithSecrets) (LLMClient, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "bedrock"
	}
	switch provider {
	case "stub":
		return NewStubLLMClient(), nil
	case "bedrock":
		client, err := NewBedrockLLMClient(ctx, BedrockConfig{
			DefaultModel: cfg.Model,
			SonnetModel:  cfg.SonnetModel,
			OpusModel:    cfg.OpusModel,
			HaikuModel:   cfg.HaikuModel,
			Region:       cfg.Region,
			MaxTokens:    cfg.MaxTokens,
			Temperature:  cfg.Temperature,
		})
		if err != nil {
			return nil, err
		}
		return instrumentLLMClient(provider, client), nil
	case "openrouter":
		client, err := NewOpenRouterLLMClient(OpenRouterConfig{
			APIKey:       cfg.OpenRouterAPIKey,
			HTTPDoer:     cfg.HTTPDoer,
			DefaultModel: cfg.Model,
			SonnetModel:  cfg.SonnetModel,
			OpusModel:    cfg.OpusModel,
			HaikuModel:   cfg.HaikuModel,
			MaxTokens:    cfg.MaxTokens,
			Temperature:  cfg.Temperature,
		})
		if err != nil {
			return nil, err
		}
		return instrumentLLMClient(provider, client), nil
	default:
		return nil, fmt.Errorf("%w: unsupported graph agent llm provider %q", ErrInvalidRequest, provider)
	}
}

func ProbeLLM(ctx context.Context, client LLMClient) error {
	if client == nil {
		return nil
	}
	prober, ok := client.(LLMProber)
	if !ok {
		return nil
	}
	return prober.Probe(ctx)
}

func normalizeModel(model string) string {
	if strings.TrimSpace(model) == "" {
		return DefaultModel
	}
	return strings.TrimSpace(model)
}
