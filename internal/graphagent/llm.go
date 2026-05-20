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
}

type DraftResponse struct {
	Rationale string `json:"rationale"`
	Cypher    string `json:"cypher,omitempty"`
	Refusal   string `json:"refusal,omitempty"`
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

type LLMConfig struct {
	Provider    string
	Model       string
	SonnetModel string
	OpusModel   string
	HaikuModel  string
	MaxTokens   int
	Temperature float64
}

func NewLLMClient(ctx context.Context, cfg LLMConfig) (LLMClient, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "bedrock"
	}
	switch provider {
	case "stub":
		return NewStubLLMClient(), nil
	case "bedrock":
		return NewBedrockLLMClient(ctx, BedrockConfig{
			DefaultModel: cfg.Model,
			SonnetModel:  cfg.SonnetModel,
			OpusModel:    cfg.OpusModel,
			HaikuModel:   cfg.HaikuModel,
			MaxTokens:    cfg.MaxTokens,
			Temperature:  cfg.Temperature,
		})
	default:
		return nil, fmt.Errorf("%w: unsupported graph agent llm provider %q", ErrInvalidRequest, provider)
	}
}

func normalizeModel(model string) string {
	if strings.TrimSpace(model) == "" {
		return DefaultModel
	}
	return strings.TrimSpace(model)
}
