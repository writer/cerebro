package graphagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxMCPHistoryItems     = 12
	maxMCPHistoryItemBytes = 4096
)

type MCPAskArguments struct {
	TenantID string
	Question string
	ScopeURN string
	Model    string
	History  any
}

type HistoryInputSchema struct {
	Type     string                 `json:"type"`
	MaxItems int                    `json:"maxItems"`
	Items    HistoryItemInputSchema `json:"items"`
}

type HistoryItemInputSchema struct {
	Type                 string                 `json:"type"`
	AdditionalProperties bool                   `json:"additionalProperties"`
	Properties           HistoryInputProperties `json:"properties"`
	Required             []string               `json:"required"`
}

type HistoryInputProperties struct {
	Role    StringInputSchema `json:"role"`
	Content StringInputSchema `json:"content"`
}

type StringInputSchema struct {
	Type      string   `json:"type"`
	Enum      []string `json:"enum,omitempty"`
	MinLength int      `json:"minLength,omitempty"`
	MaxLength int      `json:"maxLength,omitempty"`
}

// DecodeMCPAskRequest keeps graph-reasoning input semantics behind the graph
// domain boundary while the MCP adapter owns transport and authorization.
func DecodeMCPAskRequest(args MCPAskArguments) (AskRequest, error) {
	history, err := decodeMCPHistory(args.History)
	if err != nil {
		return AskRequest{}, err
	}
	return AskRequest{
		TenantID: strings.TrimSpace(args.TenantID),
		Question: strings.TrimSpace(args.Question),
		ScopeURN: strings.TrimSpace(args.ScopeURN),
		Model:    strings.TrimSpace(args.Model),
		History:  history,
	}, nil
}

func GraphHistoryInputSchema() HistoryInputSchema {
	return HistoryInputSchema{
		Type:     "array",
		MaxItems: maxMCPHistoryItems,
		Items: HistoryItemInputSchema{
			Type:                 "object",
			AdditionalProperties: false,
			Properties: HistoryInputProperties{
				Role:    StringInputSchema{Type: "string", Enum: []string{"assistant", "user"}},
				Content: StringInputSchema{Type: "string", MinLength: 1, MaxLength: maxMCPHistoryItemBytes},
			},
			Required: []string{"role", "content"},
		},
	}
}

func decodeMCPHistory(raw any) ([]HistoryMessage, error) {
	if raw == nil {
		return nil, nil
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: graph reasoning history is invalid", ErrInvalidRequest)
	}
	var history []HistoryMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&history); err != nil {
		return nil, fmt.Errorf("%w: graph reasoning history is invalid", ErrInvalidRequest)
	}
	if len(history) > maxMCPHistoryItems {
		return nil, fmt.Errorf("%w: graph reasoning history exceeds %d items", ErrInvalidRequest, maxMCPHistoryItems)
	}
	for _, message := range history {
		role := strings.TrimSpace(message.Role)
		content := strings.TrimSpace(message.Content)
		if (role != "assistant" && role != "user") || content == "" || len(content) > maxMCPHistoryItemBytes {
			return nil, fmt.Errorf("%w: graph reasoning history contains an invalid message", ErrInvalidRequest)
		}
	}
	return history, nil
}
