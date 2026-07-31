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

// DecodeMCPAskRequest keeps graph-reasoning input semantics behind the graph
// domain boundary while the MCP adapter owns transport and authorization.
func DecodeMCPAskRequest(args map[string]any) (AskRequest, error) {
	history, err := decodeMCPHistory(args["history"])
	if err != nil {
		return AskRequest{}, err
	}
	return AskRequest{
		TenantID: textArg(args, "tenant_id"),
		Question: textArg(args, "question"),
		ScopeURN: textArg(args, "scope_urn"),
		Model:    textArg(args, "model"),
		History:  history,
	}, nil
}

func MCPHistoryInputSchema() map[string]any {
	return map[string]any{
		"type":     "array",
		"maxItems": maxMCPHistoryItems,
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"role":    map[string]any{"type": "string", "enum": []string{"assistant", "user"}},
				"content": map[string]any{"type": "string", "minLength": 1, "maxLength": maxMCPHistoryItemBytes},
			},
			"required": []string{"role", "content"},
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

func textArg(args map[string]any, key string) string {
	value, ok := args[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
