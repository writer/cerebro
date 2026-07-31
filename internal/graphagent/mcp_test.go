package graphagent

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeMCPAskRequest(t *testing.T) {
	request, err := DecodeMCPAskRequest(map[string]any{
		"tenant_id": " tenant-one ",
		"question":  " What changed? ",
		"scope_urn": " urn:cerebro:tenant-one:asset:one ",
		"model":     " claude-opus-4-7 ",
		"history": []any{
			map[string]any{"role": "user", "content": "Check the production asset."},
			map[string]any{"role": "assistant", "content": "The prior evidence was incomplete."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.TenantID != "tenant-one" || request.Question != "What changed?" || len(request.History) != 2 {
		t.Fatalf("DecodeMCPAskRequest() = %#v", request)
	}
	if request.History[1].Content != "The prior evidence was incomplete." {
		t.Fatalf("history = %#v", request.History)
	}
}

func TestDecodeMCPAskRequestRejectsInvalidHistory(t *testing.T) {
	tests := map[string]any{
		"unknown field": []any{map[string]any{"role": "user", "content": "hello", "extra": true}},
		"invalid role":  []any{map[string]any{"role": "system", "content": "hello"}},
		"empty content": []any{map[string]any{"role": "user", "content": "  "}},
		"oversized":     []any{map[string]any{"role": "user", "content": strings.Repeat("x", maxMCPHistoryItemBytes+1)}},
		"too many": func() []any {
			items := make([]any, maxMCPHistoryItems+1)
			for index := range items {
				items[index] = map[string]any{"role": "user", "content": "hello"}
			}
			return items
		}(),
	}
	for name, history := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeMCPAskRequest(map[string]any{"history": history})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestMCPHistoryInputSchemaMatchesDecoderBounds(t *testing.T) {
	schema := MCPHistoryInputSchema()
	if schema["maxItems"] != maxMCPHistoryItems {
		t.Fatalf("maxItems = %#v", schema["maxItems"])
	}
	items := schema["items"].(map[string]any)
	properties := items["properties"].(map[string]any)
	content := properties["content"].(map[string]any)
	if content["maxLength"] != maxMCPHistoryItemBytes {
		t.Fatalf("content maxLength = %#v", content["maxLength"])
	}
}
