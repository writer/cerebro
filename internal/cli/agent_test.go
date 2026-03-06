package cli

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/evalops/cerebro/internal/agents"
)

type scriptedProvider struct {
	responses []*agents.Response
	index     int
}

func (p *scriptedProvider) Complete(_ context.Context, _ []agents.Message, _ []agents.Tool) (*agents.Response, error) {
	if p.index >= len(p.responses) {
		return &agents.Response{Message: agents.Message{Role: "assistant", Content: "done"}}, nil
	}

	resp := p.responses[p.index]
	p.index++
	return resp, nil
}

func (p *scriptedProvider) Stream(context.Context, []agents.Message, []agents.Tool) (<-chan agents.StreamEvent, error) {
	return nil, errors.New("not implemented")
}

func TestRunAgentLoop_ApprovalDeniedSkipsTool(t *testing.T) {
	called := false
	toolCall := agents.ToolCall{
		ID:        "call-1",
		Name:      "dangerous",
		Arguments: json.RawMessage(`{"target":"x"}`),
	}

	provider := &scriptedProvider{
		responses: []*agents.Response{
			{Message: agents.Message{Role: "assistant", ToolCalls: []agents.ToolCall{toolCall}}},
			{Message: agents.Message{Role: "assistant", Content: "approval needed"}},
		},
	}

	session := &agents.Session{
		ID:       "session-1",
		Status:   "active",
		Messages: []agents.Message{{Role: "user", Content: "run tool"}},
	}

	tools := []agents.Tool{{
		Name:             "dangerous",
		RequiresApproval: true,
		Handler: func(context.Context, json.RawMessage) (string, error) {
			called = true
			return "ok", nil
		},
	}}

	err := runAgentLoop(context.Background(), provider, session, tools, func(_ *agents.Tool, _ agents.ToolCall) bool {
		return false
	})
	if err != nil {
		t.Fatalf("runAgentLoop returned error: %v", err)
	}
	if called {
		t.Fatal("expected tool handler not to be called when approval is denied")
	}
	if session.Status != "pending_approval" {
		t.Fatalf("expected session status pending_approval, got %s", session.Status)
	}
}

func TestRunAgentLoop_ApprovalGrantedExecutesTool(t *testing.T) {
	called := false
	toolCall := agents.ToolCall{
		ID:        "call-1",
		Name:      "dangerous",
		Arguments: json.RawMessage(`{"target":"x"}`),
	}

	provider := &scriptedProvider{
		responses: []*agents.Response{
			{Message: agents.Message{Role: "assistant", ToolCalls: []agents.ToolCall{toolCall}}},
			{Message: agents.Message{Role: "assistant", Content: "done"}},
		},
	}

	session := &agents.Session{
		ID:       "session-1",
		Status:   "active",
		Messages: []agents.Message{{Role: "user", Content: "run tool"}},
	}

	tools := []agents.Tool{{
		Name:             "dangerous",
		RequiresApproval: true,
		Handler: func(context.Context, json.RawMessage) (string, error) {
			called = true
			return "ok", nil
		},
	}}

	err := runAgentLoop(context.Background(), provider, session, tools, func(_ *agents.Tool, _ agents.ToolCall) bool {
		return true
	})
	if err != nil {
		t.Fatalf("runAgentLoop returned error: %v", err)
	}
	if !called {
		t.Fatal("expected tool handler to be called when approval is granted")
	}
	if session.Status != "active" {
		t.Fatalf("expected session status active, got %s", session.Status)
	}
}
