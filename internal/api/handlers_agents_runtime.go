package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/snowflake"
)

func (s *Server) runAgentSessionLoop(ctx context.Context, session *agents.Session, agent *agents.Agent) (agents.Message, error) {
	const maxTurns = 15

	for i := 0; i < maxTurns; i++ {
		messages := make([]agents.Message, 0, len(session.Messages)+1)
		messages = append(messages, agents.Message{Role: "system", Content: session.GetSystemPrompt()})
		messages = append(messages, session.Messages...)

		resp, err := agent.Provider.Complete(ctx, messages, agent.Tools)
		if err != nil {
			return agents.Message{}, err
		}

		session.Messages = append(session.Messages, resp.Message)
		if len(resp.Message.ToolCalls) == 0 {
			clearPendingToolCall(session)
			session.Status = "active"
			return resp.Message, nil
		}

		blocked := s.executeAgentToolCalls(ctx, session, agent.Tools, resp.Message.ToolCalls)
		if blocked {
			pending := pendingApprovalMessage(session)
			session.Messages = append(session.Messages, pending)
			return pending, nil
		}
	}

	timeoutMessage := agents.Message{
		Role:    "assistant",
		Content: "I reached the maximum number of tool-execution turns for this request. Please narrow the scope and try again.",
	}
	session.Messages = append(session.Messages, timeoutMessage)
	return timeoutMessage, nil
}

func (s *Server) executeAgentToolCalls(ctx context.Context, session *agents.Session, tools []agents.Tool, calls []agents.ToolCall) bool {
	for _, tc := range calls {
		tool := findAgentTool(tools, tc.Name)
		if tool == nil {
			session.Messages = append(session.Messages, agents.Message{
				Role:    "tool",
				Content: fmt.Sprintf("Error: Tool %s not found", tc.Name),
				Name:    tc.ID,
			})
			continue
		}

		if err := tool.ValidateExecution(false); err != nil {
			var toolErr *agents.ToolError
			if errors.As(err, &toolErr) && toolErr.Code == "approval_required" {
				session.Status = "pending_approval"
				setPendingToolCall(session, tc)
				session.Messages = append(session.Messages, agents.Message{
					Role:    "tool",
					Content: approvalRequiredToolOutput(tc.Name),
					Name:    tc.ID,
				})
				return true
			}

			output := fmt.Sprintf("Error executing tool: %v", err)
			if errors.As(err, &toolErr) {
				output = toolErr.JSON()
			}
			session.Messages = append(session.Messages, agents.Message{
				Role:    "tool",
				Content: output,
				Name:    tc.ID,
			})
			continue
		}

		output, err := tool.Handler(ctx, tc.Arguments)
		if err != nil {
			var toolErr *agents.ToolError
			if errors.As(err, &toolErr) {
				output = toolErr.JSON()
			} else {
				output = fmt.Sprintf("Error executing tool: %v", err)
			}
		}

		session.Messages = append(session.Messages, agents.Message{
			Role:    "tool",
			Content: output,
			Name:    tc.ID,
		})
	}

	clearPendingToolCall(session)
	session.Status = "active"
	return false
}

func findAgentTool(tools []agents.Tool, name string) *agents.Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

func approvalRequiredToolOutput(toolName string) string {
	payload, _ := json.Marshal(map[string]string{
		"error": fmt.Sprintf("tool %s requires approval before execution", toolName),
		"code":  "approval_required",
	})
	return string(payload)
}

const pendingToolApprovalTTL = 30 * time.Minute

func setPendingToolCall(session *agents.Session, call agents.ToolCall) {
	if session.Context.Metadata == nil {
		session.Context.Metadata = map[string]interface{}{}
	}

	var args interface{} = map[string]interface{}{}
	if len(call.Arguments) > 0 {
		_ = json.Unmarshal(call.Arguments, &args)
	}

	session.Context.Metadata["pending_tool_call"] = map[string]interface{}{
		"id":         call.ID,
		"name":       call.Name,
		"arguments":  args,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func clearPendingToolCall(session *agents.Session) {
	if session.Context.Metadata == nil {
		return
	}
	delete(session.Context.Metadata, "pending_tool_call")
}

func pendingApprovalMessage(session *agents.Session) agents.Message {
	metadata := map[string]interface{}{"status": "pending_approval"}
	if session.Context.Metadata != nil {
		if pending, ok := session.Context.Metadata["pending_tool_call"]; ok {
			metadata["pending_tool_call"] = pending
		}
	}

	return agents.Message{
		Role:     "assistant",
		Content:  "Tool execution is paused because this action requires approval.",
		Metadata: metadata,
	}
}

func (s *Server) logToolApprovalDecision(ctx context.Context, r *http.Request, session *agents.Session, pendingCall pendingToolCall, decision string) {
	if s.auditLogger == nil {
		return
	}

	approverID := strings.TrimSpace(GetUserID(ctx))
	if approverID == "" {
		approverID = strings.TrimSpace(session.UserID)
	}

	details := map[string]interface{}{
		"session_id":   session.ID,
		"tool_call_id": pendingCall.ID,
		"tool_name":    pendingCall.Name,
		"decision":     decision,
		"approver_id":  approverID,
		"decided_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if !pendingCall.CreatedAt.IsZero() {
		details["requested_at"] = pendingCall.CreatedAt.UTC().Format(time.RFC3339Nano)
	}

	entry := &snowflake.AuditEntry{
		Action:       "agent.tool_approval",
		ActorID:      approverID,
		ActorType:    "user",
		ResourceType: "agent_session_tool_call",
		ResourceID:   pendingCall.ID,
		Details:      details,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}

	if err := s.auditLogger.Log(ctx, entry); err != nil && s.app.Logger != nil {
		s.app.Logger.Warn("failed to persist tool approval audit log", "error", err, "session_id", session.ID, "tool_call_id", pendingCall.ID, "decision", decision)
	}
}

func pendingToolCallFromSession(session *agents.Session) (pendingToolCall, bool) {
	if session.Context.Metadata == nil {
		return pendingToolCall{}, false
	}

	raw, ok := session.Context.Metadata["pending_tool_call"]
	if !ok {
		return pendingToolCall{}, false
	}

	pendingMap, ok := raw.(map[string]interface{})
	if !ok {
		return pendingToolCall{}, false
	}

	id, _ := pendingMap["id"].(string)
	name, _ := pendingMap["name"].(string)
	if id == "" || name == "" {
		return pendingToolCall{}, false
	}

	arguments, ok := pendingMap["arguments"]
	if !ok {
		arguments = map[string]interface{}{}
	}

	var createdAt time.Time
	if createdRaw, ok := pendingMap["created_at"].(string); ok && strings.TrimSpace(createdRaw) != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, createdRaw); err == nil {
			createdAt = parsed.UTC()
		}
	}

	return pendingToolCall{ID: id, Name: name, Arguments: arguments, CreatedAt: createdAt}, true
}

type pendingToolCall struct {
	ID        string
	Name      string
	Arguments interface{}
	CreatedAt time.Time
}
