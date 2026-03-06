package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/agents"
)

// Agent endpoints

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agentList := s.app.Agents.ListAgents()
	result := make([]map[string]interface{}, len(agentList))
	for i, a := range agentList {
		result[i] = map[string]interface{}{
			"id":          a.ID,
			"name":        a.Name,
			"description": a.Description,
			"tools":       len(a.Tools),
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"agents": result, "count": len(result)})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, ok := s.app.Agents.GetAgent(id)
	if !ok {
		s.error(w, http.StatusNotFound, "agent not found")
		return
	}

	tools := make([]map[string]interface{}, len(agent.Tools))
	for i, t := range agent.Tools {
		tools[i] = map[string]interface{}{
			"name":              t.Name,
			"description":       t.Description,
			"requires_approval": t.RequiresApproval,
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"id":          agent.ID,
		"name":        agent.Name,
		"description": agent.Description,
		"tools":       tools,
	})
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID    string                 `json:"agent_id"`
		UserID     string                 `json:"user_id"`
		FindingIDs []string               `json:"finding_ids,omitempty"`
		Context    map[string]interface{} `json:"context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	authenticatedUserID := strings.TrimSpace(GetUserID(r.Context()))
	requestedUserID := strings.TrimSpace(req.UserID)
	sessionUserID := requestedUserID
	if authenticatedUserID != "" {
		if requestedUserID != "" && requestedUserID != authenticatedUserID {
			s.error(w, http.StatusForbidden, "cannot create a session for another user")
			return
		}
		sessionUserID = authenticatedUserID
	}
	if sessionUserID == "" {
		s.error(w, http.StatusBadRequest, "user_id is required")
		return
	}

	session, err := s.app.Agents.CreateSession(req.AgentID, sessionUserID, agents.SessionContext{
		FindingIDs: req.FindingIDs,
		Metadata:   req.Context,
	})
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusCreated, session)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(id)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	if !canAccessSession(r, session) {
		s.error(w, http.StatusForbidden, "forbidden")
		return
	}
	s.json(w, http.StatusOK, session)
}

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(sessionID)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	if !canAccessSession(r, session) {
		s.error(w, http.StatusForbidden, "forbidden")
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		s.error(w, http.StatusBadRequest, "content is required")
		return
	}

	// Add user message
	session.Status = "active"
	session.Messages = append(session.Messages, agents.Message{
		Role:    "user",
		Content: req.Content,
	})

	// Get agent and generate response
	agent, ok := s.app.Agents.GetAgent(session.AgentID)
	if !ok || agent.Provider == nil {
		// Return guidance if no LLM provider is configured
		session.Messages = append(session.Messages, agents.Message{
			Role:    "assistant",
			Content: "I understand you want help with: " + req.Content + ". However, no LLM provider is configured. Please set ANTHROPIC_API_KEY or OPENAI_API_KEY.",
		})
		if err := s.app.Agents.UpdateSession(session); err != nil {
			s.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.json(w, http.StatusOK, session.Messages[len(session.Messages)-1])
		return
	}

	resp, err := s.runAgentSessionLoop(r.Context(), session, agent)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Agents.UpdateSession(session); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, resp)
}

func (s *Server) approveSessionToolCall(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(sessionID)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	if !canAccessSession(r, session) {
		s.error(w, http.StatusForbidden, "forbidden")
		return
	}

	agent, ok := s.app.Agents.GetAgent(session.AgentID)
	if !ok || agent.Provider == nil {
		s.error(w, http.StatusBadRequest, "agent provider not configured")
		return
	}

	pendingCall, ok := pendingToolCallFromSession(session)
	if !ok {
		s.error(w, http.StatusBadRequest, "no pending tool call requiring approval")
		return
	}

	if !pendingCall.CreatedAt.IsZero() && time.Since(pendingCall.CreatedAt) > pendingToolApprovalTTL {
		clearPendingToolCall(session)
		session.Status = "active"
		msg := agents.Message{
			Role:    "assistant",
			Content: fmt.Sprintf("Approval window expired for tool %s. Please re-run the request.", pendingCall.Name),
			Metadata: map[string]interface{}{
				"status": "approval_expired",
			},
		}
		session.Messages = append(session.Messages, msg)
		s.logToolApprovalDecision(r.Context(), r, session, pendingCall, "expired")
		if err := s.app.Agents.UpdateSession(session); err != nil {
			s.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.json(w, http.StatusBadRequest, msg)
		return
	}

	var req struct {
		Approve *bool `json:"approve,omitempty"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			s.error(w, http.StatusBadRequest, "invalid request")
			return
		}
	}

	approved := true
	if req.Approve != nil {
		approved = *req.Approve
	}

	if !approved {
		clearPendingToolCall(session)
		session.Status = "active"
		msg := agents.Message{
			Role:    "assistant",
			Content: fmt.Sprintf("Approval denied for tool %s. The tool was not executed.", pendingCall.Name),
			Metadata: map[string]interface{}{
				"status": "approval_denied",
			},
		}
		session.Messages = append(session.Messages, msg)
		s.logToolApprovalDecision(r.Context(), r, session, pendingCall, "denied")
		if err := s.app.Agents.UpdateSession(session); err != nil {
			s.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.json(w, http.StatusOK, msg)
		return
	}

	tool := findAgentTool(agent.Tools, pendingCall.Name)
	if tool == nil {
		s.error(w, http.StatusBadRequest, "pending tool not found on agent")
		return
	}
	if !tool.RequiresApproval {
		s.error(w, http.StatusBadRequest, "pending tool does not require approval")
		return
	}
	if err := tool.ValidateExecution(true); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logToolApprovalDecision(r.Context(), r, session, pendingCall, "approved")

	argsRaw, _ := json.Marshal(pendingCall.Arguments)
	output, err := tool.Handler(r.Context(), argsRaw)
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
		Name:    pendingCall.ID,
	})

	clearPendingToolCall(session)
	session.Status = "active"

	resp, err := s.runAgentSessionLoop(r.Context(), session, agent)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := s.app.Agents.UpdateSession(session); err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, resp)
}

func (s *Server) getMessages(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := s.app.Agents.GetSession(sessionID)
	if !ok {
		s.error(w, http.StatusNotFound, "session not found")
		return
	}
	if !canAccessSession(r, session) {
		s.error(w, http.StatusForbidden, "forbidden")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"messages": session.Messages, "count": len(session.Messages)})
}

func canAccessSession(r *http.Request, session *agents.Session) bool {
	if session == nil {
		return false
	}
	authenticatedUserID := strings.TrimSpace(GetUserID(r.Context()))
	if authenticatedUserID == "" {
		return true
	}
	return strings.TrimSpace(session.UserID) == authenticatedUserID
}
