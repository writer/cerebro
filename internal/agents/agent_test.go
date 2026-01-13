package agents

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// MockLLMProvider for testing
type MockLLMProvider struct {
	response *Response
	err      error
}

func (m *MockLLMProvider) Complete(ctx context.Context, messages []Message, tools []Tool) (*Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *MockLLMProvider) Stream(ctx context.Context, messages []Message, tools []Tool) (<-chan StreamEvent, error) {
	ch := make(chan StreamEvent)
	go func() {
		ch <- StreamEvent{Content: "test", Done: true}
		close(ch)
	}()
	return ch, nil
}

func TestAgentRegistry_NewAgentRegistry(t *testing.T) {
	r := NewAgentRegistry()
	if r == nil {
		t.Fatal("NewAgentRegistry returned nil")
	}

	if r.agents == nil {
		t.Error("agents map should be initialized")
	}

	if r.sessions == nil {
		t.Error("sessions map should be initialized")
	}
}

func TestAgentRegistry_RegisterAgent(t *testing.T) {
	r := NewAgentRegistry()

	agent := &Agent{
		ID:          "test-agent",
		Name:        "Test Agent",
		Description: "A test agent",
		Provider:    &MockLLMProvider{},
	}

	r.RegisterAgent(agent)

	found, ok := r.GetAgent("test-agent")
	if !ok {
		t.Fatal("expected to find registered agent")
	}

	if found.Name != "Test Agent" {
		t.Errorf("got name %s, want Test Agent", found.Name)
	}
}

func TestAgentRegistry_ListAgents(t *testing.T) {
	r := NewAgentRegistry()

	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Agent 1"})
	r.RegisterAgent(&Agent{ID: "agent-2", Name: "Agent 2"})
	r.RegisterAgent(&Agent{ID: "agent-3", Name: "Agent 3"})

	agents := r.ListAgents()
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}

func TestAgentRegistry_CreateSession(t *testing.T) {
	r := NewAgentRegistry()

	agent := &Agent{
		ID:   "test-agent",
		Name: "Test Agent",
	}
	r.RegisterAgent(agent)

	ctx := SessionContext{
		FindingIDs: []string{"f1", "f2"},
		AssetIDs:   []string{"a1"},
	}

	session, err := r.CreateSession("test-agent", "user-123", ctx)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if session.ID == "" {
		t.Error("session ID should be generated")
	}

	if session.AgentID != "test-agent" {
		t.Errorf("got agent ID %s, want test-agent", session.AgentID)
	}

	if session.UserID != "user-123" {
		t.Errorf("got user ID %s, want user-123", session.UserID)
	}

	if session.Status != "active" {
		t.Errorf("got status %s, want active", session.Status)
	}

	if len(session.Context.FindingIDs) != 2 {
		t.Error("session context should have finding IDs")
	}
}

func TestAgentRegistry_CreateSession_AgentNotFound(t *testing.T) {
	r := NewAgentRegistry()

	_, err := r.CreateSession("non-existent", "user-123", SessionContext{})
	if err == nil {
		t.Error("expected error for non-existent agent")
	}
}

func TestAgentRegistry_GetSession(t *testing.T) {
	r := NewAgentRegistry()

	r.RegisterAgent(&Agent{ID: "test-agent"})
	session, _ := r.CreateSession("test-agent", "user", SessionContext{})

	found, ok := r.GetSession(session.ID)
	if !ok {
		t.Fatal("expected to find session")
	}

	if found.ID != session.ID {
		t.Errorf("got ID %s, want %s", found.ID, session.ID)
	}

	// Non-existent session
	_, ok = r.GetSession("non-existent")
	if ok {
		t.Error("expected not to find non-existent session")
	}
}

func TestAgentRegistry_UpdateSession(t *testing.T) {
	r := NewAgentRegistry()

	r.RegisterAgent(&Agent{ID: "test-agent"})
	session, _ := r.CreateSession("test-agent", "user", SessionContext{})

	originalTime := session.UpdatedAt

	time.Sleep(10 * time.Millisecond)
	session.Status = "completed"
	r.UpdateSession(session)

	updated, _ := r.GetSession(session.ID)
	if updated.Status != "completed" {
		t.Error("session should be updated")
	}

	if !updated.UpdatedAt.After(originalTime) {
		t.Error("UpdatedAt should be updated")
	}
}

func TestMemory_NewMemory(t *testing.T) {
	m := NewMemory(100)
	if m == nil {
		t.Fatal("NewMemory returned nil")
	}

	if m.maxSize != 100 {
		t.Errorf("got maxSize %d, want 100", m.maxSize)
	}
}

func TestMemory_Add(t *testing.T) {
	m := NewMemory(10)

	m.Add("test content", "fact", 0.8, time.Hour)

	entries := m.Search("", 10)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Content != "test content" {
		t.Errorf("got content %s, want test content", entries[0].Content)
	}

	if entries[0].Type != "fact" {
		t.Errorf("got type %s, want fact", entries[0].Type)
	}
}

func TestMemory_MaxSize(t *testing.T) {
	m := NewMemory(3)

	for i := 0; i < 5; i++ {
		m.Add("content", "fact", 0.5, time.Hour)
	}

	entries := m.Search("", 10)
	if len(entries) != 3 {
		t.Errorf("expected max 3 entries, got %d", len(entries))
	}
}

func TestMemory_Search_ExpiresEntries(t *testing.T) {
	m := NewMemory(10)

	// Add expired entry
	m.Add("expired", "fact", 0.5, -time.Hour)

	// Add valid entry
	m.Add("valid", "fact", 0.5, time.Hour)

	entries := m.Search("", 10)
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(entries))
	}

	if entries[0].Content != "valid" {
		t.Error("expected only valid entry")
	}
}

func TestMessage_Fields(t *testing.T) {
	msg := Message{
		Role:    "user",
		Content: "Hello",
		Name:    "test-user",
		ToolCalls: []ToolCall{
			{ID: "call-1", Name: "search"},
		},
		Metadata: map[string]interface{}{"key": "value"},
	}

	if msg.Role != "user" {
		t.Error("Role field incorrect")
	}

	if len(msg.ToolCalls) != 1 {
		t.Error("ToolCalls field incorrect")
	}
}

func TestToolCall_Fields(t *testing.T) {
	args := json.RawMessage(`{"query": "test"}`)
	tc := ToolCall{
		ID:        "call-1",
		Name:      "search",
		Arguments: args,
	}

	if tc.ID != "call-1" {
		t.Error("ID field incorrect")
	}

	if tc.Name != "search" {
		t.Error("Name field incorrect")
	}
}

func TestTool_Fields(t *testing.T) {
	tool := Tool{
		Name:        "search_findings",
		Description: "Search for security findings",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type": "string",
				},
			},
		},
		RequiresApproval: true,
	}

	if tool.Name != "search_findings" {
		t.Error("Name field incorrect")
	}

	if !tool.RequiresApproval {
		t.Error("RequiresApproval field incorrect")
	}
}

func TestSession_Fields(t *testing.T) {
	now := time.Now()
	session := &Session{
		ID:      "session-1",
		AgentID: "agent-1",
		UserID:  "user-1",
		Status:  "active",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
		Context: SessionContext{
			FindingIDs: []string{"f1"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if session.ID != "session-1" {
		t.Error("ID field incorrect")
	}

	if len(session.Messages) != 1 {
		t.Error("Messages field incorrect")
	}
}

func TestSessionContext_Fields(t *testing.T) {
	ctx := SessionContext{
		FindingIDs: []string{"f1", "f2"},
		AssetIDs:   []string{"a1"},
		Investigation: &Investigation{
			ID:    "inv-1",
			Title: "Test Investigation",
		},
		Metadata: map[string]interface{}{"key": "value"},
	}

	if len(ctx.FindingIDs) != 2 {
		t.Error("FindingIDs field incorrect")
	}

	if ctx.Investigation.Title != "Test Investigation" {
		t.Error("Investigation field incorrect")
	}
}

func TestInvestigation_Fields(t *testing.T) {
	now := time.Now()
	inv := &Investigation{
		ID:          "inv-1",
		Title:       "Security Incident",
		Description: "A critical security incident",
		Severity:    "critical",
		Status:      "active",
		Findings:    []string{"f1", "f2"},
		Timeline: []Event{
			{Timestamp: now, Type: "created", Description: "Investigation created"},
		},
		CreatedAt: now,
	}

	if inv.Severity != "critical" {
		t.Error("Severity field incorrect")
	}

	if len(inv.Timeline) != 1 {
		t.Error("Timeline field incorrect")
	}
}

func TestUsage_Fields(t *testing.T) {
	usage := Usage{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	if usage.TotalTokens != 150 {
		t.Error("TotalTokens field incorrect")
	}
}

func TestResponse_Fields(t *testing.T) {
	resp := &Response{
		Message: Message{
			Role:    "assistant",
			Content: "Hello!",
		},
		Usage: Usage{
			TotalTokens: 100,
		},
		FinishReason: "stop",
	}

	if resp.FinishReason != "stop" {
		t.Error("FinishReason field incorrect")
	}
}
