package agents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type mockSessionStore struct {
	sessions map[string]*Session
}

type failingSessionStore struct {
	saveErr error
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]*Session)}
}

func (m *mockSessionStore) Save(_ context.Context, session *Session) error {
	copy := *session
	m.sessions[session.ID] = &copy
	return nil
}

func (m *mockSessionStore) Get(_ context.Context, id string) (*Session, error) {
	session, ok := m.sessions[id]
	if !ok {
		return nil, nil
	}
	copy := *session
	return &copy, nil
}

func (f *failingSessionStore) Save(_ context.Context, _ *Session) error {
	return f.saveErr
}

func (f *failingSessionStore) Get(_ context.Context, _ string) (*Session, error) {
	return nil, nil
}

func TestNewMemory(t *testing.T) {
	m := NewMemory(100)
	if m == nil {
		t.Fatal("expected memory to be created")
	}
	if m.maxSize != 100 {
		t.Errorf("expected maxSize 100, got %d", m.maxSize)
	}
	if m.entries == nil {
		t.Error("expected entries to be initialized")
	}
}

func TestMemory_Add(t *testing.T) {
	m := NewMemory(10)

	m.Add("test content", "fact", 0.9, time.Hour)

	entries := m.Search("", 10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Content != "test content" {
		t.Errorf("expected content 'test content', got '%s'", entries[0].Content)
	}
	if entries[0].Type != "fact" {
		t.Errorf("expected type 'fact', got '%s'", entries[0].Type)
	}
	if entries[0].Relevance != 0.9 {
		t.Errorf("expected relevance 0.9, got %f", entries[0].Relevance)
	}
}

func TestMemory_Add_Pruning(t *testing.T) {
	m := NewMemory(3)

	for i := 0; i < 5; i++ {
		m.Add("content", "fact", 0.5, time.Hour)
	}

	entries := m.Search("", 10)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries after pruning, got %d", len(entries))
	}
}

func TestMemory_Search_ExpiresAt(t *testing.T) {
	m := NewMemory(10)

	// Add expired entry
	m.Add("expired", "fact", 0.5, -time.Hour)
	// Add valid entry
	m.Add("valid", "fact", 0.5, time.Hour)

	entries := m.Search("", 10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
	if entries[0].Content != "valid" {
		t.Errorf("expected 'valid', got '%s'", entries[0].Content)
	}
}

func TestMemory_Search_Limit(t *testing.T) {
	m := NewMemory(10)

	for i := 0; i < 5; i++ {
		m.Add("content", "fact", 0.5, time.Hour)
	}

	entries := m.Search("", 2)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries with limit, got %d", len(entries))
	}
}

func TestMemory_Search_QueryAwareRanking(t *testing.T) {
	m := NewMemory(10)

	m.Add("jira triage note", "observation", 0.2, time.Hour)
	m.Add("aws admin role can assume prod", "fact", 0.9, time.Hour)

	entries := m.Search("aws admin", 1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Content != "aws admin role can assume prod" {
		t.Fatalf("expected query-relevant entry, got %q", entries[0].Content)
	}
}

func TestNewAgentRegistry(t *testing.T) {
	r := NewAgentRegistry()
	if r == nil {
		t.Fatal("expected registry to be created")
	}
	if r.agents == nil {
		t.Error("expected agents map to be initialized")
	}
	if r.sessions == nil {
		t.Error("expected sessions map to be initialized")
	}
}

func TestAgentRegistry_RegisterAgent(t *testing.T) {
	r := NewAgentRegistry()
	agent := &Agent{
		ID:          "agent-1",
		Name:        "Test Agent",
		Description: "A test agent",
	}

	r.RegisterAgent(agent)

	got, ok := r.GetAgent("agent-1")
	if !ok {
		t.Fatal("expected agent to be found")
	}
	if got.Name != "Test Agent" {
		t.Errorf("expected name 'Test Agent', got '%s'", got.Name)
	}
}

func TestAgentRegistry_GetAgent_NotFound(t *testing.T) {
	r := NewAgentRegistry()
	_, ok := r.GetAgent("nonexistent")
	if ok {
		t.Error("expected agent not to be found")
	}
}

func TestAgentRegistry_ListAgents(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Agent 1"})
	r.RegisterAgent(&Agent{ID: "agent-2", Name: "Agent 2"})

	agents := r.ListAgents()
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestAgentRegistry_CreateSession(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Test Agent"})

	session, err := r.CreateSession("agent-1", "user-123", SessionContext{
		FindingIDs: []string{"finding-1"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.ID == "" {
		t.Error("expected session ID to be set")
	}
	if session.AgentID != "agent-1" {
		t.Errorf("expected AgentID 'agent-1', got '%s'", session.AgentID)
	}
	if session.UserID != "user-123" {
		t.Errorf("expected UserID 'user-123', got '%s'", session.UserID)
	}
	if session.Status != "active" {
		t.Errorf("expected status 'active', got '%s'", session.Status)
	}
	if len(session.Context.FindingIDs) != 1 {
		t.Errorf("expected 1 finding ID, got %d", len(session.Context.FindingIDs))
	}
}

func TestAgentRegistry_CreateSession_AgentNotFound(t *testing.T) {
	r := NewAgentRegistry()
	_, err := r.CreateSession("nonexistent", "user-123", SessionContext{})
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestAgentRegistry_GetSession(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1"})
	session, _ := r.CreateSession("agent-1", "user-123", SessionContext{})

	got, ok := r.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to be found")
	}
	if got.ID != session.ID {
		t.Errorf("expected session ID '%s', got '%s'", session.ID, got.ID)
	}
}

func TestAgentRegistry_GetSession_NotFound(t *testing.T) {
	r := NewAgentRegistry()
	_, ok := r.GetSession("nonexistent")
	if ok {
		t.Error("expected session not to be found")
	}
}

func TestAgentRegistry_UpdateSession(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1"})
	session, _ := r.CreateSession("agent-1", "user-123", SessionContext{})

	originalUpdated := session.UpdatedAt
	time.Sleep(time.Millisecond)

	session.Status = "completed"
	if err := r.UpdateSession(session); err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}

	got, _ := r.GetSession(session.ID)
	if got.Status != "completed" {
		t.Errorf("expected status 'completed', got '%s'", got.Status)
	}
	if !got.UpdatedAt.After(originalUpdated) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestAgentRegistry_PersistsAndHydratesSessions(t *testing.T) {
	r := NewAgentRegistry()
	store := newMockSessionStore()
	r.SetSessionStore(store)
	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Test Agent"})

	session, err := r.CreateSession("agent-1", "user-123", SessionContext{})
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	if _, ok := store.sessions[session.ID]; !ok {
		t.Fatalf("expected session to be persisted to session store")
	}

	delete(r.sessions, session.ID)

	hydrated, ok := r.GetSession(session.ID)
	if !ok || hydrated == nil {
		t.Fatalf("expected session to be hydrated from persistent store")
	}

	hydrated.Status = "completed"
	if err := r.UpdateSession(hydrated); err != nil {
		t.Fatalf("update session failed: %v", err)
	}

	if store.sessions[session.ID].Status != "completed" {
		t.Fatalf("expected persisted session status to be updated")
	}
}

func TestAgentRegistry_CreateSession_ReturnsErrorOnPersistFailure(t *testing.T) {
	r := NewAgentRegistry()
	r.SetSessionStore(&failingSessionStore{saveErr: errors.New("snowflake down")})
	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Test Agent"})

	_, err := r.CreateSession("agent-1", "user-123", SessionContext{})
	if err == nil {
		t.Fatal("expected create session to fail when persistence fails")
	}
	if len(r.sessions) != 0 {
		t.Fatal("expected failed persisted session not to remain in registry")
	}
}

func TestAgentRegistry_UpdateSession_ReturnsErrorOnPersistFailure(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1", Name: "Test Agent"})

	store := newMockSessionStore()
	r.SetSessionStore(store)

	session, err := r.CreateSession("agent-1", "user-123", SessionContext{})
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	r.SetSessionStore(&failingSessionStore{saveErr: errors.New("snowflake down")})

	session.Status = "completed"
	if err := r.UpdateSession(session); err == nil {
		t.Fatal("expected update session to fail when persistence fails")
	}
}

func TestMessage(t *testing.T) {
	msg := Message{
		Role:    "assistant",
		Content: "Hello!",
		Name:    "Claude",
		Metadata: map[string]interface{}{
			"model": "claude-3",
		},
	}

	if msg.Role != "assistant" {
		t.Errorf("expected role 'assistant', got '%s'", msg.Role)
	}
	if msg.Content != "Hello!" {
		t.Errorf("expected content 'Hello!', got '%s'", msg.Content)
	}
	if msg.Name != "Claude" {
		t.Errorf("expected name 'Claude', got '%s'", msg.Name)
	}
	if msg.Metadata["model"] != "claude-3" {
		t.Error("expected metadata model 'claude-3'")
	}
}

func TestToolCall(t *testing.T) {
	tc := ToolCall{
		ID:        "call-123",
		Name:      "search",
		Arguments: []byte(`{"query":"test"}`),
	}

	if tc.ID != "call-123" {
		t.Errorf("expected ID 'call-123', got '%s'", tc.ID)
	}
	if tc.Name != "search" {
		t.Errorf("expected name 'search', got '%s'", tc.Name)
	}
	if string(tc.Arguments) != `{"query":"test"}` {
		t.Error("expected arguments to match")
	}
}

func TestToolValidateExecutionRequiresApproval(t *testing.T) {
	tool := &Tool{
		Name:             "dangerous",
		RequiresApproval: true,
		Handler: func(context.Context, json.RawMessage) (string, error) {
			return "ok", nil
		},
	}

	if err := tool.ValidateExecution(false); err == nil {
		t.Fatal("expected approval_required error when tool is not approved")
	}

	if err := tool.ValidateExecution(true); err != nil {
		t.Fatalf("expected approved tool to validate, got %v", err)
	}
}

func TestUsage(t *testing.T) {
	usage := Usage{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	if usage.TotalTokens != 150 {
		t.Errorf("expected total tokens 150, got %d", usage.TotalTokens)
	}
	if usage.PromptTokens != 100 {
		t.Errorf("expected prompt tokens 100, got %d", usage.PromptTokens)
	}
	if usage.CompletionTokens != 50 {
		t.Errorf("expected completion tokens 50, got %d", usage.CompletionTokens)
	}
}

func TestStreamEvent(t *testing.T) {
	event := StreamEvent{
		Type:    "delta",
		Content: "Hello",
		Done:    false,
		Error:   nil,
	}

	if event.Type != "delta" {
		t.Errorf("expected type 'delta', got '%s'", event.Type)
	}
	if event.Content != "Hello" {
		t.Errorf("expected content 'Hello', got '%s'", event.Content)
	}
	if event.Done {
		t.Error("expected Done to be false")
	}
	if event.Error != nil {
		t.Error("expected Error to be nil")
	}
}

func TestTool(t *testing.T) {
	handler := func(ctx context.Context, args json.RawMessage) (string, error) {
		return "result", nil
	}

	tool := Tool{
		Name:             "test_tool",
		Description:      "A test tool",
		Parameters:       map[string]interface{}{"type": "object"},
		Handler:          handler,
		RequiresApproval: true,
	}

	if tool.Name != "test_tool" {
		t.Errorf("expected name 'test_tool', got '%s'", tool.Name)
	}
	if tool.Description != "A test tool" {
		t.Errorf("expected description 'A test tool', got '%s'", tool.Description)
	}
	if tool.Parameters["type"] != "object" {
		t.Error("expected parameters type to be 'object'")
	}
	if !tool.RequiresApproval {
		t.Error("expected RequiresApproval to be true")
	}

	result, err := tool.Handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("expected result 'result', got '%s'", result)
	}
}

func TestSessionContext(t *testing.T) {
	ctx := SessionContext{
		FindingIDs: []string{"f1", "f2"},
		AssetIDs:   []string{"a1"},
		Investigation: &Investigation{
			ID:       "inv-1",
			Title:    "Test Investigation",
			Severity: "high",
		},
		Metadata: map[string]interface{}{
			"source": "alert",
		},
	}

	if len(ctx.FindingIDs) != 2 {
		t.Errorf("expected 2 finding IDs, got %d", len(ctx.FindingIDs))
	}
	if len(ctx.AssetIDs) != 1 {
		t.Errorf("expected 1 asset ID, got %d", len(ctx.AssetIDs))
	}
	if ctx.Investigation.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", ctx.Investigation.Severity)
	}
	if ctx.Metadata["source"] != "alert" {
		t.Error("expected metadata source to be 'alert'")
	}
}

func TestInvestigation(t *testing.T) {
	now := time.Now()
	inv := Investigation{
		ID:          "inv-123",
		Title:       "Security Incident",
		Description: "Suspicious activity detected",
		Severity:    "critical",
		Status:      "open",
		Findings:    []string{"f1", "f2"},
		Timeline: []Event{
			{
				Timestamp:   now,
				Type:        "detection",
				Description: "Initial alert",
			},
		},
		CreatedAt: now,
	}

	if inv.ID != "inv-123" {
		t.Errorf("expected ID 'inv-123', got '%s'", inv.ID)
	}
	if inv.Title != "Security Incident" {
		t.Errorf("expected title 'Security Incident', got '%s'", inv.Title)
	}
	if inv.Description != "Suspicious activity detected" {
		t.Errorf("expected description 'Suspicious activity detected', got '%s'", inv.Description)
	}
	if inv.Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", inv.Severity)
	}
	if inv.Status != "open" {
		t.Errorf("expected status 'open', got '%s'", inv.Status)
	}
	if len(inv.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(inv.Findings))
	}
	if len(inv.Timeline) != 1 {
		t.Errorf("expected 1 timeline event, got %d", len(inv.Timeline))
	}
	if inv.CreatedAt != now {
		t.Error("expected CreatedAt to match")
	}
}

func TestEvent(t *testing.T) {
	now := time.Now()
	event := Event{
		Timestamp:   now,
		Type:        "action",
		Description: "Blocked IP address",
		Data: map[string]interface{}{
			"ip": "192.168.1.1",
		},
	}

	if event.Timestamp != now {
		t.Error("expected Timestamp to match")
	}
	if event.Type != "action" {
		t.Errorf("expected type 'action', got '%s'", event.Type)
	}
	if event.Description != "Blocked IP address" {
		t.Errorf("expected description 'Blocked IP address', got '%s'", event.Description)
	}
	if event.Data["ip"] != "192.168.1.1" {
		t.Errorf("expected ip '192.168.1.1', got '%v'", event.Data["ip"])
	}
}

func TestMemoryEntry(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	entry := MemoryEntry{
		ID:        "entry-1",
		Content:   "Important fact",
		Type:      "fact",
		Relevance: 0.95,
		CreatedAt: now,
		ExpiresAt: expires,
	}

	if entry.ID != "entry-1" {
		t.Errorf("expected ID 'entry-1', got '%s'", entry.ID)
	}
	if entry.Content != "Important fact" {
		t.Errorf("expected content 'Important fact', got '%s'", entry.Content)
	}
	if entry.Type != "fact" {
		t.Errorf("expected type 'fact', got '%s'", entry.Type)
	}
	if entry.Relevance != 0.95 {
		t.Errorf("expected relevance 0.95, got %f", entry.Relevance)
	}
	if entry.CreatedAt != now {
		t.Error("expected CreatedAt to match")
	}
	if entry.ExpiresAt != expires {
		t.Error("expected ExpiresAt to match")
	}
}

// Concurrent access test
func TestAgentRegistry_ConcurrentAccess(t *testing.T) {
	r := NewAgentRegistry()
	r.RegisterAgent(&Agent{ID: "agent-1"})

	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			r.GetAgent("agent-1")
			r.ListAgents()
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 5; i++ {
		go func(id int) {
			r.CreateSession("agent-1", "user", SessionContext{})
			done <- true
		}(i)
	}

	for i := 0; i < 15; i++ {
		<-done
	}
}

func TestMemory_ConcurrentAccess(t *testing.T) {
	m := NewMemory(100)
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			m.Add("content", "fact", 0.5, time.Hour)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			m.Search("", 5)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}
