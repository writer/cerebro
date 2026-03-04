package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Agent represents an AI-powered security investigation agent
type Agent struct {
	ID          string
	Name        string
	Description string
	Provider    LLMProvider
	Tools       []Tool
	Memory      *Memory
}

// LLMProvider interface for different AI backends
type LLMProvider interface {
	Complete(ctx context.Context, messages []Message, tools []Tool) (*Response, error)
	Stream(ctx context.Context, messages []Message, tools []Tool) (<-chan StreamEvent, error)
}

type Message struct {
	Role      string                 `json:"role"` // system, user, assistant, tool
	Content   string                 `json:"content"`
	Name      string                 `json:"name,omitempty"`
	ToolCalls []ToolCall             `json:"tool_calls,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type Response struct {
	Message      Message
	Usage        Usage
	FinishReason string
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type StreamEvent struct {
	Type    string
	Content string
	Done    bool
	Error   error
}

// Tool represents a capability the agent can use
type Tool struct {
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Parameters       map[string]interface{} `json:"parameters"`
	Handler          ToolHandler            `json:"-"`
	RequiresApproval bool                   `json:"requires_approval"`
}

func (t *Tool) ValidateExecution(approved bool) error {
	if t == nil {
		return fmt.Errorf("tool not found")
	}
	if t.RequiresApproval && !approved {
		return &ToolError{
			Message: fmt.Sprintf("tool %s requires approval before execution", t.Name),
			Code:    "approval_required",
		}
	}
	if t.Handler == nil {
		return fmt.Errorf("tool %s is not executable", t.Name)
	}
	return nil
}

type ToolHandler func(ctx context.Context, args json.RawMessage) (string, error)

// Session represents an investigation session
type Session struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	UserID    string         `json:"user_id"`
	Status    string         `json:"status"` // active, completed, pending_approval
	Messages  []Message      `json:"messages"`
	Context   SessionContext `json:"context"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type SessionContext struct {
	FindingIDs    []string               `json:"finding_ids,omitempty"`
	AssetIDs      []string               `json:"asset_ids,omitempty"`
	Investigation *Investigation         `json:"investigation,omitempty"`
	Playbook      *Playbook              `json:"playbook,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type Investigation struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Findings    []string  `json:"findings"`
	Timeline    []Event   `json:"timeline"`
	CreatedAt   time.Time `json:"created_at"`
}

type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// Memory provides context storage for agents
type Memory struct {
	entries []MemoryEntry
	maxSize int
	mu      sync.RWMutex
}

type MemoryEntry struct {
	ID        string
	Content   string
	Type      string // fact, observation, decision
	Relevance float64
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewMemory(maxSize int) *Memory {
	return &Memory{
		entries: make([]MemoryEntry, 0),
		maxSize: maxSize,
	}
}

func (m *Memory) Add(content, entryType string, relevance float64, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := MemoryEntry{
		ID:        uuid.New().String(),
		Content:   content,
		Type:      entryType,
		Relevance: relevance,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	m.entries = append(m.entries, entry)

	// Prune if over capacity
	if len(m.entries) > m.maxSize {
		m.entries = m.entries[len(m.entries)-m.maxSize:]
	}
}

func (m *Memory) Search(query string, limit int) []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	if limit <= 0 {
		limit = 10
	}

	query = strings.TrimSpace(strings.ToLower(query))
	tokens := strings.Fields(query)

	type scoredEntry struct {
		entry MemoryEntry
		score float64
	}

	scored := make([]scoredEntry, 0, len(m.entries))

	for _, e := range m.entries {
		if !e.ExpiresAt.After(now) {
			continue
		}

		score := e.Relevance
		ageHours := now.Sub(e.CreatedAt).Hours()
		if ageHours < 0 {
			ageHours = 0
		}
		score += 1.0 / (1.0 + ageHours/24.0)

		if query != "" {
			content := strings.ToLower(e.Content)
			entryType := strings.ToLower(e.Type)

			if strings.Contains(content, query) {
				score += 2.0
			}
			for _, token := range tokens {
				if strings.Contains(content, token) {
					score += 1.0
				}
				if entryType == token {
					score += 0.5
				}
			}
		}

		scored = append(scored, scoredEntry{entry: e, score: score})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].entry.CreatedAt.After(scored[j].entry.CreatedAt)
		}
		return scored[i].score > scored[j].score
	})

	if len(scored) > limit {
		scored = scored[:limit]
	}

	results := make([]MemoryEntry, 0, len(scored))
	for _, item := range scored {
		results = append(results, item.entry)
	}

	return results
}

// AgentRegistry manages available agents
type AgentRegistry struct {
	agents       map[string]*Agent
	sessions     map[string]*Session
	sessionStore SessionStore
	mu           sync.RWMutex
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents:   make(map[string]*Agent),
		sessions: make(map[string]*Session),
	}
}

func (r *AgentRegistry) SetSessionStore(store SessionStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessionStore = store
}

func (r *AgentRegistry) RegisterAgent(agent *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[agent.ID] = agent
}

func (r *AgentRegistry) GetAgent(id string) (*Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	return a, ok
}

func (r *AgentRegistry) ListAgents() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agents := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		agents = append(agents, a)
	}
	return agents
}

func (r *AgentRegistry) CreateSession(agentID, userID string, ctx SessionContext) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.agents[agentID]; !ok {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	session := &Session{
		ID:        uuid.New().String(),
		AgentID:   agentID,
		UserID:    userID,
		Status:    "active",
		Messages:  make([]Message, 0),
		Context:   ctx,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	r.sessions[session.ID] = session
	if r.sessionStore != nil {
		if err := r.sessionStore.Save(context.Background(), session); err != nil {
			delete(r.sessions, session.ID)
			return nil, fmt.Errorf("persist session: %w", err)
		}
	}
	return session, nil
}

func (r *AgentRegistry) GetSession(id string) (*Session, bool) {
	r.mu.RLock()
	s, ok := r.sessions[id]
	store := r.sessionStore
	r.mu.RUnlock()
	if ok {
		return s, true
	}

	if store != nil {
		persisted, err := store.Get(context.Background(), id)
		if err == nil && persisted != nil {
			r.mu.Lock()
			r.sessions[id] = persisted
			r.mu.Unlock()
			return persisted, true
		}
	}

	return nil, false
}

func (r *AgentRegistry) UpdateSession(session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	session.UpdatedAt = time.Now()
	r.sessions[session.ID] = session
	if r.sessionStore != nil {
		if err := r.sessionStore.Save(context.Background(), session); err != nil {
			return fmt.Errorf("persist session: %w", err)
		}
	}
	return nil
}

// GetSystemPrompt generates the system prompt for the session
func (s *Session) GetSystemPrompt() string {
	basePrompt := `You are a specialized security investigation agent. Your goal is to analyze security findings, 
assess their impact, and recommend or take remediation actions.
Use the available tools to gather information. Be thorough and evidence-based.`

	if s.Context.Playbook != nil {
		playbook := s.Context.Playbook
		sop := fmt.Sprintf("\n\nFOLLOW THIS STANDARD OPERATING PROCEDURE (SOP): %s\n%s\n\nSteps:",
			playbook.Name, playbook.Description)

		for _, step := range playbook.Steps {
			sop += fmt.Sprintf("\n%d. %s: %s (Action: %s)",
				step.Order, step.Name, step.Description, step.Action)
		}

		sop += "\n\nYou MUST follow these steps in order. Do not skip steps unless they are clearly irrelevant based on evidence."
		return basePrompt + sop
	}

	return basePrompt
}
