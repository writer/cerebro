package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"time"

	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/attackpath"
	"github.com/writerinternal/cerebro/internal/auth"
	"github.com/writerinternal/cerebro/internal/cache"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/graph"
	"github.com/writerinternal/cerebro/internal/health"
	"github.com/writerinternal/cerebro/internal/identity"
	"github.com/writerinternal/cerebro/internal/lineage"
	"github.com/writerinternal/cerebro/internal/notifications"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/remediation"
	"github.com/writerinternal/cerebro/internal/runtime"
	"github.com/writerinternal/cerebro/internal/scanner"
	"github.com/writerinternal/cerebro/internal/scheduler"
	"github.com/writerinternal/cerebro/internal/threatintel"
	"github.com/writerinternal/cerebro/internal/ticketing"
	"github.com/writerinternal/cerebro/internal/webhooks"
)

// newTestApp creates a minimal in-memory App suitable for API integration tests.
func newTestApp(t *testing.T) *app.App {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	pe := policy.NewEngine()
	fs := findings.NewStore()
	sc := scanner.NewScanner(pe, scanner.ScanConfig{Workers: 2}, logger)

	return &app.App{
		Config: &app.Config{
			LogLevel: "error",
			Port:     0,
		},
		Logger:         logger,
		Policy:         pe,
		Findings:       fs,
		Scanner:        sc,
		Cache:          cache.NewPolicyCache(1000, 5*time.Minute),
		Agents:         agents.NewAgentRegistry(),
		RBAC:           auth.NewRBAC(),
		Webhooks:       webhooks.NewServiceForTesting(),
		Notifications:  notifications.NewManager(),
		Scheduler:      scheduler.NewScheduler(logger),
		Ticketing:      ticketing.NewService(),
		Identity:       identity.NewService(),
		AttackPath:     attackpath.NewGraph(),
		Providers:      providers.NewRegistry(),
		Health:         health.NewRegistry(),
		Lineage:        lineage.NewLineageMapper(),
		Remediation:    remediation.NewEngine(logger),
		RuntimeDetect:  runtime.NewDetectionEngine(),
		RuntimeRespond: runtime.NewResponseEngine(),
		SecurityGraph:  graph.New(),
		ScanWatermarks: scanner.NewWatermarkStore(nil),
		ThreatIntel:    threatintel.NewThreatIntelService(),
	}
}

// newTestServer creates a Server backed by the in-memory test app.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(newTestApp(t))
}

// do is a helper that sends a request to the test server and returns the response.
func do(t *testing.T, s *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// decodeJSON decodes the response body into a generic map.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode json: %v (body=%s)", err, w.Body.String())
	}
	return out
}

type scriptedAgentProvider struct {
	responses []*agents.Response
	index     int
}

func (p *scriptedAgentProvider) Complete(_ context.Context, _ []agents.Message, _ []agents.Tool) (*agents.Response, error) {
	if p.index >= len(p.responses) {
		return &agents.Response{Message: agents.Message{Role: "assistant", Content: "done"}}, nil
	}
	resp := p.responses[p.index]
	p.index++
	return resp, nil
}

func (p *scriptedAgentProvider) Stream(context.Context, []agents.Message, []agents.Tool) (<-chan agents.StreamEvent, error) {
	return nil, nil
}

// --- Health / Readiness ---

func TestHealth(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "healthy" {
		t.Fatalf("expected healthy, got %v", body["status"])
	}
}

func TestReady(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/ready", nil)
	// Ready may return 503 when Snowflake is nil; that's expected in unit tests
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 200 or 503, got %d", w.Code)
	}
}

// --- Policies CRUD ---

func TestListPolicies_Empty(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/policies/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 0 {
		t.Fatalf("expected 0, got %v", body["count"])
	}
}

func TestCreateAndGetPolicy(t *testing.T) {
	s := newTestServer(t)

	p := policy.Policy{
		ID:         "test-001",
		Name:       "No public buckets",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true"},
		Severity:   "high",
	}

	w := do(t, s, "POST", "/api/v1/policies/", p)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// GET by ID
	w = do(t, s, "GET", "/api/v1/policies/test-001", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["id"] != "test-001" {
		t.Fatalf("expected id test-001, got %v", body["id"])
	}

	// List should show 1
	w = do(t, s, "GET", "/api/v1/policies/", nil)
	body = decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1, got %v", body["count"])
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/policies/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Findings ---

func TestListFindings_Empty(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 0 {
		t.Fatalf("expected 0, got %v", body["count"])
	}
}

func TestFindingsStats(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGetFinding_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCreatePolicyThenScanFindings(t *testing.T) {
	s := newTestServer(t)

	// Create a policy
	p := policy.Policy{
		ID:         "pub-check",
		Name:       "Public check",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true"},
		Severity:   "high",
	}
	w := do(t, s, "POST", "/api/v1/policies/", p)
	if w.Code != http.StatusCreated {
		t.Fatalf("create policy: %d %s", w.Code, w.Body.String())
	}

	// Upsert a finding directly so we can test retrieval
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:         "f-1",
		PolicyID:   "pub-check",
		PolicyName: "Public check",
		ResourceID: "arn:aws:s3:::my-bucket",
		Resource:   map[string]interface{}{"type": "aws::s3::bucket"},
		Severity:   "high",
	})

	// List should have 1
	w = do(t, s, "GET", "/api/v1/findings/", nil)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1 finding, got %v", body["count"])
	}

	// Get by ID
	w = do(t, s, "GET", "/api/v1/findings/f-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Resolve
	w = do(t, s, "POST", "/api/v1/findings/f-1/resolve", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Findings filter ---

func TestListFindings_SeverityFilter(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-high", PolicyID: "p1", Severity: "high",
	})
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-low", PolicyID: "p2", Severity: "low",
	})

	w := do(t, s, "GET", "/api/v1/findings/?severity=high", nil)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1 high finding, got %v", body["count"])
	}
}

// --- Webhooks CRUD ---

func TestWebhookCRUD(t *testing.T) {
	s := newTestServer(t)

	// Create
	w := do(t, s, "POST", "/api/v1/webhooks/", map[string]interface{}{
		"url":    "https://example.com/hook",
		"events": []string{"finding.created"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeJSON(t, w)
	id := created["id"].(string)

	// List
	w = do(t, s, "GET", "/api/v1/webhooks/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Get
	w = do(t, s, "GET", "/api/v1/webhooks/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Delete
	w = do(t, s, "DELETE", "/api/v1/webhooks/"+id, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Tickets ---

func TestTicketList(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/tickets/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTicketCreate_NoProvider(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "POST", "/api/v1/tickets/", map[string]interface{}{
		"title":    "Fix bucket",
		"severity": "high",
	})
	// Expect 503 because no ticketing provider is configured
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without provider, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Remediation ---

func TestRemediationRuleCRUD(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "GET", "/api/v1/remediation/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Scheduler ---

func TestSchedulerStatus(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scheduler/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSchedulerListJobs(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scheduler/jobs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Runtime Detection ---

func TestListDetectionRules(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/detections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListRuntimeFindings(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListResponsePolicies(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/responses", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Providers ---

func TestListProviders(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/providers/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- RBAC ---

func TestListRoles(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/rbac/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListPermissions(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/rbac/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Threat Intel ---

func TestListThreatFeeds(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/threatintel/feeds", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestThreatIntelStats(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/threatintel/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Identity ---

func TestListReviews(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/identity/reviews", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Reports ---

func TestExecutiveSummary(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/reports/executive-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRiskSummary(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/reports/risk-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Notifications ---

func TestListNotifiers(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/notifications/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Scan watermarks ---

func TestScanWatermarks(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scan/watermarks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Auth middleware integration ---

func TestAuthMiddleware_BlocksUnauthenticated(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	s := NewServer(a)

	w := do(t, s, "GET", "/api/v1/policies/", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_AllowsAuthenticated(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	// Disable RBAC so we only test auth layer
	a.RBAC = nil
	s := NewServer(a)

	req := httptest.NewRequest("GET", "/api/v1/policies/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_HealthBypassesAuth(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	s := NewServer(a)

	w := do(t, s, "GET", "/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /health even without auth, got %d", w.Code)
	}
}

// --- 404 for unknown routes ---

func TestUnknownRoute(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/nonexistent", nil)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 404/405, got %d", w.Code)
	}
}

// --- MaxBodySize ---

func TestMaxBodySize_RejectsLargeBody(t *testing.T) {
	s := newTestServer(t)
	largeBody := strings.Repeat("x", 11*1024*1024) // 11MB
	req := httptest.NewRequest("POST", "/api/v1/policies/", bytes.NewReader([]byte(largeBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code == http.StatusOK || w.Code == http.StatusCreated {
		t.Fatalf("expected rejection of 11MB body, got %d", w.Code)
	}
}

func TestAgentSendMessageExecutesToolCalls(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "safe_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
			{Message: agents.Message{Role: "assistant", Content: "final response"}},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-1",
		Name:     "Test Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name: "safe_tool",
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-1", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "investigate"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Content != "final response" {
		t.Fatalf("expected final response, got %q", msg.Content)
	}
	if !called {
		t.Fatal("expected tool handler to be called")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if len(updated.Messages) < 4 {
		t.Fatalf("expected at least 4 messages in session, got %d", len(updated.Messages))
	}
}

func TestAgentSendMessageBlocksRequiresApprovalTool(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-2",
		Name:     "Approval Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-2", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Metadata["status"] != "pending_approval" {
		t.Fatalf("expected pending_approval status, got %#v", msg.Metadata["status"])
	}
	if called {
		t.Fatal("expected tool handler not to be called before approval")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if updated.Status != "pending_approval" {
		t.Fatalf("expected session status pending_approval, got %s", updated.Status)
	}
}

func TestApproveSessionToolCallExecutesPendingTool(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
			{Message: agents.Message{Role: "assistant", Content: "tool approved and completed"}},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-3",
		Name:     "Approval Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-3", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/approve", map[string]bool{"approve": true})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on approval, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Content != "tool approved and completed" {
		t.Fatalf("expected final assistant message after approval, got %q", msg.Content)
	}
	if !called {
		t.Fatal("expected pending tool to be executed after approval")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if updated.Status != "active" {
		t.Fatalf("expected session status active after approval, got %s", updated.Status)
	}
	if updated.Context.Metadata != nil {
		if _, exists := updated.Context.Metadata["pending_tool_call"]; exists {
			t.Fatal("expected pending tool call metadata to be cleared")
		}
	}
}

// suppress unused import warnings
var _ = os.DevNull
