package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListAgentSDKTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent-sdk/tools" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "cerebro_report", "tool_name": "cerebro.intelligence_report", "description": "run report"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	tools, err := c.ListAgentSDKTools(context.Background())
	if err != nil {
		t.Fatalf("list agent sdk tools: %v", err)
	}
	if len(tools) != 1 || tools[0].ID != "cerebro_report" {
		t.Fatalf("unexpected tools: %#v", tools)
	}
}

func TestCallAgentSDKTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent-sdk/tools/cerebro_context:call" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if payload["entity"] != "service:payments" {
			t.Fatalf("unexpected request payload: %#v", payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tool_id":           "cerebro_context",
			"execution_kind":    "direct_tool",
			"supports_async":    false,
			"supports_progress": false,
			"result": map[string]any{
				"entity_id": "service:payments",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.CallAgentSDKTool(context.Background(), "cerebro_context", map[string]any{"entity": "service:payments"})
	if err != nil {
		t.Fatalf("call agent sdk tool: %v", err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["entity_id"] != "service:payments" {
		t.Fatalf("unexpected result: %#v", resp.Result)
	}
}

func TestExecuteAgentSDKReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent-sdk/report" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Location", "/api/v1/platform/intelligence/reports/quality/runs/run-1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "run-1",
			"report_id":  "quality",
			"status":     "queued",
			"status_url": "/api/v1/platform/intelligence/reports/quality/runs/run-1",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	run, err := c.ExecuteAgentSDKReport(context.Background(), AgentSDKReportRequest{
		ReportID:      "quality",
		ExecutionMode: "async",
	})
	if err != nil {
		t.Fatalf("execute agent sdk report: %v", err)
	}
	if run.ID != "run-1" || run.ReportID != "quality" || run.Status != "queued" {
		t.Fatalf("unexpected report run: %#v", run)
	}
}

func TestMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Mcp-Session-Id"); got != "session-1" {
			t.Fatalf("unexpected session header: %q", got)
		}
		w.Header().Set("Mcp-Session-Id", "session-1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      "req-1",
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	req := AgentSDKMCPRequest{JSONRPC: "2.0", ID: "req-1", Method: "initialize"}
	resp, sessionID, err := c.MCP(context.Background(), "session-1", req)
	if err != nil {
		t.Fatalf("mcp call: %v", err)
	}
	if sessionID != "session-1" {
		t.Fatalf("unexpected session id: %s", sessionID)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("unexpected mcp result: %#v", resp.Result)
	}
}

func TestOpenMCPStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			t.Fatalf("unexpected accept header: %q", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Mcp-Session-Id", "session-stream")
		_, _ = fmt.Fprint(w, "event: ready\ndata: {\"status\":\"ready\"}\n\n")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	body, sessionID, err := c.OpenMCPStream(context.Background(), "")
	if err != nil {
		t.Fatalf("open mcp stream: %v", err)
	}
	defer func() { _ = body.Close() }()
	if sessionID != "session-stream" {
		t.Fatalf("unexpected session id: %s", sessionID)
	}
	line, err := bufio.NewReader(body).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read stream: %v", err)
	}
	if !strings.HasPrefix(line, "event: ready") {
		t.Fatalf("unexpected stream line: %q", line)
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: baseURL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}
