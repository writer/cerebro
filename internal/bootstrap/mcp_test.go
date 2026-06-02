package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestMCPRequiresAuth(t *testing.T) {
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "tester",
				TenantID:  "writer",
			}},
		},
	}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+mcpEndpointPath, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatalf("POST /api/v1/mcp without auth error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/mcp without auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	initResp, sessionID := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "unit-test", "version": "0"},
		},
	})
	if initResp["error"] != nil {
		t.Fatalf("initialize error = %#v", initResp["error"])
	}
	result := initResp["result"].(map[string]any)
	serverInfo := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "cerebro" {
		t.Fatalf("serverInfo.name = %#v, want cerebro", serverInfo["name"])
	}
	if sessionID == "" {
		t.Fatal("Mcp-Session-Id header empty")
	}

	toolsResp, _ := postMCP(t, server, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if toolsResp["error"] != nil {
		t.Fatalf("tools/list error = %#v", toolsResp["error"])
	}
	tools := toolsResp["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, item := range tools {
		names[item.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"cerebro.health", "cerebro.version", "cerebro.source_runtimes.list", "cerebro.findings.list", "cerebro.graph.neighborhood"} {
		if !names[want] {
			t.Fatalf("tools/list missing %s in %#v", want, names)
		}
	}
}

func TestMCPSourceRuntimesListRedactsConfig(t *testing.T) {
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta": {
			Id:       "writer-okta",
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"token":  "secret-value",
			},
		},
	}}
	server := newMCPTestServer(t, store)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.source_runtimes.list",
			"arguments": map[string]any{
				"tenant_id": "writer",
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	body, _ := json.Marshal(response)
	if strings.Contains(string(body), "secret-value") {
		t.Fatalf("MCP response leaked runtime secret: %s", body)
	}
	result := response["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	runtimes := structured["runtimes"].([]any)
	if len(runtimes) != 1 {
		t.Fatalf("len(runtimes) = %d, want 1", len(runtimes))
	}
	config := runtimes[0].(map[string]any)["config"].(map[string]any)
	if config["token"] != "[redacted]" {
		t.Fatalf("redacted token = %#v, want [redacted]", config["token"])
	}
}

func TestMCPFindingsListUsesRuntimeScope(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta": {Id: "writer-okta", SourceId: "okta", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				RuntimeID:      "writer-okta",
				TenantID:       "writer",
				RuleID:         "rule-1",
				Title:          "Finding One",
				Severity:       "high",
				Status:         "open",
				LastObservedAt: time.Now().UTC(),
			},
		},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.findings.list",
			"arguments": map[string]any{
				"runtime_id": "writer-okta",
				"status":     "open",
				"limit":      10,
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	if store.findingListRequest.RuntimeID != "writer-okta" || store.findingListRequest.Status != "open" || store.findingListRequest.Limit != 10 {
		t.Fatalf("finding list request = %#v", store.findingListRequest)
	}
	result := response["result"].(map[string]any)
	findings := result["structuredContent"].(map[string]any)["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
}

func TestMCPGraphNeighborhood(t *testing.T) {
	store := &stubRuntimeStore{}
	graph := &stubGraphStore{neighborhood: &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:prod-db", EntityType: "asset", Label: "prod-db"},
		Neighbors: []*ports.NeighborhoodNode{
			{URN: "urn:cerebro:writer:finding:finding-1", EntityType: "finding", Label: "finding-1"},
		},
	}}
	server := newMCPTestServerWithGraph(t, store, graph)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.neighborhood",
			"arguments": map[string]any{
				"root_urn": "urn:cerebro:writer:asset:prod-db",
				"limit":    5,
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	if graph.neighborhoodRootURN != "urn:cerebro:writer:asset:prod-db" || graph.neighborhoodLimit != 5 {
		t.Fatalf("graph query = (%q, %d)", graph.neighborhoodRootURN, graph.neighborhoodLimit)
	}
}

func TestMCPRouteUsesReadScope(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath, nil)
	if got := scopeForHTTPRequest(req); got != scopeCosmoSecurityRead {
		t.Fatalf("scopeForHTTPRequest(POST %s) = %q, want %q", mcpEndpointPath, got, scopeCosmoSecurityRead)
	}
}

func newMCPTestServer(t *testing.T, store *stubRuntimeStore) *httptest.Server {
	t.Helper()
	return newMCPTestServerWithGraph(t, store, nil)
}

func newMCPTestServerWithGraph(t *testing.T, store *stubRuntimeStore, graph *stubGraphStore) *httptest.Server {
	t.Helper()
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "tester",
				TenantID:  "writer",
			}},
		},
	}, Dependencies{StateStore: store, GraphStore: graph}, nil)
	return httptest.NewServer(app.Handler())
}

func postMCP(t *testing.T, server *httptest.Server, sessionID string, payload map[string]any) (map[string]any, string) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal MCP request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer test-key")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/mcp error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll MCP response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/mcp status = %d body = %s", resp.StatusCode, raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal MCP response %s: %v", raw, err)
	}
	return decoded, resp.Header.Get("Mcp-Session-Id")
}
