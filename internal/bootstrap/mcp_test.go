package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
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
	if result["protocolVersion"] != mcpProtocolVersion {
		t.Fatalf("protocolVersion = %#v, want %q", result["protocolVersion"], mcpProtocolVersion)
	}
	capabilities := result["capabilities"].(map[string]any)
	for _, capability := range []string{"tools", "resources", "prompts"} {
		if capabilities[capability] == nil {
			t.Fatalf("initialize missing %s capability in %#v", capability, capabilities)
		}
	}
	if _, ok := capabilities["experimental"]; ok {
		t.Fatalf("initialize experimental capabilities = %#v, want omitted for SDK compatibility", capabilities["experimental"])
	}
	if sessionID != "" {
		t.Fatalf("Mcp-Session-Id header = %q, want empty for stateless MCP", sessionID)
	}

	toolsResp, _ := postMCP(t, server, "", map[string]any{
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
		tool := item.(map[string]any)
		name := tool["name"].(string)
		names[name] = true
		if tool["outputSchema"] == nil {
			t.Fatalf("tool missing outputSchema: %#v", item)
		}
		if name == "cerebro.connector_definitions.validate" {
			outputSchema := tool["outputSchema"].(map[string]any)
			properties := outputSchema["properties"].(map[string]any)
			if properties["support"] == nil {
				t.Fatalf("%s outputSchema missing support report: %#v", name, outputSchema)
			}
		}
		annotations := tool["annotations"].(map[string]any)
		if annotations["readOnlyHint"] != true {
			t.Fatalf("tool missing readOnlyHint annotation: %#v", item)
		}
		if strings.HasSuffix(name, ".propose") {
			inputSchema := tool["inputSchema"].(map[string]any)
			dryRun := inputSchema["properties"].(map[string]any)["dry_run"].(map[string]any)
			if dryRun["const"] != true {
				t.Fatalf("%s dry_run schema = %#v, want const true", name, dryRun)
			}
			outputSchema := tool["outputSchema"].(map[string]any)
			if outputSchema["additionalProperties"] != false {
				t.Fatalf("%s outputSchema.additionalProperties = %#v, want false", name, outputSchema["additionalProperties"])
			}
		}
	}
	for _, want := range []string{
		"cerebro.health",
		"cerebro.version",
		"cerebro.source_runtimes.list",
		"cerebro.connector_definitions.list",
		"cerebro.connector_definitions.validate",
		"cerebro.findings.list",
		"cerebro.findings.get",
		"cerebro.findings.search",
		"cerebro.runtimes.status",
		"cerebro.evidence.list",
		"cerebro.evidence.get",
		"cerebro.assets.search",
		"cerebro.assets.get",
		"cerebro.risk.summary",
		"cerebro.risk.actions.list",
		"cerebro.risk.actions.explain",
		"cerebro.graph.neighborhood",
		"cerebro.graph.impact",
		"cerebro.graph.paths",
		"cerebro.graph.facts.list",
		"cerebro.graph.facts.explain",
		"cerebro.graph.facts.trace",
		"cerebro.agent.preflight",
		"cerebro.graph.reason",
		"cerebro.investigation.context",
		"cerebro.findings.action.propose",
		"cerebro.source_runtimes.refresh.propose",
	} {
		if !names[want] {
			t.Fatalf("tools/list missing %s in %#v", want, names)
		}
	}
}

func TestMCPToolsDeclareDomainSurfaceParity(t *testing.T) {
	corpus := mcpDomainSurfaceCorpus(t)
	tools := map[string]bool{}
	for _, tool := range mcpTools() {
		tools[tool.Name] = true
		contract, ok := mcpToolDomainSurfaceContracts[tool.Name]
		if !ok {
			t.Fatalf("%s has no MCP domain surface contract", tool.Name)
		}
		if len(contract.Markers) == 0 {
			t.Fatalf("%s domain surface contract has no markers", tool.Name)
		}
		for _, marker := range contract.Markers {
			if !strings.Contains(corpus, marker) {
				t.Fatalf("%s domain surface marker %q not found in API/domain corpus", tool.Name, marker)
			}
		}
	}
	for name := range mcpToolDomainSurfaceContracts {
		if !tools[name] {
			t.Fatalf("MCP domain surface contract covers missing tool %s", name)
		}
	}
}

type mcpToolDomainSurfaceContract struct {
	Markers []string
}

var mcpToolDomainSurfaceContracts = map[string]mcpToolDomainSurfaceContract{
	"cerebro.health":                          {Markers: []string{"GET /health"}},
	"cerebro.version":                         {Markers: []string{"GetVersion"}},
	"cerebro.source_runtimes.list":            {Markers: []string{"GET /source-runtimes"}},
	"cerebro.connector_definitions.list":      {Markers: []string{"GET /connector-definitions"}},
	"cerebro.connector_definitions.validate":  {Markers: []string{"POST /connector-definitions/validate"}},
	"cerebro.findings.list":                   {Markers: []string{"GET /source-runtimes/{runtimeID}/findings"}},
	"cerebro.findings.get":                    {Markers: []string{"GET /findings/{findingID}"}},
	"cerebro.findings.search":                 {Markers: []string{"GET /source-runtimes/{runtimeID}/findings", "GET /grc/findings"}},
	"cerebro.runtimes.status":                 {Markers: []string{"GET /source-runtimes/{runtimeID}", "GET /source-runtimes/{runtimeID}/findings"}},
	"cerebro.evidence.list":                   {Markers: []string{"GET /source-runtimes/{runtimeID}/finding-evidence"}},
	"cerebro.evidence.get":                    {Markers: []string{"GET /finding-evidence/{evidenceID}"}},
	"cerebro.assets.search":                   {Markers: []string{"GET /grc/inventory/assets"}},
	"cerebro.assets.get":                      {Markers: []string{"GET /grc/inventory/assets/detail"}},
	"cerebro.risk.summary":                    {Markers: []string{"GET /grc/dashboard", "GET /source-runtimes/{runtimeID}/findings"}},
	"cerebro.risk.actions.list":               {Markers: []string{"risk-action-plan", "internal/riskplan"}},
	"cerebro.risk.actions.explain":            {Markers: []string{"risk-action-plan", "internal/riskplan"}},
	"cerebro.graph.neighborhood":              {Markers: []string{"GET /platform/graph/neighborhood"}},
	"cerebro.graph.impact":                    {Markers: []string{"GET /platform/graph/impact"}},
	"cerebro.graph.paths":                     {Markers: []string{"GET /platform/graph/attack-paths"}},
	"cerebro.graph.facts.list":                {Markers: []string{"GET /source-runtimes/{runtimeID}/claims"}},
	"cerebro.graph.facts.explain":             {Markers: []string{"GET /source-runtimes/{runtimeID}/claims"}},
	"cerebro.graph.facts.trace":               {Markers: []string{"GET /source-runtimes/{runtimeID}/claims"}},
	"cerebro.agent.preflight":                 {Markers: []string{"POST /api/v1/agent-platform/preflight"}},
	"cerebro.graph.reason":                    {Markers: []string{"POST /api/v1/agent-platform/graph/reason"}},
	"cerebro.investigation.context":           {Markers: []string{"GET /findings/{findingID}", "GET /source-runtimes/{runtimeID}/finding-evidence", "GET /platform/graph/neighborhood"}},
	"cerebro.findings.action.propose":         {Markers: []string{"POST /findings/{findingID}/resolve", "POST /findings/{findingID}/suppress", "POST /findings/{findingID}/notes", "POST /findings/{findingID}/tickets"}},
	"cerebro.source_runtimes.refresh.propose": {Markers: []string{"POST /source-runtimes/{runtimeID}/sync"}},
}

func mcpDomainSurfaceCorpus(t *testing.T) string {
	t.Helper()
	root := bootstrapRepoRoot(t)
	var builder strings.Builder
	for _, rel := range []string{
		"internal/bootstrap/routes.go",
		"proto/cerebro/v1/bootstrap.proto",
		"api/openapi.yaml",
		"docs/domains/mcp-droid-setup.md",
		"docs/domains/findings-platform-architecture.md",
	} {
		// #nosec G304 -- rel comes from this fixed test corpus allowlist.
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		builder.Write(body)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func TestMCPConnectorDefinitionValidateReturnsSupportReport(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.connector_definitions.validate",
			"arguments": map[string]any{
				"definition": map[string]any{
					"schema_version": "cerebro.integration/v1",
					"id":             "writer-example_idp",
					"tenant_id":      "writer",
					"source_id":      "example_idp",
					"display_name":   "Example IDP",
					"auth": map[string]any{
						"model":             "bearer_token",
						"credential_fields": []any{map[string]any{"key": "token", "secret": true, "reference_only": true}},
					},
					"transport": map[string]any{
						"base_url":     "https://api.example.test",
						"verification": map[string]any{"path": "/v1/me"},
					},
					"resource_families": []any{map[string]any{
						"id":              "users",
						"path":            "/v1/users",
						"record_selector": "$.data[*]",
						"id_field":        "id",
						"event":           map[string]any{"kind": "example_idp.user", "schema_ref": "example_idp/user/v1"},
						"projection":      map[string]any{"template": "identity_user"},
						"coverage":        []any{map[string]any{"type": "entity_family", "support": "supported"}},
					}},
				},
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	structured := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	support := structured["support"].(map[string]any)
	if support["verdict"] != "supported" || support["source_id"] != "example_idp" {
		t.Fatalf("support report = %#v", support)
	}
}

func TestMCPStatelessGETIsNotSSEEndpoint(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+mcpEndpointPath, nil)
	if err != nil {
		t.Fatalf("NewRequest GET MCP: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/mcp error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/mcp status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("GET /api/v1/mcp Mcp-Session-Id = %q, want empty", got)
	}
	if contentType := resp.Header.Get("Content-Type"); strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("GET /api/v1/mcp Content-Type = %q, want non-SSE", contentType)
	}
}

func TestMCPRejectsUnsupportedProtocolVersionWithHTTPBadRequest(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest POST MCP: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2099-01-01")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/mcp error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/mcp status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestMCPSupportsDuplicateCompatibleProtocolHeaders(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest POST MCP: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Add("MCP-Protocol-Version", mcpProtocolVersion)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/mcp error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/mcp status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestMCPNotificationReturnsAcceptedEmptyBody(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal MCP notification: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest POST MCP: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/mcp notification error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/v1/mcp notification status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read notification response: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("notification response body = %q, want empty", data)
	}
}

func TestMCPTelemetryIncludesSafeToolContext(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.version",
			"arguments": map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}
	stderr := captureBootstrapStderr(t, func() {
		req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest POST MCP: %v", err)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		req.Header.Set("X-Request-ID", "req-mcp-123")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("POST /api/v1/mcp error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST /api/v1/mcp status = %d body = %s", resp.StatusCode, raw)
		}
	})

	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                           "cerebro.mcp.request",
		"http.method":                    http.MethodPost,
		"http.route":                     "POST /api/v1/mcp",
		"http.status_code":               float64(http.StatusOK),
		"mcp.method":                     "tools/call",
		"mcp.request_kind":               "request",
		"mcp.tool":                       "cerebro.version",
		"mcp.tool_known":                 true,
		"mcp.tool_family":                "version",
		"mcp.outcome":                    "ok",
		"mcp.transport":                  "stateless_http",
		"mcp.stateless":                  true,
		"mcp.accepts_json":               true,
		"mcp.accepts_sse":                false,
		"mcp.content_type":               "application/json",
		"mcp.jsonrpc_id_present":         true,
		"mcp.params_present":             true,
		"mcp.response_shape":             "tool_result",
		"mcp.tool_result_error":          false,
		"mcp.tool_result_content_count":  float64(1),
		"mcp.structured_content_present": true,
		"request_id":                     "req-mcp-123",
		"auth_mode":                      "api_key",
		"tenant_id":                      "writer",
		"principal":                      "tester",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, exists := payload["arguments"]; exists {
		t.Fatalf("telemetry recorded raw arguments: %#v", payload)
	}
}

func TestMCPTelemetryIncludesInitializeShape(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		postMCP(t, server, "", map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]any{
				"protocolVersion": mcpProtocolVersion,
				"clientInfo": map[string]any{
					"name":    "droid-test",
					"version": "0.0.0",
				},
				"capabilities": map[string]any{},
			},
		})
	})

	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"mcp.method":                      "initialize",
		"mcp.request_kind":                "request",
		"mcp.outcome":                     "ok",
		"mcp.accepts_json":                true,
		"mcp.accepts_sse":                 true,
		"mcp.jsonrpc_id_present":          true,
		"mcp.params_present":              true,
		"mcp.session_header_present":      false,
		"mcp.response_shape":              "initialize",
		"mcp.initialize_protocol_version": mcpProtocolVersion,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestMCPTelemetryIncludesListShape(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		postMCP(t, server, "client-session", map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/list",
			"params":  map[string]any{},
		})
	})

	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"mcp.method":                 "tools/list",
		"mcp.request_kind":           "request",
		"mcp.outcome":                "ok",
		"mcp.response_shape":         "list",
		"mcp.list_key":               "tools",
		"mcp.list_has_next_cursor":   false,
		"mcp.session_header_present": true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	count, ok := payload["mcp.list_count"].(float64)
	if !ok || count < 1 {
		t.Fatalf("telemetry mcp.list_count = %#v, want positive number; payload=%#v", payload["mcp.list_count"], payload)
	}
	if _, exists := payload["tools"]; exists {
		t.Fatalf("telemetry recorded raw tools list: %#v", payload)
	}
}

func TestMCPTelemetryClassifiesToolErrors(t *testing.T) {
	server := newMCPTestServer(t, nil)
	defer server.Close()

	var response map[string]any
	stderr := captureBootstrapStderr(t, func() {
		response, _ = postMCP(t, server, "", map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "cerebro.runtimes.status",
				"arguments": map[string]any{"runtime_id": "writer-okta"},
			},
		})
	})
	result := response["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("tools/call result = %#v, want tool error", result)
	}

	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"mcp.method":            "tools/call",
		"mcp.tool":              "cerebro.runtimes.status",
		"mcp.tool_family":       "runtimes",
		"mcp.outcome":           "tool_error",
		"mcp.tool_error":        true,
		"mcp.tool_error_kind":   "runtime_unavailable",
		"mcp.response_shape":    "tool_result",
		"mcp.tool_result_error": true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, exists := payload["error"]; exists {
		t.Fatalf("telemetry recorded raw error: %#v", payload)
	}
}

func TestMCPGETTelemetryRecordsStatelessRejection(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		req, err := http.NewRequest(http.MethodGet, server.URL+mcpEndpointPath, nil)
		if err != nil {
			t.Fatalf("NewRequest GET MCP: %v", err)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Accept", "text/event-stream")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/mcp error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET /api/v1/mcp status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"http.method":      http.MethodGet,
		"http.route":       "GET /api/v1/mcp",
		"http.status_code": float64(http.StatusMethodNotAllowed),
		"mcp.outcome":      "stateless_get_rejected",
		"mcp.request_kind": "transport_reject",
		"mcp.transport":    "stateless_http",
		"mcp.stateless":    true,
		"mcp.accepts_sse":  true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestMCPResourcesAndPrompts(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	resourcesResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/list",
		"params":  map[string]any{"limit": 2},
	})
	if resourcesResp["error"] != nil {
		t.Fatalf("resources/list error = %#v", resourcesResp["error"])
	}
	resourceResult := resourcesResp["result"].(map[string]any)
	if len(resourceResult["resources"].([]any)) != 2 || resourceResult["nextCursor"] == "" {
		t.Fatalf("resources/list result = %#v", resourceResult)
	}

	templatesResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "resources/templates/list",
		"params":  map[string]any{},
	})
	if templatesResp["error"] != nil {
		t.Fatalf("resources/templates/list error = %#v", templatesResp["error"])
	}
	templates := templatesResp["result"].(map[string]any)["resourceTemplates"].([]any)
	if len(templates) == 0 {
		t.Fatalf("resourceTemplates = %#v", templates)
	}

	promptsResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "prompts/list",
		"params":  map[string]any{},
	})
	if promptsResp["error"] != nil {
		t.Fatalf("prompts/list error = %#v", promptsResp["error"])
	}
	prompts := promptsResp["result"].(map[string]any)["prompts"].([]any)
	if len(prompts) != 4 {
		t.Fatalf("len(prompts) = %d, want 4", len(prompts))
	}

	promptResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "prompts/get",
		"params": map[string]any{
			"name":      "investigate_finding",
			"arguments": map[string]any{"finding_id": "finding-1"},
		},
	})
	if promptResp["error"] != nil {
		t.Fatalf("prompts/get error = %#v", promptResp["error"])
	}
	messages := promptResp["result"].(map[string]any)["messages"].([]any)
	if len(messages) != 1 {
		t.Fatalf("prompt messages = %#v", messages)
	}
	text := messages[0].(map[string]any)["content"].(map[string]any)["text"].(string)
	if !strings.Contains(text, "cerebro://investigation/finding/finding-1") || !strings.Contains(text, "never reveal redacted values") {
		t.Fatalf("prompt messages = %#v", messages)
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

func TestMCPFindingsGet(t *testing.T) {
	store := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:        "finding-1",
				RuntimeID: "writer-okta",
				TenantID:  "writer",
				RuleID:    "rule-1",
				Title:     "Finding One",
				Severity:  "critical",
				Status:    "open",
				FindingRisk: ports.FindingRisk{
					RiskScore:       94,
					LikelihoodScore: 87,
					ImpactScore:     96,
					RiskReasons:     []string{"internet exposed", "privileged asset"},
				},
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
			"name": "cerebro.findings.get",
			"arguments": map[string]any{
				"finding_id": "finding-1",
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	finding := response["result"].(map[string]any)["structuredContent"].(map[string]any)["finding"].(map[string]any)
	if finding["id"] != "finding-1" || finding["risk_score"] != float64(94) {
		t.Fatalf("finding response = %#v", finding)
	}
}

func TestMCPFindingSearchRuntimeStatusEvidenceAndInvestigation(t *testing.T) {
	now := time.Now().UTC()
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta": {Id: "writer-okta", SourceId: "okta", TenantId: "writer", Config: map[string]string{"domain": "writer.okta.com", "token": "secret"}},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				RuntimeID:      "writer-okta",
				TenantID:       "writer",
				RuleID:         "rule-1",
				Title:          "Privileged admin without MFA",
				Summary:        "Admin account is missing MFA",
				Severity:       "high",
				Status:         "open",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_user:00u1"},
				Attributes:     map[string]string{"api_key": "finding-secret", "environment": "prod"},
				FindingRisk:    ports.FindingRisk{RiskScore: 88, RiskReasons: []string{"privileged asset"}},
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {
				Id:            "evidence-1",
				RuntimeId:     "writer-okta",
				RuleId:        "rule-1",
				FindingId:     "finding-1",
				EventIds:      []string{"event-1"},
				GraphRootUrns: []string{"urn:cerebro:writer:okta_user:00u1"},
				Attributes:    map[string]string{"token": "evidence-secret", "environment": "prod"},
				GraphRows: []*cerebrov1.GraphEvidenceRow{{
					Label:      "identity_path",
					Attributes: map[string]string{"private_key": "row-secret", "label": "admin"},
					Paths: []*cerebrov1.GraphEvidencePath{{
						FromUrn:    "urn:cerebro:writer:okta_user:00u1",
						ToUrn:      "urn:cerebro:writer:asset:prod",
						Relation:   "can_access",
						Attributes: map[string]string{"password": "path-secret", "reason": "group membership"},
					}},
				}},
			},
		},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	searchResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.findings.search",
			"arguments": map[string]any{
				"query": "mfa",
				"limit": 10,
			},
		},
	})
	if searchResp["error"] != nil {
		t.Fatalf("findings.search error = %#v", searchResp["error"])
	}
	findings := searchResp["result"].(map[string]any)["structuredContent"].(map[string]any)["findings"].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["id"] != "finding-1" {
		t.Fatalf("findings.search findings = %#v", findings)
	}
	findingAttributes := findings[0].(map[string]any)["attributes"].(map[string]any)
	if findingAttributes["api_key"] != "[redacted]" || findingAttributes["environment"] != "prod" {
		t.Fatalf("finding attributes = %#v", findingAttributes)
	}
	searchMetadata := searchResp["result"].(map[string]any)["structuredContent"].(map[string]any)["metadata"].(map[string]any)
	if searchMetadata["stateless"] != true || searchMetadata["generated_at"] == "" {
		t.Fatalf("search metadata = %#v", searchMetadata)
	}

	secretSearchResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.findings.search",
			"arguments": map[string]any{"query": "finding-secret", "limit": 10},
		},
	})
	if secretSearchResp["error"] != nil {
		t.Fatalf("findings.search secret error = %#v", secretSearchResp["error"])
	}
	secretMatches := secretSearchResp["result"].(map[string]any)["structuredContent"].(map[string]any)["findings"].([]any)
	if len(secretMatches) != 0 {
		t.Fatalf("findings.search matched redacted attribute value: %#v", secretMatches)
	}

	statusResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.runtimes.status",
			"arguments": map[string]any{"runtime_id": "writer-okta"},
		},
	})
	if statusResp["error"] != nil {
		t.Fatalf("runtimes.status error = %#v", statusResp["error"])
	}
	status := statusResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	runtimeConfig := status["runtime"].(map[string]any)["config"].(map[string]any)
	if runtimeConfig["token"] != "[redacted]" {
		t.Fatalf("runtime config = %#v", runtimeConfig)
	}

	evidenceListResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.evidence.list",
			"arguments": map[string]any{
				"runtime_id": "writer-okta",
				"finding_id": "finding-1",
				"limit":      5,
			},
		},
	})
	if evidenceListResp["error"] != nil {
		t.Fatalf("evidence.list error = %#v", evidenceListResp["error"])
	}
	if got := store.findingEvidenceListRequest.FindingID; got != "finding-1" {
		t.Fatalf("findingEvidenceListRequest.FindingID = %q, want finding-1", got)
	}
	evidence := evidenceListResp["result"].(map[string]any)["structuredContent"].(map[string]any)["evidence"].([]any)
	if len(evidence) != 1 || evidence[0].(map[string]any)["id"] != "evidence-1" {
		t.Fatalf("evidence.list evidence = %#v", evidence)
	}
	evidenceRecord := evidence[0].(map[string]any)
	evidenceAttributes := evidenceRecord["attributes"].(map[string]any)
	if evidenceAttributes["token"] != "[redacted]" || evidenceAttributes["environment"] != "prod" {
		t.Fatalf("evidence attributes = %#v", evidenceAttributes)
	}
	graphRow := evidenceRecord["graph_rows"].([]any)[0].(map[string]any)
	if graphRow["attributes"].(map[string]any)["private_key"] != "[redacted]" {
		t.Fatalf("graph row attributes = %#v", graphRow["attributes"])
	}
	graphPath := graphRow["paths"].([]any)[0].(map[string]any)
	if graphPath["attributes"].(map[string]any)["password"] != "[redacted]" {
		t.Fatalf("graph path attributes = %#v", graphPath["attributes"])
	}

	evidenceGetResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.evidence.get",
			"arguments": map[string]any{"evidence_id": "evidence-1"},
		},
	})
	if evidenceGetResp["error"] != nil {
		t.Fatalf("evidence.get error = %#v", evidenceGetResp["error"])
	}
	if got := evidenceGetResp["result"].(map[string]any)["structuredContent"].(map[string]any)["evidence"].(map[string]any)["id"]; got != "evidence-1" {
		t.Fatalf("evidence.get id = %#v", got)
	}
	if got := evidenceGetResp["result"].(map[string]any)["structuredContent"].(map[string]any)["evidence"].(map[string]any)["attributes"].(map[string]any)["token"]; got != "[redacted]" {
		t.Fatalf("evidence.get token = %#v", got)
	}

	investigationResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.investigation.context",
			"arguments": map[string]any{
				"finding_id": "finding-1",
				"skip_graph": true,
				"compact":    true,
			},
		},
	})
	if investigationResp["error"] != nil {
		t.Fatalf("investigation.context error = %#v", investigationResp["error"])
	}
	context := investigationResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if context["evidence_count"] != float64(1) || context["compact"] != true {
		t.Fatalf("investigation context = %#v", context)
	}
	if context["metadata"].(map[string]any)["stateless"] != true {
		t.Fatalf("investigation metadata = %#v", context["metadata"])
	}

	resourceResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "resources/read",
		"params":  map[string]any{"uri": "cerebro://finding/finding-1"},
	})
	if resourceResp["error"] != nil {
		t.Fatalf("resources/read finding error = %#v", resourceResp["error"])
	}
	contents := resourceResp["result"].(map[string]any)["contents"].([]any)
	if len(contents) != 1 || !strings.Contains(contents[0].(map[string]any)["text"].(string), "finding-1") {
		t.Fatalf("resource contents = %#v", contents)
	}
	if strings.Contains(contents[0].(map[string]any)["text"].(string), "finding-secret") {
		t.Fatalf("resource leaked finding secret: %#v", contents)
	}
}

func TestMCPIDLookupsDoNotRevealCrossTenantExistence(t *testing.T) {
	store := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"other-finding": {ID: "other-finding", RuntimeID: "other-runtime", TenantID: "other", RuleID: "rule", Title: "Other"},
		},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.findings.get",
			"arguments": map[string]any{"finding_id": "other-finding"},
		},
	})
	result := response["result"].(map[string]any)
	if result["isError"] != true || !strings.Contains(result["content"].([]any)[0].(map[string]any)["text"].(string), "finding not found") {
		t.Fatalf("cross-tenant finding response = %#v", response)
	}
}

func TestMCPRuntimeIDToolsDoNotRevealCrossTenantExistence(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"other-runtime": {Id: "other-runtime", SourceId: "okta", TenantId: "other"},
		},
		findings:        map[string]*ports.FindingRecord{},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	for _, tt := range []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{name: "findings.list", tool: "cerebro.findings.list", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "findings.search", tool: "cerebro.findings.search", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "evidence.list", tool: "cerebro.evidence.list", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "assets.search", tool: "cerebro.assets.search", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "risk.summary", tool: "cerebro.risk.summary", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "graph.facts.list", tool: "cerebro.graph.facts.list", arguments: map[string]any{"runtime_id": "other-runtime"}},
		{name: "graph.facts.explain", tool: "cerebro.graph.facts.explain", arguments: map[string]any{"runtime_id": "other-runtime", "fact_id": "fact-1"}},
		{name: "graph.facts.trace", tool: "cerebro.graph.facts.trace", arguments: map[string]any{"runtime_id": "other-runtime", "fact_id": "fact-1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, _ := postMCP(t, server, "", map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name":      tt.tool,
					"arguments": tt.arguments,
				},
			})
			result := response["result"].(map[string]any)
			text := result["content"].([]any)[0].(map[string]any)["text"].(string)
			if result["isError"] != true || !strings.Contains(text, "source runtime not found") || strings.Contains(text, "tenant forbidden") {
				t.Fatalf("%s response = %#v", tt.name, response)
			}
		})
	}
}

func TestMCPGraphFactsURNSelectorsDoNotRevealCrossTenantExistence(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	for _, tt := range []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{name: "list subject", tool: "cerebro.graph.facts.list", arguments: map[string]any{"subject_urn": "urn:cerebro:other:asset:prod-db"}},
		{name: "explain subject", tool: "cerebro.graph.facts.explain", arguments: map[string]any{"subject_urn": "urn:cerebro:other:asset:prod-db", "predicate": "has_status", "object_value": "ok"}},
		{name: "trace object", tool: "cerebro.graph.facts.trace", arguments: map[string]any{"subject_urn": "urn:cerebro:writer:asset:prod-db", "predicate": "owned_by", "object_urn": "urn:cerebro:other:identity:alice"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, _ := postMCP(t, server, "", map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name":      tt.tool,
					"arguments": tt.arguments,
				},
			})
			result := response["result"].(map[string]any)
			text := result["content"].([]any)[0].(map[string]any)["text"].(string)
			if result["isError"] != true || !strings.Contains(text, "graph entity not found") || strings.Contains(text, "tenant forbidden") {
				t.Fatalf("%s response = %#v", tt.name, response)
			}
		})
	}
}

func TestMCPAssetsSearchUsesTenantScopedCypher(t *testing.T) {
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{{
		{Values: map[string]any{
			"urn":             "urn:cerebro:writer:asset:prod-db",
			"tenant_id":       "writer",
			"runtime_id":      "writer-aws",
			"source_id":       "aws",
			"entity_type":     "aws.rds.instance",
			"label":           "prod-db",
			"attributes_json": `{"account_id":"123456789012","api_key":"secret-api-key","environment":"prod","private_key":"secret-private-key","token_id":"token-123"}`,
		}},
		{Values: map[string]any{
			"urn":             "urn:cerebro:other:asset:prod-db",
			"tenant_id":       "other",
			"runtime_id":      "other-aws",
			"source_id":       "aws",
			"entity_type":     "aws.rds.instance",
			"label":           "other-prod-db",
			"attributes_json": `{}`,
		}},
	}}}
	server := newMCPTestServerWithGraph(t, &stubRuntimeStore{}, graph)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.assets.search",
			"arguments": map[string]any{
				"query":       "prod",
				"entity_type": "aws.rds.instance",
				"limit":       7,
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	if len(graph.cypherRequests) != 1 {
		t.Fatalf("cypher requests = %d, want 1", len(graph.cypherRequests))
	}
	if graph.cypherRequests[0].Params["tenant_id"] != "writer" || graph.cypherRequests[0].RowLimit != 7 {
		t.Fatalf("cypher request = %#v", graph.cypherRequests[0])
	}
	if strings.Contains(graph.cypherRequests[0].Query, "toLower(coalesce(e.attributes_json") {
		t.Fatalf("asset search query matches raw sensitive attributes: %s", graph.cypherRequests[0].Query)
	}
	assets := response["result"].(map[string]any)["structuredContent"].(map[string]any)["assets"].([]any)
	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want 1", len(assets))
	}
	asset := assets[0].(map[string]any)
	if asset["urn"] != "urn:cerebro:writer:asset:prod-db" {
		t.Fatalf("asset = %#v", asset)
	}
	attributes := asset["attributes"].(map[string]any)
	if attributes["environment"] != "prod" {
		t.Fatalf("attributes = %#v", attributes)
	}
	for _, key := range []string{"api_key", "private_key", "token_id"} {
		if attributes[key] != "[redacted]" {
			t.Fatalf("attributes[%q] = %#v, want redacted in %#v", key, attributes[key], attributes)
		}
	}
	if attributes["account_id"] != "123456789012" {
		t.Fatalf("attributes = %#v", attributes)
	}
}

func TestMCPAssetsGetGraphToolsAndDryRunProposals(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws":    {Id: "writer-aws", SourceId: "aws", TenantId: "writer"},
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {ID: "finding-1", RuntimeID: "writer-aws", TenantID: "writer", RuleID: "rule-1", Title: "Finding", Severity: "high", Status: "open"},
		},
	}
	graph := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:prod-db", EntityType: "aws.rds.instance", Label: "prod-db"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:finding:finding-1", EntityType: "finding", Label: "Finding"},
			},
			Relations: []*ports.NeighborhoodRelation{{
				FromURN:    "urn:cerebro:writer:asset:prod-db",
				Relation:   "has_evidence",
				ToURN:      "urn:cerebro:writer:finding:finding-1",
				Attributes: map[string]string{"secret_access_key": "hidden", "confidence": "high"},
			}},
		},
		cypherRows: [][]ports.CypherRow{
			{{
				Values: map[string]any{
					"urn":             "urn:cerebro:writer:asset:prod-db",
					"tenant_id":       "writer",
					"runtime_id":      "writer-aws",
					"source_id":       "aws",
					"entity_type":     "aws.rds.instance",
					"label":           "prod-db",
					"attributes_json": `{"environment":"prod","secret_access_key":"hidden"}`,
				},
			}},
			{{
				Values: map[string]any{
					"path_count":                 int64(1),
					"exposed_resource_count":     int64(1),
					"privileged_principal_count": int64(1),
					"cloud_account_count":        int64(1),
				},
			}},
			{{
				Values: map[string]any{
					"public_urn":             "urn:cerebro:writer:aws_public_principal:internet",
					"public_entity_type":     "aws.public_principal",
					"public_label":           "internet",
					"exposed_urn":            "urn:cerebro:writer:asset:prod-db",
					"exposed_entity_type":    "aws.rds.instance",
					"exposed_label":          "prod-db",
					"account_urn":            "urn:cerebro:writer:cloud_account:123",
					"account_entity_type":    "cloud.account",
					"account_label":          "123",
					"principal_urn":          "urn:cerebro:writer:aws_role:admin",
					"principal_entity_type":  "aws.role",
					"principal_label":        "admin",
					"permission_urn":         "urn:cerebro:writer:aws_policy:admin",
					"permission_entity_type": "aws.policy",
					"permission_label":       "admin",
					"reach_relation":         "can_reach",
					"access_relation":        "can_admin",
				},
			}},
		},
	}
	server := newMCPTestServerWithGraph(t, store, graph)
	defer server.Close()

	assetResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.assets.get",
			"arguments": map[string]any{"urn": "urn:cerebro:writer:asset:prod-db"},
		},
	})
	if assetResp["error"] != nil {
		t.Fatalf("assets.get error = %#v", assetResp["error"])
	}
	asset := assetResp["result"].(map[string]any)["structuredContent"].(map[string]any)["asset"].(map[string]any)
	if asset["attributes"].(map[string]any)["secret_access_key"] != "[redacted]" {
		t.Fatalf("asset attributes = %#v", asset["attributes"])
	}

	impactResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.impact",
			"arguments": map[string]any{
				"kind":     "asset",
				"root_urn": "urn:cerebro:writer:asset:prod-db",
				"depth":    1,
				"limit":    10,
			},
		},
	})
	if impactResp["error"] != nil {
		t.Fatalf("graph.impact error = %#v", impactResp["error"])
	}
	if got := impactResp["result"].(map[string]any)["structuredContent"].(map[string]any)["root_urn"]; got != "urn:cerebro:writer:asset:prod-db" {
		t.Fatalf("graph.impact root_urn = %#v", got)
	}
	impact := impactResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	impactRelations := impact["relations"].([]any)
	if len(impactRelations) != 1 {
		t.Fatalf("graph.impact relations = %#v", impactRelations)
	}
	impactAttributes := impactRelations[0].(map[string]any)["attributes"].(map[string]any)
	if impactAttributes["secret_access_key"] != "[redacted]" || impactAttributes["confidence"] != "high" {
		t.Fatalf("graph.impact relation attributes = %#v", impactAttributes)
	}
	if impact["metadata"].(map[string]any)["returned"] == float64(0) {
		t.Fatalf("graph.impact metadata = %#v", impact["metadata"])
	}

	crossTenantImpactResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.impact",
			"arguments": map[string]any{
				"kind":       "asset",
				"identifier": "urn:cerebro:other:asset:prod-db",
				"depth":      1,
				"limit":      10,
			},
		},
	})
	crossTenantImpact := crossTenantImpactResp["result"].(map[string]any)
	if crossTenantImpact["isError"] != true || !strings.Contains(crossTenantImpact["content"].([]any)[0].(map[string]any)["text"].(string), "graph entity not found") {
		t.Fatalf("cross-tenant graph.impact response = %#v", crossTenantImpactResp)
	}

	pathsResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.graph.paths",
			"arguments": map[string]any{"limit": 5},
		},
	})
	if pathsResp["error"] != nil {
		t.Fatalf("graph.paths error = %#v", pathsResp["error"])
	}
	paths := pathsResp["result"].(map[string]any)["structuredContent"].(map[string]any)["paths"].([]any)
	if len(paths) != 1 {
		t.Fatalf("paths = %#v", paths)
	}

	proposalResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      8,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.findings.action.propose",
			"arguments": map[string]any{
				"dry_run":    true,
				"finding_id": "finding-1",
				"action":     "update_status",
				"status":     "resolved",
				"reason":     "validated by agent",
			},
		},
	})
	if proposalResp["error"] != nil {
		t.Fatalf("findings.action.propose error = %#v", proposalResp["error"])
	}
	proposal := proposalResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if proposal["dry_run"] != true || proposal["would_mutate"] != false {
		t.Fatalf("proposal = %#v", proposal)
	}

	refreshResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.source_runtimes.refresh.propose",
			"arguments": map[string]any{"dry_run": true, "runtime_id": "writer-aws"},
		},
	})
	if refreshResp["error"] != nil {
		t.Fatalf("source_runtimes.refresh.propose error = %#v", refreshResp["error"])
	}
}

func TestMCPRuntimeStatusAndProposalsHandleMissingTargets(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	runtimeStatusResp, _ := postMCPWithoutAuth(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.runtimes.status",
			"arguments": map[string]any{"runtime_id": "missing-runtime"},
		},
	})
	if runtimeStatusResp["error"] != nil || runtimeStatusResp["result"].(map[string]any)["isError"] != true {
		t.Fatalf("runtimes.status without store response = %#v", runtimeStatusResp)
	}

	store := &stubRuntimeStore{
		runtimes:        map[string]*cerebrov1.SourceRuntime{},
		findings:        map[string]*ports.FindingRecord{},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}
	app = New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server = httptest.NewServer(app.Handler())
	defer server.Close()

	findingProposalResp, _ := postMCPWithoutAuth(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.findings.action.propose",
			"arguments": map[string]any{
				"dry_run":    true,
				"finding_id": "missing-finding",
				"action":     "add_note",
				"note":       "not real",
			},
		},
	})
	if findingProposalResp["error"] != nil || findingProposalResp["result"].(map[string]any)["isError"] != true {
		t.Fatalf("missing finding proposal response = %#v", findingProposalResp)
	}

	runtimeProposalResp, _ := postMCPWithoutAuth(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.source_runtimes.refresh.propose",
			"arguments": map[string]any{"dry_run": true, "runtime_id": "missing-runtime"},
		},
	})
	if runtimeProposalResp["error"] != nil || runtimeProposalResp["result"].(map[string]any)["isError"] != true {
		t.Fatalf("missing runtime proposal response = %#v", runtimeProposalResp)
	}
}

func TestMCPRiskSummaryAggregatesScopedRuntimeFindings(t *testing.T) {
	now := time.Now().UTC()
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws":    {Id: "writer-aws", SourceId: "aws", TenantId: "writer"},
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-critical": {
				ID:             "finding-critical",
				RuntimeID:      "writer-aws",
				TenantID:       "writer",
				RuleID:         "rule-critical",
				Title:          "Critical",
				Severity:       "critical",
				Status:         "open",
				FindingRisk:    ports.FindingRisk{RiskScore: 95, RiskReasons: []string{"internet exposed", "privileged asset"}},
				LastObservedAt: now,
			},
			"finding-high": {
				ID:             "finding-high",
				RuntimeID:      "writer-github",
				TenantID:       "writer",
				RuleID:         "rule-high",
				Title:          "High",
				Severity:       "high",
				Status:         "open",
				FindingRisk:    ports.FindingRisk{RiskScore: 75, RiskReasons: []string{"internet exposed"}},
				LastObservedAt: now.Add(-time.Minute),
			},
			"finding-resolved": {
				ID:             "finding-resolved",
				RuntimeID:      "writer-github",
				TenantID:       "writer",
				RuleID:         "rule-low",
				Title:          "Resolved",
				Severity:       "low",
				Status:         "resolved",
				FindingRisk:    ports.FindingRisk{RiskScore: 10},
				LastObservedAt: now.Add(-2 * time.Minute),
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
			"name": "cerebro.risk.summary",
			"arguments": map[string]any{
				"limit": 50,
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	summary := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	if summary["total_findings"] != float64(3) || summary["open_findings"] != float64(2) || summary["critical_open_findings"] != float64(1) || summary["high_open_findings"] != float64(1) {
		t.Fatalf("summary counts = %#v", summary)
	}
	if summary["max_risk_score"] != float64(95) {
		t.Fatalf("max_risk_score = %#v", summary["max_risk_score"])
	}
	reasons := summary["top_risk_reasons"].([]any)
	if len(reasons) == 0 || reasons[0].(map[string]any)["reason"] != "internet exposed" || reasons[0].(map[string]any)["count"] != float64(2) {
		t.Fatalf("top_risk_reasons = %#v", reasons)
	}
	recent := summary["recent_high_risk"].([]any)
	if len(recent) == 0 || recent[0].(map[string]any)["id"] != "finding-critical" {
		t.Fatalf("recent_high_risk = %#v", recent)
	}
}

func TestMCPRiskActionsListAndExplain(t *testing.T) {
	now := time.Now().UTC()
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws":    {Id: "writer-aws", SourceId: "aws", TenantId: "writer"},
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"cloud-public-prod-secrets": {
				ID:           "cloud-public-prod-secrets",
				TenantID:     "writer",
				RuntimeID:    "writer-aws",
				RuleID:       "cloud-public-resource-exposure",
				Title:        "Cloud Public Resource Exposure",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
				EventIDs:     []string{"evt-public"},
				FindingWorkflow: ports.FindingWorkflow{
					Assignee: "cloud-platform",
				},
				FindingRisk: ports.FindingRisk{
					RiskScore:       90,
					ConfidenceScore: 92,
					RiskReasons:     []string{"external_exposure", "crown_jewel"},
					RiskFactors: []ports.FindingRiskFactor{
						{FactorID: "external_exposure", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:internet_exposed"}},
					},
				},
				Attributes: map[string]string{
					"action":               "public_network_ingress",
					"internet_exposed":     "true",
					"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
					"resource_name":        "prod-secrets",
				},
				LastObservedAt: now,
			},
		},
	}
	graph := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
				{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
			},
		},
	}
	server := newMCPTestServerWithGraph(t, store, graph)
	defer server.Close()

	listResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.risk.actions.list",
			"arguments": map[string]any{
				"runtime_ids": []string{"writer-aws", "writer-github"},
				"status":      "open",
				"limit":       5,
				"graph_limit": 3,
			},
		},
	})
	if listResp["error"] != nil {
		t.Fatalf("risk.actions.list error = %#v", listResp["error"])
	}
	if listResp["result"].(map[string]any)["isError"] == true {
		t.Fatalf("risk.actions.list tool error = %#v", listResp["result"])
	}
	content := listResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if content["graph_evidence_status"] != mcpGraphEvidenceIncluded || content["graph_neighborhood_count"] != float64(1) {
		t.Fatalf("graph evidence content = %#v", content)
	}
	candidates := content["action_candidates"].([]any)
	if len(candidates) != 1 {
		t.Fatalf("action_candidates = %#v, want one candidate", candidates)
	}
	candidate := candidates[0].(map[string]any)
	candidateID := "remove-public-exposure-urn-cerebro-writer-aws-secret-store-prod-secrets"
	if candidate["id"] != candidateID || candidate["simulation_status"] != "simulated" {
		t.Fatalf("candidate = %#v, want simulated public exposure candidate", candidate)
	}
	if candidate["owner"] != "cloud-platform" {
		t.Fatalf("candidate owner = %#v, want cloud-platform", candidate["owner"])
	}
	scoreBreakdown := candidate["score_breakdown"].(map[string]any)
	if scoreBreakdown["total"].(float64) <= 0 || scoreBreakdown["attack_path_count_reduction_points"].(float64) <= 0 {
		t.Fatalf("score_breakdown = %#v, want positive attack-path contribution", scoreBreakdown)
	}
	if store.findingListRequest.RuntimeID != "" || len(store.findingListRequest.RuntimeIDs) != 2 || store.findingListRequest.RuntimeIDs[0] != "writer-aws" || store.findingListRequest.RuntimeIDs[1] != "writer-github" {
		t.Fatalf("finding list request = %#v, want runtime_ids request", store.findingListRequest)
	}
	if graph.neighborhoodRootURN != "urn:cerebro:writer:aws_secret_store:prod-secrets" || graph.neighborhoodLimit != 3 {
		t.Fatalf("graph request root=%q limit=%d, want prod-secrets limit 3", graph.neighborhoodRootURN, graph.neighborhoodLimit)
	}

	explainResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.risk.actions.explain",
			"arguments": map[string]any{
				"candidate_id": candidateID,
				"runtime_ids":  []string{"writer-aws", "writer-github"},
				"status":       "open",
				"limit":        5,
				"graph_limit":  3,
			},
		},
	})
	if explainResp["error"] != nil {
		t.Fatalf("risk.actions.explain error = %#v", explainResp["error"])
	}
	if explainResp["result"].(map[string]any)["isError"] == true {
		t.Fatalf("risk.actions.explain tool error = %#v", explainResp["result"])
	}
	explain := explainResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if explain["plan_model_version"] != "risk-action-plan-v2" {
		t.Fatalf("plan_model_version = %#v, want risk-action-plan-v2", explain["plan_model_version"])
	}
	if explain["candidate"].(map[string]any)["id"] != candidateID {
		t.Fatalf("explain candidate = %#v, want %s", explain["candidate"], candidateID)
	}
	if explain["expected_reduction"].(map[string]any)["risk_score"].(float64) <= 0 {
		t.Fatalf("expected_reduction = %#v, want positive risk score reduction", explain["expected_reduction"])
	}
	if explain["ownership"].(map[string]any)["owner"] != "cloud-platform" {
		t.Fatalf("ownership = %#v, want cloud-platform", explain["ownership"])
	}
}

func TestMCPRiskActionsDerivesTenantFromRuntimeID(t *testing.T) {
	now := time.Now().UTC()
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws": {Id: "writer-aws", SourceId: "aws", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"cloud-public-prod-secrets": {
				ID:           "cloud-public-prod-secrets",
				TenantID:     "writer",
				RuntimeID:    "writer-aws",
				RuleID:       "cloud-public-resource-exposure",
				Title:        "Cloud Public Resource Exposure",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
				FindingRisk: ports.FindingRisk{
					RiskScore:       90,
					ConfidenceScore: 92,
					RiskReasons:     []string{"external_exposure"},
					RiskFactors: []ports.FindingRiskFactor{
						{FactorID: "external_exposure", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:internet_exposed"}},
					},
				},
				Attributes: map[string]string{
					"action":               "public_network_ingress",
					"internet_exposed":     "true",
					"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
					"resource_name":        "prod-secrets",
				},
				LastObservedAt: now,
			},
		},
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:        true,
			AllowedTenants: []string{"writer"},
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "tester",
			}},
		},
	}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.risk.actions.list",
			"arguments": map[string]any{
				"runtime_id": "writer-aws",
				"status":     "open",
				"limit":      5,
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("risk.actions.list error = %#v", response["error"])
	}
	if response["result"].(map[string]any)["isError"] == true {
		t.Fatalf("risk.actions.list tool error = %#v", response["result"])
	}
	content := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	plan := content["plan"].(map[string]any)
	if plan["tenant_id"] != "writer" {
		t.Fatalf("plan.tenant_id = %#v, want writer", plan["tenant_id"])
	}
	candidates := content["action_candidates"].([]any)
	if len(candidates) != 1 {
		t.Fatalf("action_candidates = %#v, want one candidate", candidates)
	}
	if store.findingListRequest.TenantID != "writer" || store.findingListRequest.RuntimeID != "writer-aws" {
		t.Fatalf("finding list request = %#v, want tenant/runtime scoped request", store.findingListRequest)
	}
}

func TestMCPRiskSummaryCountsAllMatchingFindingsBeyondReturnedLimit(t *testing.T) {
	now := time.Now().UTC()
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-aws":    {Id: "writer-aws", SourceId: "aws", TenantId: "writer"},
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				RuntimeID:      "writer-aws",
				TenantID:       "writer",
				RuleID:         "rule-1",
				Title:          "First",
				Severity:       "high",
				Status:         "open",
				FindingRisk:    ports.FindingRisk{RiskScore: 90, RiskReasons: []string{"active"}},
				LastObservedAt: now,
			},
			"finding-2": {
				ID:             "finding-2",
				RuntimeID:      "writer-aws",
				TenantID:       "writer",
				RuleID:         "rule-2",
				Title:          "Second",
				Severity:       "medium",
				Status:         "open",
				FindingRisk:    ports.FindingRisk{RiskScore: 80, RiskReasons: []string{"active"}},
				LastObservedAt: now.Add(-time.Minute),
			},
			"finding-3": {
				ID:             "finding-3",
				RuntimeID:      "writer-github",
				TenantID:       "writer",
				RuleID:         "rule-3",
				Title:          "Third",
				Severity:       "low",
				Status:         "open",
				FindingRisk:    ports.FindingRisk{RiskScore: 70, RiskReasons: []string{"active"}},
				LastObservedAt: now.Add(-2 * time.Minute),
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
			"name": "cerebro.risk.summary",
			"arguments": map[string]any{
				"limit":  2,
				"status": "open",
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("tools/call error = %#v", response["error"])
	}
	summary := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	if summary["total_findings"] != float64(3) || summary["open_findings"] != float64(3) || summary["returned_findings"] != float64(2) {
		t.Fatalf("summary counts = %#v", summary)
	}
	bySeverity := summary["by_severity"].(map[string]any)
	if bySeverity["high"] != float64(1) || bySeverity["medium"] != float64(1) || bySeverity["low"] != float64(1) {
		t.Fatalf("by_severity = %#v", bySeverity)
	}
	metadata := summary["metadata"].(map[string]any)
	if metadata["total_matching_findings"] != float64(3) || metadata["more_results_possible"] != true {
		t.Fatalf("metadata = %#v", metadata)
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

func TestMCPGraphFactsListAndExplain(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"runtime-1": {Id: "runtime-1", TenantId: "writer", SourceId: "github"},
		},
		claims: map[string]*ports.ClaimRecord{
			"fact-1": {
				ID:            "fact-1",
				RuntimeID:     "runtime-1",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:github_code_repository:repo-1",
				Predicate:     "owned_by",
				ObjectURN:     "urn:cerebro:writer:identity:email:alice@example.com",
				ClaimType:     "relation",
				Status:        "asserted",
				SourceEventID: "event-1",
				ObservedAt:    time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC),
				UpdatedAt:     time.Date(2026, 6, 22, 14, 1, 0, 0, time.UTC),
				Attributes:    map[string]string{"confidence": "high", "evidence_urn": "urn:cerebro:writer:evidence:evidence-1"},
			},
			"fact-2": {
				ID:          "fact-2",
				RuntimeID:   "runtime-1",
				TenantID:    "writer",
				SubjectURN:  "urn:cerebro:writer:github_code_repository:repo-1",
				Predicate:   "has_status",
				ObjectValue: "active",
				ClaimType:   "attribute",
				Status:      "asserted",
				ObservedAt:  time.Date(2026, 6, 22, 13, 59, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC),
				Attributes:  map[string]string{"confidence": "medium"},
			},
			"fact-3": {
				ID:          "fact-3",
				RuntimeID:   "runtime-1",
				TenantID:    "writer",
				SubjectURN:  "urn:cerebro:writer:github_code_repository:repo-1",
				Predicate:   "monitored_by",
				ObjectValue: "security",
				ClaimType:   "attribute",
				Status:      "asserted",
				ObservedAt:  time.Date(2026, 6, 22, 13, 58, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 6, 22, 13, 59, 0, 0, time.UTC),
				Attributes:  map[string]string{"confidence": "medium"},
			},
		},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	listResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.facts.list",
			"arguments": map[string]any{
				"runtime_id": "runtime-1",
				"predicate":  "owned_by",
				"limit":      5,
			},
		},
	})
	if listResp["error"] != nil {
		t.Fatalf("graph facts list error = %#v", listResp["error"])
	}
	listContent := listResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	listMetadata := listContent["metadata"].(map[string]any)
	if listMetadata["limit_applied"] != float64(5) || listMetadata["returned"] != float64(1) {
		t.Fatalf("list metadata = %#v", listMetadata)
	}
	facts := listContent["facts"].([]any)
	if len(facts) != 1 {
		t.Fatalf("len(facts) = %d, want 1", len(facts))
	}
	if got := facts[0].(map[string]any)["id"]; got != "fact-1" {
		t.Fatalf("fact id = %#v, want fact-1", got)
	}
	if store.claimListRequest.Predicate != "owned_by" || store.claimListRequest.Limit != 6 {
		t.Fatalf("claim list request = %#v", store.claimListRequest)
	}

	explainResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.graph.facts.explain",
			"arguments": map[string]any{"runtime_id": "runtime-1", "fact_id": "fact-1"},
		},
	})
	if explainResp["error"] != nil {
		t.Fatalf("graph facts explain error = %#v", explainResp["error"])
	}
	explain := explainResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if explain["explanation"] == "" {
		t.Fatalf("explanation missing from response: %#v", explain)
	}
	explainMetadata := explain["metadata"].(map[string]any)
	if explainMetadata["returned"] != float64(1) || explainMetadata["stateless"] != true {
		t.Fatalf("explain metadata = %#v", explainMetadata)
	}
	edge := explain["edge"].(map[string]any)
	if edge["relation"] != "owned_by" || edge["status"] != "asserted" {
		t.Fatalf("edge = %#v, want owned_by asserted edge", edge)
	}
	evidence := explain["evidence"].([]any)
	if len(evidence) != 2 {
		t.Fatalf("len(evidence) = %d, want source event plus evidence URN", len(evidence))
	}

	traceResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.facts.trace",
			"arguments": map[string]any{
				"runtime_id":         "runtime-1",
				"fact_id":            "fact-1",
				"limit":              2,
				"include_evidence":   true,
				"evidence_limit":     2,
				"include_attributes": false,
			},
		},
	})
	if traceResp["error"] != nil {
		t.Fatalf("graph facts trace error = %#v", traceResp["error"])
	}
	trace := traceResp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if len(trace["steps"].([]any)) < 2 {
		t.Fatalf("trace steps = %#v, want provenance steps", trace["steps"])
	}
	traceMetadata := trace["metadata"].(map[string]any)
	if traceMetadata["related_more"] != true || traceMetadata["related_truncated"] != true || traceMetadata["related_truncation_reason"] != "related_fact_limit" {
		t.Fatalf("trace metadata = %#v, want related fact limit truncation", traceMetadata)
	}
	anchorFact := trace["anchor"].(map[string]any)["fact"].(map[string]any)
	if _, ok := anchorFact["attributes"]; ok {
		t.Fatalf("anchor fact attributes present despite include_attributes=false: %#v", anchorFact)
	}

	limitedResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.facts.list",
			"arguments": map[string]any{
				"runtime_id": "runtime-1",
				"limit":      5,
				"max_bytes":  1,
			},
		},
	})
	limitedResult := limitedResp["result"].(map[string]any)
	limitedText := limitedResult["content"].([]any)[0].(map[string]any)["text"].(string)
	if limitedResult["isError"] != true || !strings.Contains(limitedText, "response exceeds max_bytes") {
		t.Fatalf("graph facts max_bytes response = %#v", limitedResp)
	}
}

func TestMCPGraphFactsExplainOutputSchemaDeclaresResponseFields(t *testing.T) {
	var outputSchema map[string]any
	for _, tool := range mcpTools() {
		if tool.Name == "cerebro.graph.facts.explain" {
			outputSchema = tool.OutputSchema
			break
		}
	}
	if outputSchema == nil {
		t.Fatal("cerebro.graph.facts.explain tool not found")
	}
	properties := outputSchema["properties"].(map[string]any)
	for _, key := range []string{"fact", "edge", "evidence", "freshness", "explanation", "metadata"} {
		if _, ok := properties[key]; !ok {
			t.Fatalf("output schema missing %q: %#v", key, properties)
		}
	}
	if outputSchema["additionalProperties"] != false {
		t.Fatalf("output schema should reject undeclared fields: %#v", outputSchema)
	}
}

func TestMCPGraphReason(t *testing.T) {
	graph := &stubGraphStore{
		cypherRows: [][]ports.CypherRow{{
			{Values: map[string]any{
				"entity_urn":  "urn:cerebro:writer:asset:prod-db",
				"entity_type": "asset",
				"label":       "prod-db",
			}},
		}},
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:prod-db", EntityType: "asset", Label: "prod-db"},
		},
	}
	llm := &graphagent.StubLLMClient{
		DraftResponse: &graphagent.DraftResponse{
			Rationale: "Answering with scoped graph evidence.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:writer:asset:prod-db` first.",
	}
	server := newMCPTestServerWithGraphReasoning(t, &stubRuntimeStore{}, graph, llm)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.reason",
			"arguments": map[string]any{
				"question":  "Which asset should I review first?",
				"scope_urn": "urn:cerebro:writer:asset:prod-db",
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("graph.reason error = %#v", response["error"])
	}
	content := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	if content["trace_id"] == "" || content["query_plan"] == nil || content["cypher"] == nil {
		t.Fatalf("graph.reason missing trace/query/cypher: %#v", content)
	}
	rows := content["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["entity_urn"] != "urn:cerebro:writer:asset:prod-db" {
		t.Fatalf("graph.reason rows = %#v", rows)
	}
	provenance := content["provenance"].(map[string]any)
	if provenance["surface"] != "graph-reasoning" || provenance["citation_status"] != "valid" {
		t.Fatalf("graph.reason provenance = %#v", provenance)
	}
	preflight := content["preflight"].(map[string]any)
	if preflight["tenant_id"] != "writer" || preflight["enabled"] != true {
		t.Fatalf("graph.reason preflight = %#v", preflight)
	}
	preflightPolicy := preflight["policy"].(map[string]any)
	if preflightPolicy["passing"] != true {
		t.Fatalf("graph.reason preflight policy = %#v", preflightPolicy)
	}
	if content["tenant_id"] != "writer" {
		t.Fatalf("graph.reason tenant_id = %#v, want authenticated tenant writer", content["tenant_id"])
	}
	metadata := content["metadata"].(map[string]any)
	if metadata["returned"] != float64(1) || metadata["stateless"] != true {
		t.Fatalf("graph.reason metadata = %#v", metadata)
	}

	overrideResponse, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.reason",
			"arguments": map[string]any{
				"tenant_id": "other",
				"question":  "Which asset should I review first?",
			},
		},
	})
	overrideResult := overrideResponse["result"].(map[string]any)
	if overrideResult["isError"] != true || !strings.Contains(overrideResult["content"].([]any)[0].(map[string]any)["text"].(string), "tenant forbidden") {
		t.Fatalf("graph.reason tenant override response = %#v", overrideResponse)
	}
}

func TestMCPGraphReasonRejectsUnsupportedModelBeforeLLM(t *testing.T) {
	llm := &graphagent.StubLLMClient{}
	server := newMCPTestServerWithGraphReasoning(t, &stubRuntimeStore{}, &stubGraphStore{}, llm)
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.reason",
			"arguments": map[string]any{
				"question": "Which asset should I review first?",
				"model":    "attacker-selected-provider-model",
			},
		},
	})
	result := response["result"].(map[string]any)
	content := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if result["isError"] != true || !strings.Contains(content, "unsupported graph agent model") {
		t.Fatalf("graph.reason unsupported model response = %#v", response)
	}
	if len(llm.DraftRequests) != 0 {
		t.Fatalf("draft requests = %#v, want unsupported model rejected before LLM", llm.DraftRequests)
	}
}

func TestMCPGraphReasonMissingTenantWithoutAuthReportsInvalidRequest(t *testing.T) {
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{
		StateStore:    &stubRuntimeStore{},
		GraphStore:    &stubGraphStore{},
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, _ := postMCPWithoutAuth(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.reason",
			"arguments": map[string]any{
				"question": "Which asset should I review first?",
			},
		},
	})
	result := response["result"].(map[string]any)
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if result["isError"] != true || !strings.Contains(text, "tenant_id is required") || strings.Contains(text, "scope forbidden") {
		t.Fatalf("graph.reason missing tenant response = %#v", response)
	}
}

func TestMCPAgentPreflight(t *testing.T) {
	server := newMCPTestServerWithGraphReasoning(t, &stubRuntimeStore{}, &stubGraphStore{}, graphagent.NewStubLLMClient())
	defer server.Close()

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.agent.preflight",
			"arguments": map[string]any{
				"capability_ids": []any{"graph-reasoning"},
				"question":       "What should I inspect?",
				"scope_urn":      "urn:cerebro:writer:asset:prod-db",
			},
		},
	})
	if response["error"] != nil {
		t.Fatalf("agent.preflight error = %#v", response["error"])
	}
	content := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	if content["tenant_id"] != "writer" || content["enabled"] != true {
		t.Fatalf("agent.preflight content = %#v", content)
	}
	graphContext := content["graph_context"].(map[string]any)
	if graphContext["scope_tenant_id"] != "writer" || graphContext["read_only"] != true {
		t.Fatalf("agent.preflight graph_context = %#v", graphContext)
	}
	writeBack := content["write_back"].(map[string]any)
	if writeBack["required"] != true || writeBack["trace_id_required"] != true {
		t.Fatalf("agent.preflight write_back = %#v", writeBack)
	}

	overrideResponse, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.agent.preflight",
			"arguments": map[string]any{
				"tenant_id":      "other",
				"capability_ids": []any{"graph-reasoning"},
			},
		},
	})
	overrideResult := overrideResponse["result"].(map[string]any)
	if overrideResult["isError"] != true || !strings.Contains(overrideResult["content"].([]any)[0].(map[string]any)["text"].(string), "tenant forbidden") {
		t.Fatalf("agent.preflight tenant override response = %#v", overrideResponse)
	}
}

func TestMCPGraphToolMetadataNormalizesLimits(t *testing.T) {
	graph := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:prod-db", EntityType: "asset", Label: "prod-db"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:finding:finding-1", EntityType: "finding", Label: "finding-1"},
			},
		},
		cypherRows: [][]ports.CypherRow{
			{{
				Values: map[string]any{
					"path_count":                 int64(1),
					"exposed_resource_count":     int64(1),
					"privileged_principal_count": int64(1),
					"cloud_account_count":        int64(1),
				},
			}},
			{{
				Values: map[string]any{
					"public_urn":             "urn:cerebro:writer:aws_public_principal:internet",
					"public_entity_type":     "aws.public_principal",
					"public_label":           "internet",
					"exposed_urn":            "urn:cerebro:writer:asset:prod-db",
					"exposed_entity_type":    "aws.rds.instance",
					"exposed_label":          "prod-db",
					"account_urn":            "urn:cerebro:writer:cloud_account:123",
					"account_entity_type":    "cloud.account",
					"account_label":          "123",
					"principal_urn":          "urn:cerebro:writer:aws_role:admin",
					"principal_entity_type":  "aws.role",
					"principal_label":        "admin",
					"permission_urn":         "urn:cerebro:writer:aws_policy:admin",
					"permission_entity_type": "aws.policy",
					"permission_label":       "admin",
					"reach_relation":         "can_reach",
					"access_relation":        "can_admin",
				},
			}},
		},
	}
	server := newMCPTestServerWithGraph(t, &stubRuntimeStore{}, graph)
	defer server.Close()

	neighborhoodResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.neighborhood",
			"arguments": map[string]any{
				"root_urn": "urn:cerebro:writer:asset:prod-db",
				"limit":    1000,
			},
		},
	})
	if neighborhoodResp["error"] != nil {
		t.Fatalf("graph.neighborhood error = %#v", neighborhoodResp["error"])
	}
	if graph.neighborhoodLimit != 50 {
		t.Fatalf("graph.neighborhood limit = %d, want 50", graph.neighborhoodLimit)
	}
	neighborhoodMetadata := neighborhoodResp["result"].(map[string]any)["structuredContent"].(map[string]any)["metadata"].(map[string]any)
	if neighborhoodMetadata["limit_applied"] != float64(50) {
		t.Fatalf("graph.neighborhood metadata = %#v", neighborhoodMetadata)
	}

	exactNeighborhoodResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.neighborhood",
			"arguments": map[string]any{
				"root_urn": "urn:cerebro:writer:asset:prod-db",
				"limit":    1,
			},
		},
	})
	if exactNeighborhoodResp["error"] != nil {
		t.Fatalf("graph.neighborhood exact error = %#v", exactNeighborhoodResp["error"])
	}
	exactNeighborhoodMetadata := exactNeighborhoodResp["result"].(map[string]any)["structuredContent"].(map[string]any)["metadata"].(map[string]any)
	if exactNeighborhoodMetadata["truncated"] != false {
		t.Fatalf("graph.neighborhood exact metadata = %#v", exactNeighborhoodMetadata)
	}

	impactResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro.graph.impact",
			"arguments": map[string]any{
				"kind":     "asset",
				"root_urn": "urn:cerebro:writer:asset:prod-db",
			},
		},
	})
	if impactResp["error"] != nil {
		t.Fatalf("graph.impact error = %#v", impactResp["error"])
	}
	if graph.neighborhoodLimit != 100 {
		t.Fatalf("graph.impact neighborhood limit = %d, want 100", graph.neighborhoodLimit)
	}
	impactMetadata := impactResp["result"].(map[string]any)["structuredContent"].(map[string]any)["metadata"].(map[string]any)
	if impactMetadata["limit_applied"] != float64(100) || impactMetadata["returned"] == float64(0) {
		t.Fatalf("graph.impact metadata = %#v", impactMetadata)
	}

	pathsResp, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.graph.paths",
			"arguments": map[string]any{"limit": 1000},
		},
	})
	if pathsResp["error"] != nil {
		t.Fatalf("graph.paths error = %#v", pathsResp["error"])
	}
	if len(graph.cypherRequests) != 2 || graph.cypherRequests[1].RowLimit != 100 {
		t.Fatalf("graph.paths cypher requests = %#v, want sample limit 100", graph.cypherRequests)
	}
	pathsMetadata := pathsResp["result"].(map[string]any)["structuredContent"].(map[string]any)["metadata"].(map[string]any)
	if pathsMetadata["limit_applied"] != float64(100) {
		t.Fatalf("graph.paths metadata = %#v", pathsMetadata)
	}
}

func TestMCPOriginProtocolAndNotificationHandling(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("bad origin POST error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want 403", resp.StatusCode)
	}

	response, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if response["error"] != nil {
		t.Fatalf("tools/list error = %#v", response["error"])
	}
	unsupportedReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("NewRequest unsupported: %v", err)
	}
	unsupportedReq.Header.Set("Content-Type", "application/json")
	unsupportedReq.Header.Set("Accept", "application/json, text/event-stream")
	unsupportedReq.Header.Set("Authorization", "Bearer test-key")
	unsupportedReq.Header.Set("MCP-Protocol-Version", "1999-01-01")
	unsupportedResp, err := server.Client().Do(unsupportedReq)
	if err != nil {
		t.Fatalf("unsupported protocol POST error = %v", err)
	}
	defer func() { _ = unsupportedResp.Body.Close() }()
	if unsupportedResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported protocol status = %d, want %d", unsupportedResp.StatusCode, http.StatusBadRequest)
	}

	notificationReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`))
	if err != nil {
		t.Fatalf("NewRequest notification: %v", err)
	}
	notificationReq.Header.Set("Content-Type", "application/json")
	notificationReq.Header.Set("Accept", "application/json, text/event-stream")
	notificationReq.Header.Set("Authorization", "Bearer test-key")
	notificationResp, err := server.Client().Do(notificationReq)
	if err != nil {
		t.Fatalf("notification POST error = %v", err)
	}
	_ = notificationResp.Body.Close()
	if notificationResp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status = %d, want 202", notificationResp.StatusCode)
	}
}

func TestMCPRouteUsesReadScope(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath, nil)
	if got := httpRoutePolicyForRequest(req).Scope; got != scopeCosmoSecurityRead {
		t.Fatalf("scopeForHTTPRequest(POST %s) = %q, want %q", mcpEndpointPath, got, scopeCosmoSecurityRead)
	}
}

func TestMCPMethodScopeGate(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath, nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, authContext{
		principal: authPrincipal{
			Name:     "scoped",
			TenantID: "writer",
			Scopes:   []string{"other.scope"},
		},
	}))
	response := app.handleMCPRequest(req, mcpJSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	})
	if response.Error == nil || response.Error.Message != "scope forbidden" {
		t.Fatalf("scoped tools/list response = %#v", response)
	}
}

func TestMCPMetadataDoesNotClaimUnknownTruncation(t *testing.T) {
	metadata := mcpResponseMetadata(1, 1, nil)
	if metadata["truncated"] != false {
		t.Fatalf("metadata truncated = %#v, want false in %#v", metadata["truncated"], metadata)
	}
	if _, ok := metadata["truncation_reason"]; ok {
		t.Fatalf("metadata should not include truncation_reason when truncation is unknown: %#v", metadata)
	}
	if metadata["more_results_possible"] != true {
		t.Fatalf("metadata more_results_possible = %#v, want true", metadata["more_results_possible"])
	}
}

func newMCPTestServer(t *testing.T, store *stubRuntimeStore) *httptest.Server {
	t.Helper()
	return newMCPTestServerWithGraph(t, store, nil)
}

func newMCPTestServerWithGraph(t *testing.T, store *stubRuntimeStore, graph *stubGraphStore) *httptest.Server {
	t.Helper()
	return newMCPTestServerWithGraphReasoning(t, store, graph, nil)
}

func newMCPTestServerWithGraphReasoning(t *testing.T, store *stubRuntimeStore, graph *stubGraphStore, llm graphagent.LLMClient) *httptest.Server {
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
	}, Dependencies{StateStore: store, GraphStore: graph, GraphAgentLLM: llm}, nil)
	return httptest.NewServer(app.Handler())
}

func postMCP(t *testing.T, server *httptest.Server, sessionID string, payload map[string]any) (map[string]any, string) {
	t.Helper()
	return postMCPWithAuthHeader(t, server, sessionID, payload, "Bearer test-key")
}

func postMCPWithoutAuth(t *testing.T, server *httptest.Server, payload map[string]any) (map[string]any, string) {
	t.Helper()
	return postMCPWithAuthHeader(t, server, "", payload, "")
}

func postMCPWithAuthHeader(t *testing.T, server *httptest.Server, sessionID string, payload map[string]any, authHeader string) (map[string]any, string) {
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
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
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
	if got := resp.Header.Get("MCP-Protocol-Version"); got != mcpProtocolVersion {
		t.Fatalf("MCP-Protocol-Version response header = %q, want %q", got, mcpProtocolVersion)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal MCP response %s: %v", raw, err)
	}
	return decoded, resp.Header.Get("Mcp-Session-Id")
}

func decodeMCPTelemetryPayload(t *testing.T, stderr string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		if payload["name"] == "cerebro.mcp.request" {
			return payload
		}
	}
	t.Fatalf("MCP telemetry event not found in stderr: %s", stderr)
	return nil
}
