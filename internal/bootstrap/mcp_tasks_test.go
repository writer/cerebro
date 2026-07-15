package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/mcpoperations"
	"github.com/writer/cerebro/internal/ports"
)

func TestMCPInventoryCoversEveryToolDefinition(t *testing.T) {
	definitions := map[string]struct{}{}
	for _, tool := range mcpTools() {
		definitions[tool.Name] = struct{}{}
		if _, ok := mcpoperations.Lookup(tool.Name); !ok {
			t.Fatalf("tool definition %q is missing from the operation inventory", tool.Name)
		}
	}
	for _, operation := range mcpoperations.Operations() {
		if _, ok := definitions[operation.Name]; !ok {
			t.Fatalf("operation inventory contains undefined tool %q", operation.Name)
		}
	}
}

func TestMCPBoolArgParsesJSONNumbers(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "0"},
		{value: "0.0"},
		{value: "0e0"},
		{value: "-0"},
		{value: "invalid"},
		{value: "1", want: true},
		{value: "-1", want: true},
		{value: "0.5", want: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := mcpBoolArg(map[string]any{"value": json.Number(test.value)}, "value"); got != test.want {
				t.Fatalf("mcpBoolArg(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestMCPTaskProfileIsBoundedAndPreservesDefaultTools(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()

	taskResponse := postMCPWithTaskProfile(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	tools := taskResponse["result"].(map[string]any)["tools"].([]any)
	want := map[string]bool{
		"cerebro.health":          true,
		"cerebro.version":         true,
		"cerebro.risk.explain":    true,
		"cerebro.evidence.packet": true,
		"cerebro.sources.health":  true,
		"cerebro.action.plan":     true,
	}
	if len(tools) != len(want) {
		t.Fatalf("task profile tool count = %d, want %d: %#v", len(tools), len(want), tools)
	}
	for _, raw := range tools {
		name := raw.(map[string]any)["name"].(string)
		if !want[name] {
			t.Fatalf("task profile exposed unexpected tool %q", name)
		}
	}

	expertCall := postMCPWithTaskProfile(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.graph.reason",
			"arguments": map[string]any{"question": "show paths"},
		},
	})
	if expertCall["result"].(map[string]any)["isError"] != true {
		t.Fatalf("task profile expert call = %#v, want tool error", expertCall)
	}

	defaultResponse, _ := postMCP(t, server, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/list",
	})
	defaultTools := defaultResponse["result"].(map[string]any)["tools"].([]any)
	if !mcpToolListContains(defaultTools, "cerebro.graph.reason") {
		t.Fatalf("default MCP profile no longer exposes expert tools")
	}
}

func TestMCPTaskToolsReturnExplicitStateWithoutExecution(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "aws", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:        "finding-1",
				TenantID:  "writer",
				RuntimeID: "writer-runtime",
				RuleID:    "public-access",
				Title:     "Public access",
				Severity:  "HIGH",
				Status:    "open",
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}
	server := newMCPTestServer(t, store)
	defer server.Close()

	cases := []struct {
		name      string
		tool      string
		arguments map[string]any
		nextState string
	}{
		{name: "risk explanation", tool: "cerebro.risk.explain", arguments: map[string]any{"finding_id": "finding-1", "skip_graph": true}},
		{name: "evidence packet", tool: "cerebro.evidence.packet", arguments: map[string]any{"question": "What evidence supports this review?", "action_stage": "dry_run"}},
		{name: "source health", tool: "cerebro.sources.health", arguments: map[string]any{}},
		{name: "action plan", tool: "cerebro.action.plan", arguments: map[string]any{"runtime_ids": []string{"writer-runtime"}}, nextState: "proposal"},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := postMCPWithTaskProfile(t, server, map[string]any{
				"jsonrpc": "2.0",
				"id":      index + 1,
				"method":  "tools/call",
				"params":  map[string]any{"name": test.tool, "arguments": test.arguments},
			})
			result := response["result"].(map[string]any)
			if result["isError"] == true {
				t.Fatalf("%s tool error = %#v", test.tool, result)
			}
			content := result["structuredContent"].(map[string]any)
			if content["state"] != mcpoperations.TaskStateComplete && content["state"] != mcpoperations.TaskStatePartial && content["state"] != mcpoperations.TaskStateBlocked {
				t.Fatalf("%s state = %#v", test.tool, content["state"])
			}
			if content["would_mutate"] != false {
				t.Fatalf("%s would_mutate = %#v, want false", test.tool, content["would_mutate"])
			}
			if _, ok := content["dependencies"].([]any); !ok {
				t.Fatalf("%s dependencies = %#v", test.tool, content["dependencies"])
			}
			if _, ok := content["data"].(map[string]any); !ok {
				t.Fatalf("%s data = %#v", test.tool, content["data"])
			}
			if test.nextState != "" && content["next_state"] != test.nextState {
				t.Fatalf("%s next_state = %#v, want %q", test.tool, content["next_state"], test.nextState)
			}
		})
	}

	executeResponse := postMCPWithTaskProfile(t, server, map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro.evidence.packet",
			"arguments": map[string]any{"question": "Execute this change", "action_stage": "execute"},
		},
	})
	if executeResponse["result"].(map[string]any)["isError"] != true {
		t.Fatalf("execute stage response = %#v, want tool error", executeResponse)
	}
}

func TestMCPTaskTelemetryRecordsOperationStateWithoutPrompt(t *testing.T) {
	server := newMCPTestServer(t, &stubRuntimeStore{})
	defer server.Close()
	secretPrompt := "private-review-question-4471"

	stderr := captureBootstrapStderr(t, func() {
		response := postMCPWithTaskProfile(t, server, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "cerebro.evidence.packet",
				"arguments": map[string]any{"question": secretPrompt},
			},
		})
		if response["result"].(map[string]any)["isError"] == true {
			t.Fatalf("evidence packet tool error = %#v", response)
		}
	})

	if strings.Contains(stderr, secretPrompt) || strings.Contains(stderr, `"arguments"`) || strings.Contains(stderr, `"question"`) {
		t.Fatalf("task telemetry recorded prompt content: %s", stderr)
	}
	payload := decodeMCPTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"mcp.tool":                "cerebro.evidence.packet",
		"mcp.tool_classification": "task-level",
		"mcp.tool_behavior":       "read",
		"mcp.tool_owner":          "agent-platform",
		"mcp.task":                true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func postMCPWithTaskProfile(t *testing.T, server *httptest.Server, payload map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create MCP request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Set("X-Cerebro-MCP-Toolsets", "task")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST MCP request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read MCP response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST MCP status = %d body = %s", response.StatusCode, raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode MCP response %s: %v", raw, err)
	}
	return decoded
}

func mcpToolListContains(tools []any, name string) bool {
	for _, raw := range tools {
		if raw.(map[string]any)["name"] == name {
			return true
		}
	}
	return false
}
