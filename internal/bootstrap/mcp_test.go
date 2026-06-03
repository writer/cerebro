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
	for _, want := range []string{"cerebro.health", "cerebro.version", "cerebro.source_runtimes.list", "cerebro.findings.list", "cerebro.findings.get", "cerebro.assets.search", "cerebro.risk.summary", "cerebro.graph.neighborhood"} {
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
