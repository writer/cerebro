package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

func TestAgentSDKToolsListAndGenericInvoke(t *testing.T) {
	s := newTestServer(t)
	s.app.SecurityGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})

	listResp := do(t, s, http.MethodGet, "/api/v1/agent-sdk/tools", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for tools list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var tools []map[string]any
	if err := json.Unmarshal(listResp.Body.Bytes(), &tools); err != nil {
		t.Fatalf("decode tools list: %v", err)
	}
	if !containsAgentSDKTool(tools, "cerebro_check") {
		t.Fatalf("expected cerebro_check in tools list, got %#v", tools)
	}
	if !containsAgentSDKTool(tools, "cerebro_claim") {
		t.Fatalf("expected cerebro_claim in tools list, got %#v", tools)
	}

	callResp := do(t, s, http.MethodPost, "/api/v1/agent-sdk/tools/cerebro_context:call", map[string]any{
		"entity": "service:payments",
	})
	if callResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for generic tool invoke, got %d: %s", callResp.Code, callResp.Body.String())
	}
	body := decodeJSON(t, callResp)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %#v", body["result"])
	}
	if result["entity_id"] != "service:payments" {
		t.Fatalf("expected entity_id service:payments, got %#v", result["entity_id"])
	}
}

func TestAgentSDKTypedEndpoints(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	g.AddNode(&graph.Node{ID: "evidence:signal", Kind: graph.NodeKindEvidence, Name: "Signal"})

	s.app.Policy.AddPolicy(&policy.Policy{
		ID:       "policy.refund.approval",
		Name:     "Refund approval required",
		Effect:   "forbid",
		Action:   "refund.create",
		Resource: "business::refund",
	})

	contextResp := do(t, s, http.MethodGet, "/api/v1/agent-sdk/context/service:payments?sections=risk,relationships", nil)
	if contextResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for context endpoint, got %d: %s", contextResp.Code, contextResp.Body.String())
	}
	contextBody := decodeJSON(t, contextResp)
	if contextBody["entity_id"] != "service:payments" {
		t.Fatalf("expected context entity_id service:payments, got %#v", contextBody["entity_id"])
	}

	checkResp := do(t, s, http.MethodPost, "/api/v1/agent-sdk/check", map[string]any{
		"principal": map[string]any{"id": "agent:sales-assistant"},
		"action":    "refund.create",
		"resource":  map[string]any{"type": "refund", "id": "refund:123"},
		"context":   map[string]any{"amount": 6500},
	})
	if checkResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for check endpoint, got %d: %s", checkResp.Code, checkResp.Body.String())
	}
	checkBody := decodeJSON(t, checkResp)
	if checkBody["decision"] != "deny" {
		t.Fatalf("expected deny decision, got %#v", checkBody["decision"])
	}

	claimResp := do(t, s, http.MethodPost, "/api/v1/agent-sdk/claims", map[string]any{
		"subject_id":    "customer:acme",
		"predicate":     "churning",
		"object_value":  "true",
		"status":        "asserted",
		"evidence_ids":  []string{"evidence:signal"},
		"source_system": "agent",
	})
	if claimResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for claim write, got %d: %s", claimResp.Code, claimResp.Body.String())
	}
	claimBody := decodeJSON(t, claimResp)
	if _, ok := claimBody["claim_id"].(string); !ok {
		t.Fatalf("expected claim_id, got %#v", claimBody["claim_id"])
	}
}

func TestAgentSDKMCPToolsAndResources(t *testing.T) {
	s := newTestServer(t)
	s.app.SecurityGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})

	initialize := do(t, s, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "init-1",
		"method":  "initialize",
	})
	if initialize.Code != http.StatusOK {
		t.Fatalf("expected 200 for initialize, got %d: %s", initialize.Code, initialize.Body.String())
	}
	initBody := decodeJSON(t, initialize)
	result, ok := initBody["result"].(map[string]any)
	if !ok || result["protocolVersion"] != agentSDKMCPProtocolVersion {
		t.Fatalf("expected MCP protocol version %q, got %#v", agentSDKMCPProtocolVersion, initBody["result"])
	}
	if sessionID := initialize.Header().Get("Mcp-Session-Id"); strings.TrimSpace(sessionID) == "" {
		t.Fatal("expected Mcp-Session-Id response header")
	}

	toolsList := do(t, s, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "tools-1",
		"method":  "tools/list",
	})
	if toolsList.Code != http.StatusOK {
		t.Fatalf("expected 200 for tools/list, got %d: %s", toolsList.Code, toolsList.Body.String())
	}
	toolsBody := decodeJSON(t, toolsList)
	toolsResult, ok := toolsBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %#v", toolsBody["result"])
	}
	tools, ok := toolsResult["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected tools array, got %#v", toolsResult["tools"])
	}

	callResp := do(t, s, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "call-1",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cerebro_context",
			"arguments": map[string]any{"entity": "service:payments"},
		},
	})
	if callResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for tools/call, got %d: %s", callResp.Code, callResp.Body.String())
	}
	callBody := decodeJSON(t, callResp)
	callResult, ok := callBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected call result object, got %#v", callBody["result"])
	}
	structured, ok := callResult["structuredContent"].(map[string]any)
	if !ok || structured["entity_id"] != "service:payments" {
		t.Fatalf("expected structuredContent with entity_id, got %#v", callResult["structuredContent"])
	}

	resourceResp := do(t, s, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "resource-1",
		"method":  "resources/read",
		"params":  map[string]any{"uri": "cerebro://schema/node-kinds"},
	})
	if resourceResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for resources/read, got %d: %s", resourceResp.Code, resourceResp.Body.String())
	}
	resourceBody := decodeJSON(t, resourceResp)
	resourceResult, ok := resourceBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected resource result object, got %#v", resourceBody["result"])
	}
	contents, ok := resourceResult["contents"].([]any)
	if !ok || len(contents) != 1 {
		t.Fatalf("expected one content entry, got %#v", resourceResult["contents"])
	}
	firstContent, ok := contents[0].(map[string]any)
	if !ok || !strings.Contains(firstContent["text"].(string), "\"kind\"") {
		t.Fatalf("expected JSON schema text payload, got %#v", contents[0])
	}
}

func TestAgentSDKInvokeHonorsPerToolPermissions(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"viewer-key": "viewer-user"}
	if err := a.RBAC.CreateUser(&auth.User{
		ID:      "viewer-user",
		Email:   "viewer@example.com",
		Name:    "Viewer",
		RoleIDs: []string{"viewer"},
	}); err != nil {
		t.Fatalf("create viewer user: %v", err)
	}

	a.SecurityGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	s := NewServer(a)

	listReq := newAuthenticatedRequest(t, http.MethodGet, "/api/v1/agent-sdk/tools", nil, "viewer-key")
	listResp := httptest.NewRecorder()
	s.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated tools list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var tools []map[string]any
	if err := json.Unmarshal(listResp.Body.Bytes(), &tools); err != nil {
		t.Fatalf("decode authenticated tools list: %v", err)
	}
	if !containsAgentSDKTool(tools, "cerebro_context") {
		t.Fatalf("expected cerebro_context to be visible to viewer, got %#v", tools)
	}
	if containsAgentSDKTool(tools, "cerebro_claim") {
		t.Fatalf("did not expect cerebro_claim to be visible to viewer, got %#v", tools)
	}

	contextReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/agent-sdk/tools/cerebro_context:call", map[string]any{
		"entity": "service:payments",
	}, "viewer-key")
	contextResp := httptest.NewRecorder()
	s.ServeHTTP(contextResp, contextReq)
	if contextResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer context invoke, got %d: %s", contextResp.Code, contextResp.Body.String())
	}

	claimReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/agent-sdk/tools/cerebro_claim:call", map[string]any{
		"subject_id":   "service:payments",
		"predicate":    "healthy",
		"object_value": "true",
	}, "viewer-key")
	claimResp := httptest.NewRecorder()
	s.ServeHTTP(claimResp, claimReq)
	if claimResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer claim invoke, got %d: %s", claimResp.Code, claimResp.Body.String())
	}
}

func containsAgentSDKTool(tools []map[string]any, id string) bool {
	for _, tool := range tools {
		if toolID, _ := tool["id"].(string); toolID == id {
			return true
		}
		if name, _ := tool["name"].(string); name == id {
			return true
		}
	}
	return false
}

func newAuthenticatedRequest(t *testing.T, method, path string, body any, apiKey string) *http.Request {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal authenticated request body: %v", err)
		}
		reader = bytes.NewReader(payload)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}
