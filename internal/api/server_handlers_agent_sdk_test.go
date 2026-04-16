package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
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

func TestWriteAgentSDKMCPResponseEncodingFailureReturnsInternalServerError(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()

	s.writeAgentSDKMCPResponse(w, agentSDKMCPResponse{
		JSONRPC: "2.0",
		ID:      "bad-1",
		Result:  map[string]float64{"value": math.NaN()},
	})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if got := w.Header().Get("MCP-Protocol-Version"); got != agentSDKMCPProtocolVersion {
		t.Fatalf("MCP-Protocol-Version = %q, want %q", got, agentSDKMCPProtocolVersion)
	}

	body := decodeJSON(t, w)
	if body["code"] != "internal_error" {
		t.Fatalf("code = %#v, want internal_error", body["code"])
	}
	if body["error"] != "internal server error" {
		t.Fatalf("error = %#v, want internal server error", body["error"])
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

func TestAgentSDKMCPReportToolEmitsProgress(t *testing.T) {
	s := newTestServer(t)
	server := httptest.NewServer(s)
	defer server.Close()

	sessionID := "session-progress"
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()

	streamReq, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+"/api/v1/mcp", nil)
	if err != nil {
		t.Fatalf("build mcp stream request: %v", err)
	}
	streamReq.Header.Set("Mcp-Session-Id", sessionID)
	streamResp, err := server.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("open mcp stream: %v", err)
	}
	defer func() { _ = streamResp.Body.Close() }()

	progressCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(streamResp.Body)
		var payload strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				payload.WriteString(strings.TrimPrefix(line, "data: "))
				continue
			}
			if line == "" {
				message := payload.String()
				payload.Reset()
				if strings.Contains(message, "notifications/progress") {
					progressCh <- message
					return
				}
			}
		}
	}()

	callResp := doAuthenticatedHTTP(t, server.URL, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "call-1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro_report",
			"arguments": map[string]any{
				"report_id":          "quality",
				"execution_mode":     "async",
				"materialize_result": false,
			},
			"_meta": map[string]any{
				"progressToken": "progress-1",
			},
		},
	}, map[string]string{"Mcp-Session-Id": sessionID})
	if callResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for report tool call, got %d: %s", callResp.Code, callResp.Body.String())
	}
	callBody := decodeJSON(t, callResp)
	callResult, ok := callBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %#v", callBody["result"])
	}
	structured, ok := callResult["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured content, got %#v", callResult["structuredContent"])
	}
	if structured["report_id"] != "quality" {
		t.Fatalf("expected report_id quality, got %#v", structured["report_id"])
	}

	select {
	case payload := <-progressCh:
		if !strings.Contains(payload, "\"progressToken\":\"progress-1\"") {
			t.Fatalf("expected progress token in payload, got %s", payload)
		}
		if !strings.Contains(payload, "\"report_id\":\"quality\"") {
			t.Fatalf("expected report id in payload, got %s", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP progress notification")
	}
}

func TestAgentSDKMCPReportToolEmitsSectionNotifications(t *testing.T) {
	s := newTestServer(t)
	server := httptest.NewServer(s)
	defer server.Close()

	sessionID := "session-sections"
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()

	streamReq, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+"/api/v1/mcp", nil)
	if err != nil {
		t.Fatalf("build mcp stream request: %v", err)
	}
	streamReq.Header.Set("Mcp-Session-Id", sessionID)
	streamResp, err := server.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("open mcp stream: %v", err)
	}
	defer func() { _ = streamResp.Body.Close() }()

	sectionCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(streamResp.Body)
		var payload strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				payload.WriteString(strings.TrimPrefix(line, "data: "))
				continue
			}
			if line == "" {
				message := payload.String()
				payload.Reset()
				if strings.Contains(message, "notifications/report_section") {
					sectionCh <- message
					return
				}
			}
		}
	}()

	callResp := doAuthenticatedHTTP(t, server.URL, http.MethodPost, "/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      "call-2",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "cerebro_report",
			"arguments": map[string]any{
				"report_id":          "quality",
				"execution_mode":     "async",
				"materialize_result": false,
			},
			"_meta": map[string]any{
				"progressToken": "progress-sections",
			},
		},
	}, map[string]string{"Mcp-Session-Id": sessionID})
	if callResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for report tool call, got %d: %s", callResp.Code, callResp.Body.String())
	}

	select {
	case payload := <-sectionCh:
		if !strings.Contains(payload, "\"progressToken\":\"progress-sections\"") {
			t.Fatalf("expected progress token in section payload, got %s", payload)
		}
		if !strings.Contains(payload, "\"section\"") {
			t.Fatalf("expected section payload in notification, got %s", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP report_section notification")
	}
}

func TestAgentSDKProtectedResourceMetadataIsPublic(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIAuthorizationServers = []string{"https://auth.example.com"}
	s := NewServer(a)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for protected resource metadata, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got := body["resource"]; got != "https://api.example.com" {
		t.Fatalf("expected resource URL, got %#v", got)
	}
	if got := body["mcp_protocol_version"]; got != agentSDKMCPProtocolVersion {
		t.Fatalf("expected MCP protocol version %q, got %#v", agentSDKMCPProtocolVersion, got)
	}
}

func TestAgentSDKUnauthorizedSetsProtectedResourceChallenge(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APICredentials = map[string]apiauth.Credential{
		"admin-key": apiauth.DefaultCredentialForAPIKey("admin-key", "admin-user"),
	}
	a.Config.APIKeys = map[string]string{"admin-key": "admin-user"}
	if err := a.RBAC.CreateUser(&auth.User{ID: "admin-user", Email: "admin@example.com", Name: "Admin", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	s := NewServer(a)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-sdk/tools", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing SDK auth, got %d: %s", resp.Code, resp.Body.String())
	}
	challenge := resp.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource\"") {
		t.Fatalf("expected protected-resource challenge, got %q", challenge)
	}
}

func TestAgentSDKCredentialScopesRestrictGenericAndTypedCalls(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APICredentials = map[string]apiauth.Credential{
		"scoped-key": {
			ID:              "cred-scoped",
			Name:            "Scoped SDK Client",
			UserID:          "admin-user",
			Kind:            "sdk_api_key",
			ClientID:        "sdk-client-scope",
			Scopes:          []string{"sdk.context.read"},
			Enabled:         true,
			RateLimitBucket: "cred-scoped",
		},
	}
	a.Config.APIKeys = map[string]string{"scoped-key": "admin-user"}
	if err := a.RBAC.CreateUser(&auth.User{ID: "admin-user", Email: "admin@example.com", Name: "Admin", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	a.SecurityGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	a.SecurityGraph.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	s := NewServer(a)

	contextReq := newAuthenticatedRequest(t, http.MethodGet, "/api/v1/agent-sdk/context/service:payments", nil, "scoped-key")
	contextResp := httptest.NewRecorder()
	s.ServeHTTP(contextResp, contextReq)
	if contextResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for scoped context read, got %d: %s", contextResp.Code, contextResp.Body.String())
	}

	typedClaimReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/agent-sdk/claims", map[string]any{
		"subject_id":   "customer:acme",
		"predicate":    "healthy",
		"object_value": "true",
	}, "scoped-key")
	typedClaimResp := httptest.NewRecorder()
	s.ServeHTTP(typedClaimResp, typedClaimReq)
	if typedClaimResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for typed claim with missing scope, got %d: %s", typedClaimResp.Code, typedClaimResp.Body.String())
	}
	if !strings.Contains(typedClaimResp.Body.String(), "insufficient_scope") {
		t.Fatalf("expected insufficient_scope response, got %s", typedClaimResp.Body.String())
	}

	genericClaimReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/agent-sdk/tools/cerebro_claim:call", map[string]any{
		"subject_id":   "customer:acme",
		"predicate":    "healthy",
		"object_value": "true",
	}, "scoped-key")
	genericClaimResp := httptest.NewRecorder()
	s.ServeHTTP(genericClaimResp, genericClaimReq)
	if genericClaimResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for generic claim with missing scope, got %d: %s", genericClaimResp.Code, genericClaimResp.Body.String())
	}
}

func TestAdminAgentSDKCredentialLifecycle(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APICredentialStateFile = filepath.Join(t.TempDir(), "managed-credentials.json")
	a.Config.APICredentials = map[string]apiauth.Credential{
		"admin-key": {
			ID:              "cred-admin",
			Name:            "Admin Control Plane",
			UserID:          "admin-user",
			Kind:            "api_key",
			Enabled:         true,
			RateLimitBucket: "cred-admin",
		},
	}
	a.Config.APIKeys = map[string]string{"admin-key": "admin-user"}
	if err := a.ConfigureManagedAPICredentialStore(a.Config.APICredentialStateFile); err != nil {
		t.Fatalf("configure managed credential store: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{ID: "admin-user", Email: "admin@example.com", Name: "Admin", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	s := NewServer(a)

	req := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/admin/agent-sdk/credentials", map[string]any{
		"name":   "SDK Worker",
		"scopes": []string{"sdk.context.read", "sdk.invoke"},
	}, "admin-key")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for credential create, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	apiKey, _ := body["api_key"].(string)
	credential, _ := body["credential"].(map[string]any)
	credentialID, _ := credential["id"].(string)
	if apiKey == "" || credentialID == "" {
		t.Fatalf("expected credential id and raw api_key, got %#v", body)
	}

	listReq := newAuthenticatedRequest(t, http.MethodGet, "/api/v1/admin/agent-sdk/credentials", nil, "admin-key")
	listResp := httptest.NewRecorder()
	s.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for credential list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeJSON(t, listResp)
	if got := listBody["count"]; got != float64(2) {
		t.Fatalf("expected two credentials after create, got %#v", got)
	}

	rotateReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/"+credentialID+":rotate", map[string]any{}, "admin-key")
	rotateResp := httptest.NewRecorder()
	s.ServeHTTP(rotateResp, rotateReq)
	if rotateResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for credential rotate, got %d: %s", rotateResp.Code, rotateResp.Body.String())
	}
	rotateBody := decodeJSON(t, rotateResp)
	rotatedKey, _ := rotateBody["api_key"].(string)
	if rotatedKey == "" || rotatedKey == apiKey {
		t.Fatalf("expected rotated api_key to differ, got %#v", rotateBody["api_key"])
	}

	revokeReq := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/"+credentialID+":revoke", map[string]any{
		"reason": "done",
	}, "admin-key")
	revokeResp := httptest.NewRecorder()
	s.ServeHTTP(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for credential revoke, got %d: %s", revokeResp.Code, revokeResp.Body.String())
	}

	revokedUseReq := newAuthenticatedRequest(t, http.MethodGet, "/api/v1/agent-sdk/context/service:payments", nil, rotatedKey)
	revokedUseResp := httptest.NewRecorder()
	s.ServeHTTP(revokedUseResp, revokedUseReq)
	if revokedUseResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked managed credential, got %d: %s", revokedUseResp.Code, revokedUseResp.Body.String())
	}
}

func TestAgentSDKClaimWriteEnrichesAttributionMetadata(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APICredentials = map[string]apiauth.Credential{
		"sdk-key": {
			ID:              "cred-sdk",
			Name:            "SDK Test Client",
			UserID:          "writer-user",
			Kind:            "sdk_client",
			ClientID:        "client-123",
			Enabled:         true,
			RateLimitBucket: "client-123",
		},
	}
	a.Config.APIKeys = map[string]string{"sdk-key": "writer-user"}
	if err := a.RBAC.CreateUser(&auth.User{
		ID:      "writer-user",
		Email:   "writer@example.com",
		Name:    "Writer",
		RoleIDs: []string{"admin"},
	}); err != nil {
		t.Fatalf("create writer user: %v", err)
	}

	a.SecurityGraph.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	a.SecurityGraph.AddNode(&graph.Node{ID: "evidence:signal", Kind: graph.NodeKindEvidence, Name: "Signal"})
	s := NewServer(a)

	req := newAuthenticatedRequest(t, http.MethodPost, "/api/v1/agent-sdk/claims", map[string]any{
		"subject_id":   "customer:acme",
		"predicate":    "churning",
		"object_value": "true",
		"evidence_ids": []string{"evidence:signal"},
	}, "sdk-key")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for enriched claim write, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	claimID, _ := body["claim_id"].(string)
	if claimID == "" {
		t.Fatalf("expected claim_id in response, got %#v", body)
	}
	node, ok := a.SecurityGraph.GetNode(claimID)
	if !ok || node == nil {
		t.Fatalf("expected stored claim node %q", claimID)
	}
	if node.Properties["api_credential_id"] != "cred-sdk" {
		t.Fatalf("expected api_credential_id cred-sdk, got %#v", node.Properties["api_credential_id"])
	}
	if node.Properties["sdk_client_id"] != "client-123" {
		t.Fatalf("expected sdk_client_id client-123, got %#v", node.Properties["sdk_client_id"])
	}
	if node.Properties["agent_sdk_tool_id"] != "cerebro_claim" {
		t.Fatalf("expected agent_sdk_tool_id cerebro_claim, got %#v", node.Properties["agent_sdk_tool_id"])
	}
	if node.Properties["traceparent"] != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00" {
		t.Fatalf("expected traceparent to be preserved, got %#v", node.Properties["traceparent"])
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

func doAuthenticatedHTTP(t *testing.T, baseURL, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal authenticated http body: %v", err)
	}
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build authenticated http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute authenticated http request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	recorder := httptest.NewRecorder()
	recorder.Code = resp.StatusCode
	for key, values := range resp.Header {
		for _, value := range values {
			recorder.Header().Add(key, value)
		}
	}
	_, _ = recorder.Body.ReadFrom(resp.Body)
	return recorder
}
