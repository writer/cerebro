package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHandleAgentPlatformContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-platform/contract", nil)

	(&App{}).handleAgentPlatformContract(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var contract agentplatform.Contract
	if err := json.Unmarshal(recorder.Body.Bytes(), &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if contract.Version != agentplatform.ContractVersion {
		t.Fatalf("version = %q, want %q", contract.Version, agentplatform.ContractVersion)
	}
	if len(contract.Capabilities) == 0 {
		t.Fatal("contract response missing capabilities")
	}
	if len(contract.ConnectorInfrastructure.OAuthSurfaces) == 0 {
		t.Fatal("contract response missing connector OAuth surfaces")
	}
	if contract.A2A.JSONRPCPath == "" || contract.EventSubscriptions.Resource == "" || contract.Idempotency.Header == "" {
		t.Fatalf("contract response missing public protocol contracts: %+v", contract)
	}
}

func TestHandleA2AAgentCard(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil)
	request.Host = "api.example.com"

	(&App{}).handleA2AAgentCard(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if recorder.Header().Get("Cache-Control") == "" {
		t.Fatal("agent card response missing cache-control")
	}
	var card agentplatform.A2AAgentCard
	if err := json.Unmarshal(recorder.Body.Bytes(), &card); err != nil {
		t.Fatalf("decode card: %v", err)
	}
	if card.Version != agentplatform.ContractVersion {
		t.Fatalf("version = %q, want %q", card.Version, agentplatform.ContractVersion)
	}
	if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != "http://api.example.com/api/v1/a2a" {
		t.Fatalf("card interfaces = %+v", card.SupportedInterfaces)
	}
}

func TestHandleA2AJSONRPCSendMessage(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/a2a", bytes.NewReader([]byte(`{
		"jsonrpc": "2.0",
		"id": "request-1",
		"method": "SendMessage",
		"params": {
			"message": {
				"role": "ROLE_USER",
				"parts": [{"text": "List public contracts"}],
				"messageId": "message-1"
			}
		}
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST A2A: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var response agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error != nil || response.Result == nil || response.ID != "request-1" {
		t.Fatalf("A2A response = %+v, want direct message result", response)
	}
}

func TestHandleA2AJSONRPCEvidencePacketTask(t *testing.T) {
	store := newA2ATestJobStore()
	app := New(agentPlatformAuthConfig(), Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{
		"jsonrpc": "2.0",
		"id": "request-1",
		"method": "SendMessage",
		"params": {
			"message": {
				"role": "ROLE_USER",
				"parts": [{"text": "Triage this alert before an agent run"}],
				"messageId": "message-1"
			},
			"metadata": {
				"skillId": "agent-evidence-packet",
				"evidencePacket": {
					"tenant_id": "writer",
					"scope_urn": "urn:cerebro:writer:finding:alert-1",
					"capability_ids": ["graph-reasoning"],
					"action": {"stage": "recommend"}
				}
			}
		}
	}`)
	resp := postA2AJSONRPC(t, server, "operator-key", "task-key-1", body)
	defer func() { _ = resp.Body.Close() }()
	var response agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error != nil || response.Result == nil {
		t.Fatalf("A2A response = %+v, want completed task", response)
	}
	task := decodeA2ATestTaskResult(t, response.Result, "task")
	if task.Status.State != agentplatform.A2ATaskStateCompleted || len(task.Artifacts) != 1 {
		t.Fatalf("task = %+v, want completed task with artifact", task)
	}
	packet := decodeA2ATestEvidencePacket(t, task.Artifacts[0].Parts[0].Data)
	if packet.TenantID != "writer" || packet.ActorID != "tester" || !packet.Preflight.Enabled {
		t.Fatalf("packet context/preflight = %+v, want authenticated enabled packet", packet)
	}
	if len(packet.VerifierResults) == 0 || len(packet.RequiredWriteBack) == 0 {
		t.Fatalf("packet missing verifier or writeback guidance: %+v", packet)
	}

	replay := postA2AJSONRPC(t, server, "operator-key", "task-key-1", body)
	defer func() { _ = replay.Body.Close() }()
	var replayResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(replay.Body).Decode(&replayResponse); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	replayTask := decodeA2ATestTaskResult(t, replayResponse.Result, "task")
	if replayTask.ID != task.ID || store.createCount != 1 {
		t.Fatalf("replay task id/create count = %q/%d, want %q/1", replayTask.ID, store.createCount, task.ID)
	}
}

func TestHandleA2AJSONRPCGetAndListTasks(t *testing.T) {
	store := newA2ATestJobStore()
	app := New(agentPlatformAuthConfig(), Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createBody := []byte(`{
		"jsonrpc": "2.0",
		"id": "create",
		"method": "SendMessage",
		"params": {
			"message": {
				"role": "ROLE_USER",
				"contextId": "ctx-1",
				"parts": [{"text": "Build an evidence packet"}],
				"messageId": "message-1"
			},
			"metadata": {
				"skillId": "agent-evidence-packet",
				"evidencePacket": {
					"tenant_id": "writer",
					"scope_urn": "urn:cerebro:writer:finding:alert-1",
					"capability_ids": ["graph-reasoning"]
				}
			}
		}
	}`)
	createResp := postA2AJSONRPC(t, server, "operator-key", "task-key-2", createBody)
	defer func() { _ = createResp.Body.Close() }()
	var createResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(createResp.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	created := decodeA2ATestTaskResult(t, createResponse.Result, "task")

	getBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "get",
		"method":  "GetTask",
		"params": map[string]any{
			"id":            created.ID,
			"historyLength": 0,
		},
	})
	if err != nil {
		t.Fatalf("marshal get body: %v", err)
	}
	getResp := postA2AJSONRPC(t, server, "operator-key", "", getBody)
	defer func() { _ = getResp.Body.Close() }()
	var getResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(getResp.Body).Decode(&getResponse); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	got := decodeA2ATestTaskResult(t, getResponse.Result, "")
	if got.ID != created.ID || len(got.History) != 0 || len(got.Artifacts) != 1 {
		t.Fatalf("GetTask result = %+v, want same task without history", got)
	}

	listResp := postA2AJSONRPC(t, server, "operator-key", "", []byte(`{"jsonrpc":"2.0","id":"list","method":"ListTasks","params":{"limit":10}}`))
	defer func() { _ = listResp.Body.Close() }()
	var listResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(listResp.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	var list struct {
		Tasks     []agentplatform.A2ATask `json:"tasks"`
		TotalSize int                     `json:"totalSize"`
	}
	decodeA2ATestResult(t, listResponse.Result, &list)
	if list.TotalSize != 1 || len(list.Tasks) != 1 || list.Tasks[0].ID != created.ID {
		t.Fatalf("ListTasks result = %+v, want created task", list)
	}
}

func TestHandleA2AJSONRPCGetTaskHidesOtherTenantTasks(t *testing.T) {
	store := newA2ATestJobStore()
	cfg := agentPlatformAuthConfig()
	cfg.Auth.APICredentials = append(cfg.Auth.APICredentials, config.APICredential{
		ID:        "other-credential",
		ClientID:  "other-client",
		Key:       "other-key",
		Principal: "other-tester",
		TenantID:  "other",
	})
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createResp := postA2AJSONRPC(t, server, "operator-key", "task-key-3", []byte(`{
		"jsonrpc": "2.0",
		"id": "create",
		"method": "SendMessage",
		"params": {
			"message": {
				"role": "ROLE_USER",
				"parts": [{"text": "Build an evidence packet"}],
				"messageId": "message-1"
			},
			"metadata": {
				"skillId": "agent-evidence-packet",
				"evidencePacket": {
					"tenant_id": "writer",
					"scope_urn": "urn:cerebro:writer:finding:alert-1",
					"capability_ids": ["graph-reasoning"]
				}
			}
		}
	}`))
	defer func() { _ = createResp.Body.Close() }()
	var createResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(createResp.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	created := decodeA2ATestTaskResult(t, createResponse.Result, "task")
	getBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "get",
		"method":  "GetTask",
		"params":  map[string]any{"id": created.ID},
	})
	if err != nil {
		t.Fatalf("marshal get body: %v", err)
	}
	getResp := postA2AJSONRPC(t, server, "other-key", "", getBody)
	defer func() { _ = getResp.Body.Close() }()
	var getResponse agentplatform.A2AJSONRPCResponse
	if err := json.NewDecoder(getResp.Body).Decode(&getResponse); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResponse.Error == nil || getResponse.Error.Code != -32001 {
		t.Fatalf("cross-tenant GetTask response = %+v, want TaskNotFoundError", getResponse)
	}
}

func TestHandleA2AJSONRPCUnsupportedMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/a2a", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":"request-2","method":"SendStreamingMessage"}`)))

	(&App{}).handleA2AJSONRPC(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var response agentplatform.A2AJSONRPCResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error == nil || response.Error.Code != -32004 {
		t.Fatalf("response = %+v, want unsupported operation error", response)
	}
}

func TestHandleEventSubscriptionContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/event-subscriptions/contract", nil)

	(&App{}).handleEventSubscriptionContract(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var contract agentplatform.EventSubscriptionContract
	if err := json.Unmarshal(recorder.Body.Bytes(), &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if contract.Delivery.Transport != "https_webhook" || len(contract.EventTypes) == 0 {
		t.Fatalf("event subscription contract = %+v", contract)
	}
}

func TestHandleIdempotencyContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/idempotency-contract", nil)

	(&App{}).handleIdempotencyContract(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var contract agentplatform.IdempotencyContract
	if err := json.Unmarshal(recorder.Body.Bytes(), &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if contract.Header != "Idempotency-Key" || contract.ConflictStatus != http.StatusConflict {
		t.Fatalf("idempotency contract = %+v", contract)
	}
}

func TestHandleAgentPlatformSecurityControlPlane(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-platform/security-control-plane", nil)

	(&App{}).handleAgentPlatformSecurityControlPlane(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var controlPlane agentplatform.SecurityControlPlane
	if err := json.Unmarshal(recorder.Body.Bytes(), &controlPlane); err != nil {
		t.Fatalf("decode control plane: %v", err)
	}
	if controlPlane.Version != agentplatform.ContractVersion {
		t.Fatalf("version = %q, want %q", controlPlane.Version, agentplatform.ContractVersion)
	}
	if len(controlPlane.AgentProfiles) == 0 || len(controlPlane.VerifierLayer) == 0 || len(controlPlane.ActionLadder) == 0 {
		t.Fatalf("control plane missing core registries: %+v", controlPlane)
	}
}

func TestHandleAgentPlatformCapabilities(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-platform/capabilities?domain_id=connectors&default_on=true", nil)

	(&App{}).handleAgentPlatformCapabilities(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var registry agentplatform.CapabilityRegistry
	if err := json.Unmarshal(recorder.Body.Bytes(), &registry); err != nil {
		t.Fatalf("decode registry: %v", err)
	}
	if registry.Version != agentplatform.ContractVersion {
		t.Fatalf("version = %q, want %q", registry.Version, agentplatform.ContractVersion)
	}
	if registry.Totals.Capabilities == 0 {
		t.Fatal("registry response missing capabilities")
	}
	for _, capability := range registry.Capabilities {
		if capability.DomainID != "connectors" || !capability.DefaultOn {
			t.Fatalf("capability does not match filter: %+v", capability)
		}
	}
}

func TestHandleAgentPlatformCapabilitiesRejectsBadFilter(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-platform/capabilities?default_on=maybe", nil)

	(&App{}).handleAgentPlatformCapabilities(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestHandleAgentPlatformCapabilityDecision(t *testing.T) {
	body := []byte(`{"capability_id":"grc-ask","tenant_id":"tenant-1","actor_id":"actor-1","requested_scopes":["cosmo.security.read"]}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-platform/capability-decisions", bytes.NewReader(body))

	(&App{}).handleAgentPlatformCapabilityDecision(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var decision agentplatform.CapabilityDecision
	if err := json.Unmarshal(recorder.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if !decision.Enabled {
		t.Fatalf("decision enabled = false, blockers = %+v", decision.Blockers)
	}
	if decision.CapabilityID != "grc-ask" || decision.TenantID != "tenant-1" || decision.ActorID != "actor-1" {
		t.Fatalf("decision lost request context: %+v", decision)
	}
}

func TestAgentPlatformCapabilityDecisionForcesAuthenticatedTenantAndScopes(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/capability-decisions", bytes.NewReader([]byte(`{
		"capability_id": "graph-reasoning",
		"tenant_id": "writer",
		"actor_id": "body-actor",
		"requested_scopes": ["not.real"]
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST capability decision: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var decision agentplatform.CapabilityDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if !decision.Enabled {
		t.Fatalf("decision enabled = false, blockers = %+v", decision.Blockers)
	}
	if decision.TenantID != "writer" || decision.ActorID != "tester" {
		t.Fatalf("decision context = %+v, want authenticated tenant/actor", decision)
	}

	overrideReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/capability-decisions", bytes.NewReader([]byte(`{
		"capability_id": "graph-reasoning",
		"tenant_id": "other",
		"requested_scopes": ["cosmo.security.read"]
	}`)))
	if err != nil {
		t.Fatalf("NewRequest override: %v", err)
	}
	overrideReq.Header.Set("Authorization", "Bearer test-key")
	overrideReq.Header.Set("Content-Type", "application/json")
	overrideResp, err := server.Client().Do(overrideReq)
	if err != nil {
		t.Fatalf("POST override capability decision: %v", err)
	}
	defer func() { _ = overrideResp.Body.Close() }()
	if overrideResp.StatusCode != http.StatusForbidden {
		t.Fatalf("override status = %d, want 403", overrideResp.StatusCode)
	}
}

func TestHandleAgentPlatformPreflight(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/preflight", bytes.NewReader([]byte(`{
		"capability_ids": ["graph-reasoning"],
		"question": "What should I inspect?",
		"scope_urn": "urn:cerebro:writer:asset:prod-db"
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST preflight: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var preflight agentplatform.AgentRunPreflight
	if err := json.NewDecoder(resp.Body).Decode(&preflight); err != nil {
		t.Fatalf("decode preflight: %v", err)
	}
	if !preflight.Enabled || preflight.TenantID != "writer" || preflight.ActorID != "tester" {
		t.Fatalf("preflight = %+v, want enabled authenticated context", preflight)
	}
	if preflight.GraphContext.ScopeTenantID != "writer" || !preflight.WriteBack.Required {
		t.Fatalf("preflight graph/write-back = graph:%+v write:%+v", preflight.GraphContext, preflight.WriteBack)
	}
	if len(preflight.GraphContext.SemanticViews) == 0 {
		t.Fatalf("preflight graph context missing semantic views: %+v", preflight.GraphContext)
	}
	if len(preflight.Policy.Checks) == 0 || len(preflight.CapabilityDecisions) != 1 {
		t.Fatalf("preflight missing policy/capability context: %+v", preflight)
	}
}

func TestHandleAgentPlatformPreflightIncludesCoverageContext(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-user": {
			Id:           "writer-okta-user",
			SourceId:     "okta",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "user"},
		},
		"other-okta-application": {
			Id:           "other-okta-application",
			SourceId:     "okta",
			TenantId:     "other",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "application"},
		},
	}}
	app := New(agentPlatformAuthConfig(), Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/preflight", bytes.NewReader([]byte(`{
		"capability_ids": ["graph-reasoning"],
		"question": "What should I inspect?"
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST preflight: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var preflight agentplatform.AgentRunPreflight
	if err := json.NewDecoder(resp.Body).Decode(&preflight); err != nil {
		t.Fatalf("decode preflight: %v", err)
	}
	if preflight.CoverageContext == nil || preflight.CoverageContext.TenantID != "writer" {
		t.Fatalf("coverage context = %+v, want writer tenant context", preflight.CoverageContext)
	}
	if preflight.CoverageContext.BlindSpotCount != 2 || len(preflight.CoverageContext.TopBlindSpots) != 2 {
		t.Fatalf("coverage context blind spots = %+v", preflight.CoverageContext)
	}
	var coverageCheck *agentplatform.AgentPolicyCheck
	for i := range preflight.Policy.Checks {
		if preflight.Policy.Checks[i].ID == "coverage_context" {
			coverageCheck = &preflight.Policy.Checks[i]
			break
		}
	}
	if coverageCheck == nil || coverageCheck.Status != "warning" {
		t.Fatalf("coverage policy check = %+v, checks=%+v", coverageCheck, preflight.Policy.Checks)
	}
}

func TestAgentPlatformSecurityControlPlaneEndToEndWorkflow(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-user": {
			Id:           "writer-okta-user",
			SourceId:     "okta",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "user"},
		},
	}}
	app := New(agentPlatformFullAuthConfig(), Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	controlReq, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent-platform/security-control-plane", nil)
	if err != nil {
		t.Fatalf("NewRequest control plane: %v", err)
	}
	controlReq.Header.Set("Authorization", "Bearer test-key")
	controlResp, err := server.Client().Do(controlReq)
	if err != nil {
		t.Fatalf("GET control plane: %v", err)
	}
	defer func() { _ = controlResp.Body.Close() }()
	if controlResp.StatusCode != http.StatusOK {
		t.Fatalf("control plane status = %d, want 200", controlResp.StatusCode)
	}
	var controlPlane agentplatform.SecurityControlPlane
	if err := json.NewDecoder(controlResp.Body).Decode(&controlPlane); err != nil {
		t.Fatalf("decode control plane: %v", err)
	}
	if len(controlPlane.EvalSuite.Scenarios) == 0 || len(controlPlane.ConnectorToolGates) == 0 {
		t.Fatalf("control plane missing evals or connector gates: %+v", controlPlane)
	}

	preflightBody := []byte(`{
		"capability_ids": ["graph-reasoning", "connector-oauth-mcp"],
		"question": "Explain connector readiness before reasoning over this finding.",
		"scope_urn": "urn:cerebro:writer:finding:alert-1",
		"connector_readiness": {"catalog-managed": "connected"}
	}`)
	preflightReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/preflight", bytes.NewReader(preflightBody))
	if err != nil {
		t.Fatalf("NewRequest preflight: %v", err)
	}
	preflightReq.Header.Set("Authorization", "Bearer test-key")
	preflightReq.Header.Set("Content-Type", "application/json")
	preflightResp, err := server.Client().Do(preflightReq)
	if err != nil {
		t.Fatalf("POST preflight: %v", err)
	}
	defer func() { _ = preflightResp.Body.Close() }()
	if preflightResp.StatusCode != http.StatusOK {
		t.Fatalf("preflight status = %d, want 200", preflightResp.StatusCode)
	}
	var preflight agentplatform.AgentRunPreflight
	if err := json.NewDecoder(preflightResp.Body).Decode(&preflight); err != nil {
		t.Fatalf("decode preflight: %v", err)
	}
	if !preflight.Enabled || preflight.TenantID != "writer" || preflight.ActorID != "tester" {
		t.Fatalf("preflight = %+v, want enabled authenticated writer context", preflight)
	}
	if len(preflight.ConnectorContext) != 1 || !preflight.ConnectorContext[0].Satisfied {
		t.Fatalf("connector context = %+v, want one satisfied connector", preflight.ConnectorContext)
	}
	if preflight.CoverageContext == nil || preflight.CoverageContext.TenantID != "writer" {
		t.Fatalf("coverage context = %+v, want writer tenant coverage", preflight.CoverageContext)
	}

	packetBody := []byte(`{
		"capability_ids": ["graph-reasoning", "connector-oauth-mcp", "runtime-response-actions"],
		"question": "Plan a remediation dry run for this alert after checking connector readiness.",
		"scope_urn": "urn:cerebro:writer:finding:alert-1",
		"connector_readiness": {"catalog-managed": "connected"},
		"allow_preview": true,
		"evidence_urns": ["urn:cerebro:writer:evidence:event-1"],
		"memory_hints": [{"type": "prior_investigation", "urn": "urn:cerebro:writer:investigation:prev"}],
		"action": {
			"stage": "dry_run",
			"target_urns": ["urn:cerebro:writer:asset:service-1"]
		}
	}`)
	packetReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/evidence-packets", bytes.NewReader(packetBody))
	if err != nil {
		t.Fatalf("NewRequest evidence packet: %v", err)
	}
	packetReq.Header.Set("Authorization", "Bearer test-key")
	packetReq.Header.Set("Content-Type", "application/json")
	packetResp, err := server.Client().Do(packetReq)
	if err != nil {
		t.Fatalf("POST evidence packet: %v", err)
	}
	defer func() { _ = packetResp.Body.Close() }()
	if packetResp.StatusCode != http.StatusOK {
		t.Fatalf("packet status = %d, want 200", packetResp.StatusCode)
	}
	var packet agentplatform.AgentEvidencePacket
	if err := json.NewDecoder(packetResp.Body).Decode(&packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	if packet.TenantID != "writer" || packet.ActorID != "tester" || !packet.Preflight.Enabled {
		t.Fatalf("packet context/preflight = %+v, want authenticated enabled packet", packet)
	}
	if packet.Confidence.Level != "medium" || !containsString(packet.Confidence.Reasons, "coverage_blind_spots") {
		t.Fatalf("packet confidence = %+v, want medium with coverage blind spots", packet.Confidence)
	}
	if !packetHasAgent(packet, "coverage-scout") || !packetHasAgent(packet, "remediation-planner") {
		t.Fatalf("packet agents = %+v, want coverage and remediation profiles", packet.RecommendedAgents)
	}
	if !packetHasVerifierStatus(packet, "connector-tool-gates", "pass") || !packetHasVerifierStatus(packet, "remediation-safety", "pass") {
		t.Fatalf("packet verifiers = %+v, want connector/remediation pass", packet.VerifierResults)
	}
	if packetActionStatus(packet, agentplatform.ActionStageDryRun) != "requested" {
		t.Fatalf("packet action ladder = %+v, want dry_run requested", packet.ActionLadder)
	}
	if !packet.SimulationPlan.Allowed || packet.SimulationPlan.Mode != "graph_or_fixture_only" {
		t.Fatalf("simulation plan = %+v, want allowed graph-only simulation", packet.SimulationPlan)
	}
	if len(packet.SecurityMemory.Hints) != 1 || len(packet.RequiredWriteBack) == 0 {
		t.Fatalf("packet memory/writeback = memory:%+v write:%+v", packet.SecurityMemory, packet.RequiredWriteBack)
	}
}

func TestAgentPlatformEvidencePacketForcesAuthenticatedContext(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/evidence-packets", bytes.NewReader([]byte(`{
		"tenant_id": "writer",
		"actor_id": "body-actor",
		"question": "Triage this alert",
		"scope_urn": "urn:cerebro:writer:finding:alert-1",
		"capability_ids": ["graph-reasoning"],
		"requested_scopes": ["not.real"],
		"action": {"stage": "recommend"},
		"memory_hints": [{"type": "prior_investigation", "urn": "urn:cerebro:writer:investigation:prev"}]
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST evidence packet: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var packet agentplatform.AgentEvidencePacket
	if err := json.NewDecoder(resp.Body).Decode(&packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	if packet.TenantID != "writer" || packet.ActorID != "tester" {
		t.Fatalf("packet context = %+v, want authenticated tenant/actor", packet)
	}
	if !packet.Preflight.Enabled {
		t.Fatalf("packet preflight enabled = false, blockers = %+v", packet.Preflight.Blockers)
	}
	if len(packet.RecommendedAgents) == 0 || len(packet.VerifierResults) == 0 {
		t.Fatalf("packet missing agents or verifiers: %+v", packet)
	}
	if len(packet.SecurityMemory.ReadableTypes) == 0 || len(packet.ConnectorToolGates) == 0 {
		t.Fatalf("packet missing memory or connector gates: %+v", packet)
	}
}

func TestAgentPlatformEvidencePacketRejectsTenantOverride(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/evidence-packets", bytes.NewReader([]byte(`{
		"tenant_id": "other",
		"question": "Triage this alert",
		"scope_urn": "urn:cerebro:other:finding:alert-1",
		"capability_ids": ["graph-reasoning"]
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST evidence packet override: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAgentPlatformEvidencePacketRejectsCrossTenantPacketURNs(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "evidence urn",
			body: `{
				"tenant_id": "writer",
				"question": "Triage this alert",
				"scope_urn": "urn:cerebro:writer:finding:alert-1",
				"evidence_urns": ["urn:cerebro:other:finding:alert-2"],
				"capability_ids": ["graph-reasoning"]
			}`,
		},
		{
			name: "action target urn",
			body: `{
				"tenant_id": "writer",
				"question": "Triage this alert",
				"scope_urn": "urn:cerebro:writer:finding:alert-1",
				"capability_ids": ["graph-reasoning"],
				"action": {"stage": "recommend", "target_urns": ["urn:cerebro:other:finding:alert-2"]}
			}`,
		},
		{
			name: "memory hint urn",
			body: `{
				"tenant_id": "writer",
				"question": "Triage this alert",
				"scope_urn": "urn:cerebro:writer:finding:alert-1",
				"capability_ids": ["graph-reasoning"],
				"memory_hints": [{"type": "prior_investigation", "urn": "urn:cerebro:other:investigation:prev"}]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/evidence-packets", bytes.NewReader([]byte(tt.body)))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer test-key")
			req.Header.Set("Content-Type", "application/json")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("POST evidence packet: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
}

func TestAgentPlatformClaimVerificationForcesAuthenticatedContextAndStageGates(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/claims/verify", bytes.NewReader([]byte(`{
		"tenant_id": "writer",
		"actor_id": "body-actor",
		"claim": "Finding alert-1 should be remediated",
		"claim_type": "finding_triage",
		"scope_urn": "urn:cerebro:writer:finding:alert-1",
		"supporting_evidence_urns": ["urn:cerebro:writer:evidence:ev-1"],
		"freshness_state": "fresh",
		"requested_action_stage": "execute",
		"human_approved": false
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST claim verification: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var verification agentplatform.ClaimVerification
	if err := json.NewDecoder(resp.Body).Decode(&verification); err != nil {
		t.Fatalf("decode verification: %v", err)
	}
	if verification.TenantID != "writer" || verification.ActorID != "tester" {
		t.Fatalf("verification context = %+v, want authenticated tenant/actor", verification)
	}
	if verification.Verdict != agentplatform.ClaimVerdictWeaklySupported || verification.AllowedNextStage != agentplatform.ActionStageExplain {
		t.Fatalf("verification verdict/stage = %q/%q, want weakly_supported/explain", verification.Verdict, verification.AllowedNextStage)
	}
	if !claimVerificationHasBlocker(verification, "stage_skip") || !claimVerificationHasBlocker(verification, "unapproved_mutation") {
		t.Fatalf("verification blockers = %+v, want stage and approval blockers", verification.Blockers)
	}
	if len(verification.RequiredWriteBack) == 0 || len(verification.VerifierResults) == 0 {
		t.Fatalf("verification missing writeback or verifiers: %+v", verification)
	}
}

func TestAgentPlatformClaimVerificationRejectsCrossTenantURNs(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/claims/verify", bytes.NewReader([]byte(`{
		"tenant_id": "writer",
		"claim": "Finding alert-1 should be remediated",
		"scope_urn": "urn:cerebro:writer:finding:alert-1",
		"supporting_evidence_urns": ["urn:cerebro:writer:evidence:ev-1"],
		"missing_evidence": ["urn:cerebro:other:evidence:ev-2"],
		"freshness_state": "fresh"
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST claim verification: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAgentPlatformClaimVerificationRequiresClaim(t *testing.T) {
	app := New(agentPlatformAuthConfig(), Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/claims/verify", bytes.NewReader([]byte(`{
		"tenant_id": "writer",
		"scope_urn": "urn:cerebro:writer:finding:alert-1"
	}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST claim verification: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleAgentPlatformCapabilityDecisionReportsUnknownCapability(t *testing.T) {
	body := []byte(`{"capability_id":"missing-capability","requested_scopes":["cosmo.security.read"]}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-platform/capability-decisions", bytes.NewReader(body))

	(&App{}).handleAgentPlatformCapabilityDecision(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func claimVerificationHasBlocker(verification agentplatform.ClaimVerification, code string) bool {
	for _, blocker := range verification.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func agentPlatformAuthConfig() config.Config {
	return config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{
				{
					ID:        "test-credential",
					ClientID:  "test-client",
					Key:       "test-key",
					Principal: "tester",
					TenantID:  "writer",
					Scopes:    []string{scopeCosmoSecurityRead},
				},
				{
					ID:        "operator-credential",
					ClientID:  "operator-client",
					Key:       "operator-key",
					Principal: "tester",
					TenantID:  "writer",
				},
			},
		},
	}
}

func agentPlatformFullAuthConfig() config.Config {
	cfg := agentPlatformAuthConfig()
	cfg.Auth.APICredentials[0].Scopes = []string{
		scopeCosmoSecurityRead,
		scopeConnectorCredentialsRead,
		scopeConnectorCredentialsWrite,
		scopeRuntimeResponseWrite,
		scopeFindingCandidatePromote,
		scopeGraphActionsWrite,
	}
	return cfg
}

func packetHasAgent(packet agentplatform.AgentEvidencePacket, id string) bool {
	for _, agent := range packet.RecommendedAgents {
		if agent.ID == id {
			return true
		}
	}
	return false
}

func packetHasVerifierStatus(packet agentplatform.AgentEvidencePacket, id string, status string) bool {
	for _, result := range packet.VerifierResults {
		if result.ID == id && result.Status == status {
			return true
		}
	}
	return false
}

func packetActionStatus(packet agentplatform.AgentEvidencePacket, stageID string) string {
	for _, status := range packet.ActionLadder {
		if status.Stage.ID == stageID {
			return status.Status
		}
	}
	return ""
}

func postA2AJSONRPC(t *testing.T, server *httptest.Server, apiKey string, idempotencyKey string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/a2a", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST A2A: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	return resp
}

func decodeA2ATestTaskResult(t *testing.T, result any, wrapperKey string) agentplatform.A2ATask {
	t.Helper()
	if wrapperKey == "" {
		var task agentplatform.A2ATask
		decodeA2ATestResult(t, result, &task)
		return task
	}
	var wrapped map[string]agentplatform.A2ATask
	decodeA2ATestResult(t, result, &wrapped)
	task, ok := wrapped[wrapperKey]
	if !ok {
		t.Fatalf("A2A result = %+v, missing %q", wrapped, wrapperKey)
	}
	return task
}

func decodeA2ATestEvidencePacket(t *testing.T, value any) agentplatform.AgentEvidencePacket {
	t.Helper()
	var packet agentplatform.AgentEvidencePacket
	decodeA2ATestResult(t, value, &packet)
	return packet
}

func decodeA2ATestResult(t *testing.T, value any, target any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("decode result: %v", err)
	}
}

type a2ATestJobStore struct {
	mu          sync.Mutex
	nextID      int
	createCount int
	jobs        map[string]*ports.Job
	idempotent  map[string]string
	events      []*ports.JobEvent
}

func newA2ATestJobStore() *a2ATestJobStore {
	return &a2ATestJobStore{
		nextID:     1,
		jobs:       map[string]*ports.Job{},
		idempotent: map[string]string{},
	}
}

func (s *a2ATestJobStore) Ping(context.Context) error {
	return nil
}

func (s *a2ATestJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.IdempotencyKey != "" {
		key := request.TenantID + "\x00" + request.IdempotencyKey
		if id := s.idempotent[key]; id != "" {
			return cloneA2ATestJob(s.jobs[id]), false, nil
		}
	}
	id := "job-test"
	if s.nextID > 1 {
		id = "job-test-" + strconv.Itoa(s.nextID)
	}
	s.nextID++
	s.createCount++
	now := time.Now().UTC()
	job := &ports.Job{
		ID:             id,
		Kind:           request.Kind,
		Status:         ports.JobStatusQueued,
		TenantID:       request.TenantID,
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		IdempotencyKey: request.IdempotencyKey,
		Payload:        cloneA2ATestMap(request.Payload),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.jobs[id] = cloneA2ATestJob(job)
	if request.IdempotencyKey != "" {
		s.idempotent[request.TenantID+"\x00"+request.IdempotencyKey] = id
	}
	return cloneA2ATestJob(job), true, nil
}

func (s *a2ATestJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	return cloneA2ATestJob(job), nil
}

func (s *a2ATestJobStore) ListJobs(_ context.Context, filter ports.JobFilter) ([]*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := int(filter.Limit)
	if limit == 0 {
		limit = 50
	}
	jobs := []*ports.Job{}
	for _, job := range s.jobs {
		if filter.TenantID != "" && job.TenantID != filter.TenantID {
			continue
		}
		if filter.Kind != "" && job.Kind != filter.Kind {
			continue
		}
		if filter.Status != "" && job.Status != filter.Status {
			continue
		}
		jobs = append(jobs, cloneA2ATestJob(job))
		if len(jobs) >= limit {
			break
		}
	}
	return jobs, nil
}

func (s *a2ATestJobStore) CountJobs(_ context.Context, filter ports.JobFilter) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count uint64
	for _, job := range s.jobs {
		if filter.TenantID != "" && job.TenantID != filter.TenantID {
			continue
		}
		if filter.Kind != "" && job.Kind != filter.Kind {
			continue
		}
		if filter.Status != "" && job.Status != filter.Status {
			continue
		}
		count++
	}
	return count, nil
}

func (s *a2ATestJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	if len(update.AllowedStatuses) > 0 && !a2ATestContainsStatus(update.AllowedStatuses, job.Status) {
		return nil, ports.ErrJobUpdateConflict
	}
	if update.Status != "" {
		job.Status = update.Status
	}
	if update.Progress != nil {
		job.Progress = *update.Progress
	}
	if update.Message != "" {
		job.Message = update.Message
	}
	if update.Error != "" {
		job.Error = update.Error
	}
	if update.Result != nil {
		job.Result = cloneA2ATestMap(update.Result)
	}
	if update.ResultRefs != nil {
		job.ResultRefs = cloneA2ATestStringMap(update.ResultRefs)
	}
	if update.StartedAt != nil {
		job.StartedAt = *update.StartedAt
	}
	if update.FinishedAt != nil {
		job.FinishedAt = *update.FinishedAt
	}
	if update.CancelRequested != nil {
		job.CancelRequested = *update.CancelRequested
	}
	job.UpdatedAt = time.Now().UTC()
	return cloneA2ATestJob(job), nil
}

func (s *a2ATestJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.Sequence = uint64(len(s.events) + 1)
	event.CreatedAt = time.Now().UTC()
	cloned := event
	cloned.Payload = cloneA2ATestMap(event.Payload)
	s.events = append(s.events, &cloned)
	return &cloned, nil
}

func (s *a2ATestJobStore) ListJobEvents(_ context.Context, jobID string, limit uint32) ([]*ports.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := int(limit)
	if max == 0 {
		max = len(s.events)
	}
	events := []*ports.JobEvent{}
	for _, event := range s.events {
		if event.JobID != jobID {
			continue
		}
		cloned := *event
		cloned.Payload = cloneA2ATestMap(event.Payload)
		events = append(events, &cloned)
		if len(events) >= max {
			break
		}
	}
	return events, nil
}

func a2ATestContainsStatus(values []string, status string) bool {
	for _, value := range values {
		if value == status {
			return true
		}
	}
	return false
}

func cloneA2ATestJob(job *ports.Job) *ports.Job {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.Payload = cloneA2ATestMap(job.Payload)
	cloned.Result = cloneA2ATestMap(job.Result)
	cloned.ResultRefs = cloneA2ATestStringMap(job.ResultRefs)
	return &cloned
}

func cloneA2ATestMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneA2ATestStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
