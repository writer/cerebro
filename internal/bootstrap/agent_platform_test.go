package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/config"
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
	if len(contract.SecurityControlPlane.IntegrationStrategies) != 8 {
		t.Fatalf("contract response integration strategies = %d, want 8", len(contract.SecurityControlPlane.IntegrationStrategies))
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

func TestHandleAgentPlatformCapabilityDecisionReportsUnknownCapability(t *testing.T) {
	body := []byte(`{"capability_id":"missing-capability","requested_scopes":["cosmo.security.read"]}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-platform/capability-decisions", bytes.NewReader(body))

	(&App{}).handleAgentPlatformCapabilityDecision(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func agentPlatformAuthConfig() config.Config {
	return config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{{
				ID:        "test-credential",
				ClientID:  "test-client",
				Key:       "test-key",
				Principal: "tester",
				TenantID:  "writer",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
		},
	}
}
