package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/agentplatform"
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

func TestHandleAgentPlatformCapabilityDecisionReportsUnknownCapability(t *testing.T) {
	body := []byte(`{"capability_id":"missing-capability","requested_scopes":["cosmo.security.read"]}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-platform/capability-decisions", bytes.NewReader(body))

	(&App{}).handleAgentPlatformCapabilityDecision(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}
