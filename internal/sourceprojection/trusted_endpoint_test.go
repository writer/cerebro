package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func trustedEndpointEvent(id string, kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "trusted_endpoint",
		Kind:       kind,
		Attributes: attrs,
	}
}

func findProjectedEntityByType(recorder *projectionRecorder, entityType string) *ports.ProjectedEntity {
	for _, entity := range recorder.entities {
		if entity.EntityType == entityType {
			return entity
		}
	}
	return nil
}

func TestProjectTrustedEndpointTrustGateDecision(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := trustedEndpointEvent("te-trust-gate", "trusted_endpoint.trust_gate_decision", map[string]string{
		"agent_id":     "dev_123",
		"hostname":     "workstation",
		"action":       "git_push",
		"decision":     "deny",
		"severity":     "high",
		"reason":       "posture_failed",
		"agent_status": "deprovisioned",
		"managed":      "false",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	agentURN := "urn:cerebro:writer:trusted_endpoint_agent:dev_123"
	agent := state.entities[agentURN]
	if agent == nil || agent.EntityType != "trusted_endpoint.agent" {
		t.Fatalf("trusted_endpoint.agent entity missing or wrong: %#v", agent)
	}
	for key, want := range map[string]string{
		"agent_status": "deprovisioned",
		"managed":      "false",
	} {
		if got := agent.Attributes[key]; got != want {
			t.Fatalf("agent attribute %q = %q, want %q", key, got, want)
		}
	}

	gate := findProjectedEntityByType(state, "trusted_endpoint.trust_gate_decision")
	if gate == nil {
		t.Fatalf("trusted_endpoint.trust_gate_decision entity missing; entities=%#v", state.entities)
	}
	for key, want := range map[string]string{
		"decision":            "deny",
		"agent_status":        "deprovisioned",
		"managed":             "false",
		"reason":              "posture_failed",
		"severity_normalized": "HIGH",
		"status_normalized":   "failing",
	} {
		if got := gate.Attributes[key]; got != want {
			t.Fatalf("trust gate attribute %q = %q, want %q", key, got, want)
		}
	}

	assertProjectedLink(t, state, agentURN, relationHasEvidence, gate.URN)
	assertProjectedLink(t, state, gate.URN, relationObservedOn, agentURN)
}

func TestProjectTrustedEndpointGRCEvidenceNormalizesStatus(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := trustedEndpointEvent("te-grc", "trusted_endpoint.grc_evidence", map[string]string{
		"agent_id":   "dev_123",
		"control_id": "AC-2",
		"status":     "failing",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	evidence := findProjectedEntityByType(state, "trusted_endpoint.grc_evidence")
	if evidence == nil {
		t.Fatalf("trusted_endpoint.grc_evidence entity missing; entities=%#v", state.entities)
	}
	if got := evidence.Attributes["status_normalized"]; got != "failing" {
		t.Fatalf("grc status_normalized = %q, want failing", got)
	}
	if got := evidence.Attributes["control_id"]; got != "AC-2" {
		t.Fatalf("grc control_id = %q, want AC-2", got)
	}
}

func TestProjectTrustedEndpointAgentExecutionReceipt(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := trustedEndpointEvent("te-receipt", "trusted_endpoint.agent_execution_receipt", map[string]string{
		"agent_id":                   "dev_123",
		"device_id":                  "dev_123",
		"receipt_id":                 "receipt-1",
		"captured_at":                "2026-07-16T12:00:00Z",
		"receipt_digest":             "sha256:receipt",
		"previous_receipt_digest":    "sha256:previous",
		"sequence":                   "7",
		"agent_product":              "Codex",
		"model":                      "gpt-test",
		"session_id":                 "session-1",
		"turn_id":                    "turn-1",
		"tool_call_id":               "call-1",
		"tool_name":                  "Bash",
		"action":                     "aws ecs register-task-definition",
		"permission_mode":            "never",
		"phase":                      "completed",
		"local_user_claim":           "jonathan",
		"local_user_claim_source":    "process_user",
		"evidence_integrity":         "authenticated_device_claim",
		"claimed_evidence_integrity": "signature_valid",
		"provider_binding":           "unverified",
		"claimed_provider_binding":   "provider_bound",
		"claimed_provider_event_id":  "cloudtrail-1",
		"normalized_receipt_digest":  "server-digest",
		"receipt_key":                "receipt-key",
	})
	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 4 || result.LinksProjected != 5 {
		t.Fatalf("Project() counts = %d entities/%d links, want 4/5", result.EntitiesProjected, result.LinksProjected)
	}
	observation := findProjectedEntityByType(state, "trusted_endpoint.agent_execution_receipt_observation")
	if observation == nil {
		t.Fatalf("receipt observation missing; entities=%#v", state.entities)
	}
	for key, want := range map[string]string{
		"receipt_id":                 "receipt-1",
		"captured_at":                "2026-07-16T12:00:00Z",
		"agent_product":              "Codex",
		"session_id":                 "session-1",
		"tool_name":                  "Bash",
		"action":                     "aws ecs register-task-definition",
		"local_user_claim":           "jonathan",
		"local_user_claim_source":    "process_user",
		"evidence_integrity":         "authenticated_device_claim",
		"claimed_evidence_integrity": "signature_valid",
		"provider_binding":           "unverified",
		"claimed_provider_binding":   "provider_bound",
	} {
		if got := observation.Attributes[key]; got != want {
			t.Fatalf("receipt attribute %q = %q, want %q", key, got, want)
		}
	}
	agentURN := "urn:cerebro:writer:trusted_endpoint_agent:dev_123"
	session := findProjectedEntityByType(state, "trusted_endpoint.agent_session")
	if session == nil {
		t.Fatalf("agent session entity missing; entities=%#v", state.entities)
	}
	assertProjectedLink(t, state, agentURN, relationHasContext, session.URN)
	receipt := findProjectedEntityByType(state, "trusted_endpoint.agent_execution_receipt")
	if receipt == nil {
		t.Fatalf("canonical receipt entity missing; entities=%#v", state.entities)
	}
	assertProjectedLink(t, state, session.URN, relationHasEvidence, receipt.URN)
	assertProjectedLink(t, state, receipt.URN, relationHasEvidence, observation.URN)
	assertProjectedLink(t, state, agentURN, relationHasEvidence, observation.URN)
	assertProjectedLink(t, state, observation.URN, relationObservedOn, agentURN)
}

func TestProjectTrustedEndpointReceiptScopesSessionsAndSurfacesVersions(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	for _, tc := range []struct {
		id, agentID, digest string
	}{
		{id: "te-receipt-v1", agentID: "dev_123", digest: "digest-v1"},
		{id: "te-receipt-v2", agentID: "dev_123", digest: "digest-v2"},
		{id: "te-other-device", agentID: "dev_456", digest: "digest-other"},
	} {
		event := trustedEndpointEvent(tc.id, "trusted_endpoint.agent_execution_receipt", map[string]string{
			"agent_id": tc.agentID, "device_id": tc.agentID, "receipt_id": "receipt-1",
			"receipt_key": "key-" + tc.agentID, "normalized_receipt_digest": tc.digest,
			"agent_product": "Codex", "session_id": "session-1", "action": "git push",
		})
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", tc.id, err)
		}
	}
	var sessions, receipts, observations int
	for _, entity := range state.entities {
		switch entity.EntityType {
		case "trusted_endpoint.agent_session":
			sessions++
		case "trusted_endpoint.agent_execution_receipt":
			receipts++
		case "trusted_endpoint.agent_execution_receipt_observation":
			observations++
		}
	}
	if sessions != 2 || receipts != 2 || observations != 3 {
		t.Fatalf("scoped graph sessions/receipts/observations = %d/%d/%d, want 2/2/3", sessions, receipts, observations)
	}
}

func TestRegistryRoutesTrustedEndpointKinds(t *testing.T) {
	kinds := []string{
		"trusted_endpoint.agent_identity",
		"trusted_endpoint.host_posture",
		"trusted_endpoint.repo_worktree_context",
		"trusted_endpoint.ai_session_summary",
		"trusted_endpoint.ai_workflow_risk",
		"trusted_endpoint.security_finding",
		"trusted_endpoint.grc_evidence",
		"trusted_endpoint.trust_gate_decision",
		"trusted_endpoint.action_outcome",
		"trusted_endpoint.agent_execution_receipt",
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			event := trustedEndpointEvent("te-"+kind, kind, map[string]string{
				"agent_id": "dev_123",
				"action":   "git_push",
				"decision": "deny",
			})
			entities, links, err := BuiltinRegistry().Project(event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", kind, err)
			}
			foundAgent := false
			for _, entity := range entities {
				if entity.EntityType == "trusted_endpoint.agent" {
					foundAgent = true
					break
				}
			}
			if !foundAgent {
				t.Fatalf("kind %q did not route to trusted_endpoint projector; entities=%#v", kind, entities)
			}
			if len(links) == 0 {
				t.Fatalf("kind %q produced no projected links", kind)
			}
		})
	}
}
