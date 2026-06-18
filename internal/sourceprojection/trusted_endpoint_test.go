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
		"agent_id": "dev_123",
		"hostname": "workstation",
		"action":   "git_push",
		"decision": "deny",
		"severity": "high",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	agentURN := "urn:cerebro:writer:trusted_endpoint_agent:dev_123"
	agent := state.entities[agentURN]
	if agent == nil || agent.EntityType != "trusted_endpoint.agent" {
		t.Fatalf("trusted_endpoint.agent entity missing or wrong: %#v", agent)
	}

	gate := findProjectedEntityByType(state, "trusted_endpoint.trust_gate_decision")
	if gate == nil {
		t.Fatalf("trusted_endpoint.trust_gate_decision entity missing; entities=%#v", state.entities)
	}
	for key, want := range map[string]string{
		"decision":            "deny",
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
