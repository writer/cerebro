package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

func TestPolicyEvaluateEndpoint_DenyAndAudit(t *testing.T) {
	s := newTestServer(t)
	s.app.Policy.AddPolicy(&policy.Policy{
		ID:          "policy.refund.approval",
		Name:        "Refund approval required",
		Effect:      "forbid",
		Action:      "refund.create",
		Resource:    "business::refund",
		Description: "Refunds must pass approval policy",
		Severity:    "high",
	})

	auditLogs := &captureAuditLogger{}
	s.auditLogger = auditLogs

	w := do(t, s, http.MethodPost, "/api/v1/policy/evaluate", map[string]any{
		"principal": map[string]any{"id": "user:alice"},
		"action":    "refund.create",
		"resource":  map[string]any{"type": "refund", "id": "refund:123"},
		"context":   map[string]any{"amount": 6500, "currency": "USD"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["decision"] != "deny" {
		t.Fatalf("expected deny decision, got %#v", body["decision"])
	}
	if requiresApproval, _ := body["requires_approval"].(bool); requiresApproval {
		t.Fatalf("expected requires_approval=false, got %#v", body["requires_approval"])
	}
	if _, ok := body["remediation_steps"].([]any); !ok {
		t.Fatalf("expected remediation_steps array, got %#v", body["remediation_steps"])
	}

	if len(auditLogs.entries) != 1 {
		t.Fatalf("expected 1 audit log entry, got %d", len(auditLogs.entries))
	}
	if auditLogs.entries[0].Action != "policy.evaluate" {
		t.Fatalf("expected policy.evaluate action, got %q", auditLogs.entries[0].Action)
	}
	if auditLogs.entries[0].Details["decision"] != "deny" {
		t.Fatalf("expected deny decision in audit details, got %#v", auditLogs.entries[0].Details["decision"])
	}
}

func TestPolicyEvaluateEndpoint_RequiresApprovalFromPropagation(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user-1", Kind: graph.NodeKindUser, Name: "user-1"})
	g.AddNode(&graph.Node{ID: "svc-1", Kind: graph.NodeKindApplication, Name: "svc-1"})
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 1500000.0}})
	g.AddEdge(&graph.Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	w := do(t, s, http.MethodPost, "/api/v1/policy/evaluate", map[string]any{
		"principal": map[string]any{"id": "user:reviewer"},
		"action":    "identity.update",
		"resource":  map[string]any{"type": "user", "id": "user-1"},
		"context":   map[string]any{"ticket_id": "CHG-123"},
		"proposed_change": map[string]any{
			"id":                     "proposal-1",
			"source":                 "api-test",
			"reason":                 "quarterly review",
			"approval_arr_threshold": 100000.0,
			"mutations": []map[string]any{
				{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": false}},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["decision"] != "require_approval" {
		t.Fatalf("expected require_approval decision, got %#v", body["decision"])
	}
	if requiresApproval, _ := body["requires_approval"].(bool); !requiresApproval {
		t.Fatalf("expected requires_approval=true, got %#v", body["requires_approval"])
	}

	propagation, ok := body["propagation"].(map[string]any)
	if !ok {
		t.Fatalf("expected propagation section, got %#v", body["propagation"])
	}
	if propagation["decision"] != string(graph.DecisionNeedsApproval) {
		t.Fatalf("expected propagation decision %q, got %#v", graph.DecisionNeedsApproval, propagation["decision"])
	}
}

func TestPolicyEvaluateEndpoint_BackwardCompatiblePoliciesPath(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/policies/evaluate", map[string]any{
		"principal": map[string]any{"id": "user:tester"},
		"action":    "noop.action",
		"resource":  map[string]any{"type": "test", "id": "test:1"},
		"context":   map[string]any{"source": "unit-test"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["decision"] != "allow" {
		t.Fatalf("expected allow decision, got %#v", body["decision"])
	}
}
