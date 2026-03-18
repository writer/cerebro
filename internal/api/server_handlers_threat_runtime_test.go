package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/runtime"
)

func seedRuntimeApprovalExecution(t *testing.T, s *Server, policyID, ip string) *runtime.ResponseExecution {
	t.Helper()
	s.app.RuntimeRespond.SetActionHandler(runtime.NewDefaultActionHandler(runtime.DefaultActionHandlerOptions{
		Blocklist: s.app.RuntimeRespond.Blocklist(),
	}))
	if err := s.app.RuntimeRespond.CreatePolicy(&runtime.ResponsePolicy{
		ID:              policyID,
		Name:            policyID,
		Enabled:         true,
		RequireApproval: true,
		Triggers: []runtime.PolicyTrigger{{
			Type:     "finding",
			Category: runtime.CategoryReverseShell,
			Severity: "high",
		}},
		Actions: []runtime.PolicyAction{{
			Type:       runtime.ActionBlockIP,
			Parameters: map[string]string{"target": "destination"},
		}},
	}); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	execution, err := s.app.RuntimeRespond.ProcessFinding(context.Background(), &runtime.RuntimeFinding{
		ID:           policyID + "-finding",
		RuleID:       "reverse-shell",
		Category:     runtime.CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &runtime.RuntimeEvent{
			ID:           policyID + "-event",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &runtime.NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: ip,
			},
		},
	})
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected runtime execution")
	}
	if execution.Status != runtime.StatusApproval {
		t.Fatalf("status = %s, want %s", execution.Status, runtime.StatusApproval)
	}
	return execution
}

func TestRuntimeExecutionEndpointsListAndApprove(t *testing.T) {
	s := newTestServer(t)
	execution := seedRuntimeApprovalExecution(t, s, "runtime-approve-endpoint", "203.0.113.41")

	list := do(t, s, http.MethodGet, "/api/v1/runtime/executions?limit=1", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for runtime executions list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if listBody["count"] != float64(1) {
		t.Fatalf("expected one runtime execution, got %#v", listBody["count"])
	}
	executions, ok := listBody["executions"].([]any)
	if !ok || len(executions) != 1 {
		t.Fatalf("expected one execution payload, got %#v", listBody["executions"])
	}
	entry := executions[0].(map[string]any)
	if got := entry["id"]; got != execution.ID {
		t.Fatalf("listed execution id = %#v, want %s", got, execution.ID)
	}

	approve := do(t, s, http.MethodPost, "/api/v1/runtime/executions/"+execution.ID+"/approve", map[string]any{"approver_id": "alice"})
	if approve.Code != http.StatusOK {
		t.Fatalf("expected 200 for runtime execution approve, got %d: %s", approve.Code, approve.Body.String())
	}
	if execution.Status != runtime.StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, runtime.StatusCompleted)
	}
	if !s.app.RuntimeRespond.Blocklist().IsBlocked("203.0.113.41", "ip") {
		t.Fatal("expected approved runtime execution to block the destination IP")
	}
}

func TestRuntimeExecutionRejectEndpoint(t *testing.T) {
	s := newTestServer(t)
	execution := seedRuntimeApprovalExecution(t, s, "runtime-reject-endpoint", "203.0.113.42")

	reject := do(t, s, http.MethodPost, "/api/v1/runtime/executions/"+execution.ID+"/reject", map[string]any{
		"rejecter_id": "bob",
		"reason":      "manual override",
	})
	if reject.Code != http.StatusOK {
		t.Fatalf("expected 200 for runtime execution reject, got %d: %s", reject.Code, reject.Body.String())
	}
	if execution.Status != runtime.StatusCanceled {
		t.Fatalf("status = %s, want %s", execution.Status, runtime.StatusCanceled)
	}
}
