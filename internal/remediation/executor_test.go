package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/testutil"
)

func TestExecutor_ApproveBypassesApprovalGate(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "approval-test",
		Name:    "Approval Test",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type:             ActionNotifySlack,
				RequiresApproval: true,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{Type: TriggerManual})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}

	if err := executor.Approve(context.Background(), execution.ID, "alice"); err != nil {
		// notify_slack fails when notifications are not configured in this test setup.
		t.Logf("Approve returned expected execution error: %v", err)
	}
	if execution.Status == ExecutionApproval {
		t.Fatalf("status remained %s after approve", ExecutionApproval)
	}
	if approvedBy, _ := execution.TriggerData["approved_by"].(string); approvedBy != "alice" {
		t.Fatalf("approved_by = %q, want alice", approvedBy)
	}
}

func TestExecutor_RemoteActionFailsWithoutRemoteCaller(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "remote-action-test",
		Name:    "Remote Action Test",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type: ActionUpdateCRMField,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{Type: TriggerManual})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected execute to fail without remote caller")
	}
	if !strings.Contains(err.Error(), "remote tool caller not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
}

func TestExecutor_SendCustomerCommRequiresApprovalByDefault(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "send-customer-comm",
		Name:    "Send Customer Communication",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type: ActionSendCustomerComm,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type: TriggerManual,
		Data: map[string]any{
			"finding_id": "finding-2",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]

	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"slack.send_message": {{output: `{"ok":true}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}
	if len(caller.calls) != 0 {
		t.Fatalf("expected no remote calls before approval, got %v", caller.calls)
	}

	if err := executor.Approve(context.Background(), execution.ID, "manager@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(caller.calls) == 0 {
		t.Fatal("expected remote call after approval")
	}
}
