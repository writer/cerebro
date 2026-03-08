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

	if err := executor.Approve(context.Background(), execution.ID, "alice"); err == nil {
		// notify_slack fails because notifications are not configured; approval should still move
		// past the approval gate and execute actions.
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
