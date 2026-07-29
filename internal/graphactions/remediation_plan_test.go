package graphactions

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestPlanReversibleRemediationUsesDryRunAndReversalMetadata(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Attributes: map[string]string{
			"okta_user_email": "alice@tenant-a.example",
		},
	})}
	plan, err := (Service{Findings: workflow, Client: client}).PlanReversibleRemediation(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Reason:    "confirmed offboarding drift",
	})
	if err != nil {
		t.Fatalf("PlanReversibleRemediation() error = %v", err)
	}
	if client.called {
		t.Fatalf("dry-run plan reached provider")
	}
	if plan.Action.ID != ActionIdentityOktaSuspendUser || plan.Reversal.ID != ActionIdentityOktaUnsuspendUser {
		t.Fatalf("plan metadata = %#v", plan)
	}
	if plan.DryRun == nil || plan.DryRun.Status != ActionStatusDryRun || plan.Target != "alice@tenant-a.example" {
		t.Fatalf("dry-run plan = %#v", plan)
	}
	if !plan.ApprovalRequired || plan.HumanApproved || plan.CanExecute {
		t.Fatalf("approval flags = %#v", plan)
	}
}
