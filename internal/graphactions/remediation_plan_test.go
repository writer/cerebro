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

func TestExecuteApprovedReversibleRemediationRequiresReversibleAction(t *testing.T) {
	provider := &stubActionProvider{executeAction: &GraphAction{ID: "action-1", ExternalID: "action-1"}}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"target": "alice"},
	})}
	registry := Registry{actions: map[string]ActionSpec{
		"custom.nonreversible": {
			ID:             "custom.nonreversible",
			Provider:       "custom",
			ProviderAction: "noop",
			TargetKind:     "identity",
			ResolveTarget: func(*ports.FindingRecord, string) (string, error) {
				return "alice", nil
			},
		},
	}}
	_, err := (Service{
		Findings:  workflow,
		Providers: map[string]ActionProvider{"custom": provider},
		Registry:  registry,
	}).ExecuteApprovedReversibleRemediation(context.Background(), Input{
		FindingID: "finding-1",
		Action:    "custom.nonreversible",
	})
	if err == nil {
		t.Fatalf("ExecuteApprovedReversibleRemediation() error = nil, want nonreversible rejection")
	}
	if provider.request.Target != "" {
		t.Fatalf("nonreversible action reached provider: %#v", provider.request)
	}
}
