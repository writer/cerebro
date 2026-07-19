package decisionworkflow

import (
	"errors"
	"testing"
)

func TestWorkflowAndStateValidationRejectsArbitraryValues(t *testing.T) {
	if _, err := ParseWorkflow("custom_dashboard"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ParseWorkflow() error = %v, want ErrInvalidState", err)
	}
	if _, err := ParseDecisionState("probably_safe"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ParseDecisionState() error = %v, want ErrInvalidState", err)
	}
	if _, err := ParseCoverageState("mostly_complete"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ParseCoverageState() error = %v, want ErrInvalidState", err)
	}
}

func TestCompletionRequiresDurableTerminalOutcome(t *testing.T) {
	base := Completion{
		Workflow: WorkflowFindingToVerifiedFix, DecisionID: "decision-1", DecisionState: DecisionSupported,
		Outcome: OutcomeVerifiedClosed, AuthenticatedTenant: true, Durable: true,
	}
	if !base.Completed() {
		t.Fatal("verified durable outcome should count as completed")
	}

	tests := map[string]func(*Completion){
		"missing decision":       func(value *Completion) { value.DecisionID = "" },
		"unauthenticated tenant": func(value *Completion) { value.AuthenticatedTenant = false },
		"not durable":            func(value *Completion) { value.Durable = false },
		"blocked decision":       func(value *Completion) { value.DecisionState = DecisionBlocked },
		"reopened finding":       func(value *Completion) { value.Reopened = true },
		"nonterminal outcome":    func(value *Completion) { value.Outcome = OutcomeNone },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if candidate.Completed() {
				t.Fatal("incomplete decision counted as completed")
			}
		})
	}
}

func TestAuditPacketCompletionRequiresExportReceipt(t *testing.T) {
	completion := Completion{
		Workflow: WorkflowContinuousEvidence, DecisionID: "decision-1", DecisionState: DecisionSupported,
		Outcome: OutcomeAuditPacketDelivered, AuthenticatedTenant: true, Durable: true,
	}
	if completion.Completed() {
		t.Fatal("audit packet without export receipt counted as delivered")
	}
	completion.AuditPacketExportReceiptID = "export-receipt-1"
	if !completion.Completed() {
		t.Fatal("audit packet with export receipt should count as delivered")
	}
}

func TestCompletionRequiresWorkflowTerminalOutcome(t *testing.T) {
	tests := []struct {
		name     string
		workflow Workflow
		outcome  Outcome
		want     bool
	}{
		{name: "change accepted", workflow: WorkflowChangeDecision, outcome: OutcomeAccepted, want: true},
		{name: "change not merely verified", workflow: WorkflowChangeDecision, outcome: OutcomeVerifiedClosed},
		{name: "fix verified", workflow: WorkflowFindingToVerifiedFix, outcome: OutcomeVerifiedClosed, want: true},
		{name: "fix not merely accepted", workflow: WorkflowFindingToVerifiedFix, outcome: OutcomeAccepted},
		{name: "continuous not merely accepted", workflow: WorkflowContinuousEvidence, outcome: OutcomeAccepted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completion := Completion{
				Workflow: test.workflow, DecisionID: "decision-1", DecisionState: DecisionSupported,
				Outcome: test.outcome, AuthenticatedTenant: true, Durable: true,
			}
			if got := completion.Completed(); got != test.want {
				t.Fatalf("Completed() = %v, want %v", got, test.want)
			}
		})
	}
}
