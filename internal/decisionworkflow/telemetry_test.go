package decisionworkflow

import (
	"errors"
	"testing"
)

func TestTelemetryRejectsUnboundedStates(t *testing.T) {
	_, err := (Telemetry{Workflow: WorkflowChangeDecision, Operation: OperationPacketBuilt, ActionState: "run_anything"}).Attributes()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Attributes() error = %v, want ErrInvalidState", err)
	}
}

func TestTelemetryAcceptsBoundedPacketState(t *testing.T) {
	_, err := (Telemetry{
		Workflow: WorkflowChangeDecision, Operation: OperationPacketBuilt,
		DecisionState: DecisionSupportedWithGaps, CoverageState: CoveragePartial,
		FreshnessState: FreshnessStale, ConflictState: ConflictPresent, ActionState: ActionProposal,
		EvidenceCount: 4, CoverageGapCount: 1, DurationMillis: 25,
	}).Attributes()
	if err != nil {
		t.Fatalf("Attributes() error = %v", err)
	}
}
