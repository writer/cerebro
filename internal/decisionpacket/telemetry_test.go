package decisionpacket

import (
	"testing"

	"github.com/writer/cerebro/internal/decisionworkflow"
)

func TestPacketCoverageStateUsesHighestImpactGap(t *testing.T) {
	gaps := []CoverageGap{{State: CoveragePartial}, {State: CoverageStale}, {State: CoverageUnconfigured}}
	if got := packetCoverageState(gaps); got != decisionworkflow.CoverageUnconfigured {
		t.Fatalf("packetCoverageState() = %q, want %q", got, decisionworkflow.CoverageUnconfigured)
	}
	if got := packetCoverageState(nil); got != decisionworkflow.CoverageComplete {
		t.Fatalf("packetCoverageState(nil) = %q, want %q", got, decisionworkflow.CoverageComplete)
	}
}

func TestPacketActionStateUsesMostAdvancedBoundedState(t *testing.T) {
	actions := []ActionProposal{{State: ActionInformational}, {State: ActionStateProposal}, {State: ActionApprovalRequired}}
	if got := packetActionState(actions); got != decisionworkflow.ActionApprovalRequired {
		t.Fatalf("packetActionState() = %q, want %q", got, decisionworkflow.ActionApprovalRequired)
	}
}
