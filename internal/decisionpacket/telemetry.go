package decisionpacket

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/telemetry"
)

func recordDecisionRequested(ctx context.Context, workflow string) decisionworkflow.Workflow {
	boundedWorkflow := decisionworkflow.NormalizeWorkflow(workflow)
	metrics := observability.DecisionMetrics{Workflow: boundedWorkflow}
	observability.RecordDecisionRequested(ctx, metrics)
	recordDecisionWideEvent(ctx, "decision.requested", decisionworkflow.Telemetry{
		Workflow: boundedWorkflow, Operation: decisionworkflow.OperationRequested,
	})
	return boundedWorkflow
}

func recordDecisionPacketBuilt(ctx context.Context, workflow decisionworkflow.Workflow, packet *Packet, duration time.Duration) {
	if packet == nil {
		return
	}
	decisionState := decisionworkflow.NormalizeDecisionState(packet.Decision.State)
	coverageState := packetCoverageState(packet.CoverageGaps)
	actionState := packetActionState(packet.Actions)
	outcome := decisionworkflow.OutcomeNone
	metrics := observability.DecisionMetrics{
		Workflow: workflow, DecisionState: decisionState, CoverageState: coverageState,
		ActionState: actionState, Outcome: outcome, Duration: duration, HasDuration: true,
	}
	if !packet.Freshness.OldestObservedAt.IsZero() && !packet.GeneratedAt.Before(packet.Freshness.OldestObservedAt) {
		metrics.FreshnessAge = packet.GeneratedAt.Sub(packet.Freshness.OldestObservedAt)
		metrics.HasFreshnessAge = true
	}
	observability.RecordDecisionPacketBuilt(ctx, metrics)

	conflictState := decisionworkflow.ConflictNone
	if len(packet.Contradictions) > 0 {
		conflictState = decisionworkflow.ConflictPresent
	}
	recordDecisionWideEvent(ctx, "decision.packet.built", decisionworkflow.Telemetry{
		Workflow: workflow, Operation: decisionworkflow.OperationPacketBuilt,
		DecisionState: decisionState, CoverageState: coverageState,
		FreshnessState: decisionworkflow.NormalizeFreshnessState(packet.Freshness.State),
		ConflictState:  conflictState, ActionState: actionState, Outcome: outcome,
		SchemaVersion: packet.SchemaVersion, EvidenceCount: len(packet.Evidence),
		CoverageGapCount: len(packet.CoverageGaps), DurationMillis: duration.Milliseconds(),
	})
}

func recordDecisionWideEvent(ctx context.Context, name string, value decisionworkflow.Telemetry) {
	attrs, err := value.Attributes()
	if err != nil {
		return
	}
	telemetry.Event(ctx, name, attrs)
	telemetry.IncrementMain(ctx, name+".count", 1)
}

func packetCoverageState(gaps []CoverageGap) decisionworkflow.CoverageState {
	if len(gaps) == 0 {
		return decisionworkflow.CoverageComplete
	}
	selected := decisionworkflow.CoveragePartial
	selectedRank := coverageStateRank(selected)
	for _, gap := range gaps {
		state := decisionworkflow.NormalizeCoverageState(gap.State)
		if rank := coverageStateRank(state); rank > selectedRank {
			selected, selectedRank = state, rank
		}
	}
	return selected
}

func coverageStateRank(state decisionworkflow.CoverageState) int {
	switch state {
	case decisionworkflow.CoverageFailed:
		return 7
	case decisionworkflow.CoverageUnconfigured:
		return 6
	case decisionworkflow.CoverageUnsupported:
		return 5
	case decisionworkflow.CoverageStale:
		return 4
	case decisionworkflow.CoverageUnverified:
		return 3
	case decisionworkflow.CoverageUnknown:
		return 2
	case decisionworkflow.CoveragePartial:
		return 1
	default:
		return 0
	}
}

func packetActionState(actions []ActionProposal) decisionworkflow.ActionState {
	selected := decisionworkflow.ActionNone
	selectedRank := actionStateRank(selected)
	for _, action := range actions {
		state := decisionworkflow.NormalizeActionState(action.State)
		if rank := actionStateRank(state); rank > selectedRank {
			selected, selectedRank = state, rank
		}
	}
	return selected
}

func actionStateRank(state decisionworkflow.ActionState) int {
	switch state {
	case decisionworkflow.ActionVerified:
		return 7
	case decisionworkflow.ActionCompleted:
		return 6
	case decisionworkflow.ActionStarted:
		return 5
	case decisionworkflow.ActionApproved:
		return 4
	case decisionworkflow.ActionApprovalRequired:
		return 3
	case decisionworkflow.ActionProposal:
		return 2
	case decisionworkflow.ActionInformational:
		return 1
	default:
		return 0
	}
}
