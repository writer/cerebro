package transport

import (
	"testing"

	"github.com/writer/cerebro/internal/knowledge"
)

func TestWriteResponsesPreserveDurabilityAndProjectionState(t *testing.T) {
	decision := DecisionResponse(&knowledge.DecisionWriteResult{
		DecisionID: "decision-1", TargetCount: 2, EventID: "event-1",
		DurabilityStatus: knowledge.DurabilityRecorded, ProjectionStatus: knowledge.ProjectionFailed,
		ProjectionErrorCategory: knowledge.ProjectionErrorGraph,
	})
	if decision.GetDecisionId() != "decision-1" || decision.GetTargetCount() != 2 || decision.GetEventId() != "event-1" || decision.GetDurabilityStatus() != knowledge.DurabilityRecorded || decision.GetProjectionStatus() != knowledge.ProjectionFailed || decision.GetProjectionErrorCategory() != knowledge.ProjectionErrorGraph {
		t.Fatalf("DecisionResponse() = %#v", decision)
	}

	action := ActionResponse(&knowledge.ActionWriteResult{
		ActionID: "action-1", DecisionID: "decision-1", TargetCount: 3, EventID: "event-2",
		DurabilityStatus: knowledge.DurabilityRecorded, ProjectionStatus: knowledge.ProjectionProjected,
	})
	if action.GetActionId() != "action-1" || action.GetDecisionId() != "decision-1" || action.GetTargetCount() != 3 || action.GetEventId() != "event-2" || action.GetDurabilityStatus() != knowledge.DurabilityRecorded || action.GetProjectionStatus() != knowledge.ProjectionProjected {
		t.Fatalf("ActionResponse() = %#v", action)
	}

	outcome := OutcomeResponse(&knowledge.OutcomeWriteResult{
		OutcomeID: "outcome-1", DecisionID: "decision-1", TargetCount: 4, EventID: "event-3",
		DurabilityStatus: knowledge.DurabilityNotRecorded, ProjectionStatus: knowledge.ProjectionNotConfigured,
	})
	if outcome.GetOutcomeId() != "outcome-1" || outcome.GetDecisionId() != "decision-1" || outcome.GetTargetCount() != 4 || outcome.GetEventId() != "event-3" || outcome.GetDurabilityStatus() != knowledge.DurabilityNotRecorded || outcome.GetProjectionStatus() != knowledge.ProjectionNotConfigured {
		t.Fatalf("OutcomeResponse() = %#v", outcome)
	}
}
