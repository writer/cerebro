package transport

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/observability"
)

// RecordDecisionAction records one durable action only when the request names
// a bounded decision workflow. Legacy knowledge actions remain outside the
// decision-workflow product metric.
func RecordDecisionAction(ctx context.Context, request *cerebrov1.WriteActionRequest, metadata Metadata, result *knowledge.ActionWriteResult) {
	if request == nil || result == nil || result.DurabilityStatus != knowledge.DurabilityRecorded {
		return
	}
	workflowValue, _ := metadata["decision_workflow"].(string)
	workflow, err := decisionworkflow.ParseWorkflow(workflowValue)
	if err != nil {
		return
	}
	decisionState, _ := metadata["decision_state"].(string)
	actionState, _ := metadata["action_state"].(string)
	observability.RecordDecisionAction(ctx, observability.DecisionMetrics{
		Workflow: workflow, DecisionState: decisionworkflow.NormalizeDecisionState(decisionState),
		ActionState: decisionworkflow.NormalizeActionState(actionState),
	})
}
