// Package transport adapts knowledge write results to public protobuf
// responses while keeping transport mapping out of bootstrap.
package transport

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/knowledge"
)

// DecisionResponse maps one durable decision write result.
func DecisionResponse(result *knowledge.DecisionWriteResult) *cerebrov1.WriteDecisionResponse {
	return &cerebrov1.WriteDecisionResponse{
		DecisionId:              result.DecisionID,
		TargetCount:             result.TargetCount,
		EventId:                 result.EventID,
		DurabilityStatus:        result.DurabilityStatus,
		ProjectionStatus:        result.ProjectionStatus,
		ProjectionErrorCategory: result.ProjectionErrorCategory,
	}
}

// ActionResponse maps one durable action write result.
func ActionResponse(result *knowledge.ActionWriteResult) *cerebrov1.WriteActionResponse {
	return &cerebrov1.WriteActionResponse{
		ActionId:                result.ActionID,
		DecisionId:              result.DecisionID,
		TargetCount:             result.TargetCount,
		EventId:                 result.EventID,
		DurabilityStatus:        result.DurabilityStatus,
		ProjectionStatus:        result.ProjectionStatus,
		ProjectionErrorCategory: result.ProjectionErrorCategory,
	}
}

// OutcomeResponse maps one durable outcome write result.
func OutcomeResponse(result *knowledge.OutcomeWriteResult) *cerebrov1.WriteOutcomeResponse {
	return &cerebrov1.WriteOutcomeResponse{
		OutcomeId:               result.OutcomeID,
		DecisionId:              result.DecisionID,
		TargetCount:             result.TargetCount,
		EventId:                 result.EventID,
		DurabilityStatus:        result.DurabilityStatus,
		ProjectionStatus:        result.ProjectionStatus,
		ProjectionErrorCategory: result.ProjectionErrorCategory,
	}
}
