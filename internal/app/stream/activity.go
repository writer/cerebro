package stream

import (
	"context"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func (r *Runtime) handleTapActivityEvent(ctx context.Context, source, activityType string, evt events.CloudEvent) error {
	plan, ok := BuildTapActivityEventPlan(source, activityType, evt)
	if !ok {
		return nil
	}

	_, err := r.mutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		applyTapActivityEventPlan(securityGraph, plan)
		return true, nil
	})
	return err
}

func applyTapActivityEventPlan(securityGraph *graph.Graph, plan *ActivityEventPlan) {
	if securityGraph == nil || plan == nil {
		return
	}
	if plan.Actor != nil {
		securityGraph.AddNode(plan.Actor)
	}
	if plan.Target != nil {
		securityGraph.AddNode(plan.Target)
	}
	if plan.Activity != nil {
		securityGraph.AddNode(plan.Activity)
	}
	if plan.ActorEdge != nil {
		securityGraph.AddEdge(plan.ActorEdge)
	}
	if plan.ActivityTarget != nil {
		securityGraph.AddEdge(plan.ActivityTarget)
	}
}
