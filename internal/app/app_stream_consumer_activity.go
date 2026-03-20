package app

import (
	"context"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func (a *App) handleTapActivityEvent(ctx context.Context, source, activityType string, evt events.CloudEvent) error {
	plan, ok := buildTapActivityEventPlan(source, activityType, evt)
	if !ok {
		return nil
	}

	_, err := a.MutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		applyTapActivityEventPlan(securityGraph, plan)
		return true, nil
	})
	return err
}

func applyTapActivityEventPlan(securityGraph *graph.Graph, plan *tapActivityEventPlan) {
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
