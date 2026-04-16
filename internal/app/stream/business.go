package stream

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func (r *Runtime) handleTapBusinessEvent(ctx context.Context, eventType string, evt events.CloudEvent) error {
	system, entityType, action := ParseTapType(eventType)
	if system == "" {
		return nil
	}

	var refreshEventCorrelations bool
	_, err := r.mutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		var existingProperties map[string]any
		entityID := strings.TrimSpace(AnyToString(evt.Data["entity_id"]))
		if entityID == "" {
			entityID = strings.TrimSpace(AnyToString(evt.Data["id"]))
		}
		if entityID != "" {
			nodeID := fmt.Sprintf("%s:%s:%s", system, entityType, entityID)
			if existingNode, ok := securityGraph.GetNode(nodeID); ok && existingNode != nil && existingNode.Properties != nil {
				existingProperties = existingNode.Properties
			}
		}

		plan, ok := BuildTapBusinessEventPlan(system, entityType, action, eventType, evt, existingProperties)
		if !ok {
			return false, nil
		}
		applyTapBusinessEventPlan(securityGraph, plan)
		refreshEventCorrelations = shouldRefreshEventCorrelations(securityGraph, []string{plan.Node.ID})
		return true, nil
	})
	if err != nil {
		return err
	}
	if refreshEventCorrelations {
		r.queueEventCorrelationRefresh("tap_business")
	}
	return nil
}

func applyTapBusinessEventPlan(securityGraph *graph.Graph, plan *BusinessEventPlan) {
	if securityGraph == nil || plan == nil || plan.Node == nil {
		return
	}

	securityGraph.AddNode(plan.Node)
	for _, stub := range plan.TargetStubs {
		if stub == nil || stub.ID == "" {
			continue
		}
		if _, ok := securityGraph.GetNode(stub.ID); ok {
			continue
		}
		securityGraph.AddNode(stub)
	}
	for _, edge := range plan.Edges {
		graph.AddEdgeIfMissing(securityGraph, edge)
	}
}
