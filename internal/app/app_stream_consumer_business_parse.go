package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

type tapBusinessEventPlan struct {
	Node        *graph.Node
	TargetStubs []*graph.Node
	Edges       []*graph.Edge
}

func buildTapBusinessEventPlan(system, entityType, action, eventType string, evt events.CloudEvent, existingProperties map[string]any) (*tapBusinessEventPlan, bool) {
	entityID := strings.TrimSpace(anyToString(evt.Data["entity_id"]))
	if entityID == "" {
		entityID = strings.TrimSpace(anyToString(evt.Data["id"]))
	}
	if entityID == "" {
		return nil, false
	}

	snapshot := mapFromAny(evt.Data["snapshot"])
	changes := mapFromAny(evt.Data["changes"])
	nodeID := fmt.Sprintf("%s:%s:%s", system, entityType, entityID)
	properties := map[string]any{
		"source_system": system,
		"entity_type":   entityType,
		"action":        action,
		"event_type":    eventType,
		"event_time":    evt.Time.UTC().Format(time.RFC3339),
		"changes":       changes,
	}
	for key, value := range snapshot {
		properties[key] = value
	}
	for key, value := range deriveComputedFields(system, entityType, snapshot, changes, existingProperties, evt.Time) {
		properties[key] = value
	}
	if action == "deleted" {
		properties["inactive"] = true
	}

	node := &graph.Node{
		ID:         nodeID,
		Kind:       mapBusinessEntityKind(entityType),
		Name:       coalesceString(anyToString(snapshot["name"]), entityID),
		Provider:   system,
		Properties: properties,
		Risk:       graph.RiskNone,
	}

	edges := extractBusinessEdges(system, entityType, nodeID, snapshot)
	targetStubs := make([]*graph.Node, 0, len(edges))
	seenTargets := make(map[string]struct{}, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if _, ok := seenTargets[edge.Target]; ok {
			continue
		}
		seenTargets[edge.Target] = struct{}{}

		targetParts := strings.SplitN(edge.Target, ":", 3)
		targetKind := graph.NodeKindCompany
		targetProvider := system
		targetName := edge.Target
		if len(targetParts) == 3 {
			targetProvider = targetParts[0]
			targetKind = mapBusinessEntityKind(targetParts[1])
			targetName = targetParts[2]
		}
		targetStubs = append(targetStubs, &graph.Node{
			ID:       edge.Target,
			Kind:     targetKind,
			Name:     targetName,
			Provider: targetProvider,
			Risk:     graph.RiskNone,
		})
	}

	return &tapBusinessEventPlan{
		Node:        node,
		TargetStubs: targetStubs,
		Edges:       edges,
	}, true
}
