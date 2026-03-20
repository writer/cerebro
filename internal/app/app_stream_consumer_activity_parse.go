package app

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

type tapActivityEventPlan struct {
	Actor          *graph.Node
	Target         *graph.Node
	Activity       *graph.Node
	ActorEdge      *graph.Edge
	ActivityTarget *graph.Edge
}

func buildTapActivityEventPlan(source, activityType string, evt events.CloudEvent) (*tapActivityEventPlan, bool) {
	actorID, actorName := parseTapActivityActor(evt.Data["actor"])
	if actorID == "" {
		actorID = strings.TrimSpace(anyToString(firstPresent(evt.Data, "actor_email", "actor_id", "user_email", "user_id")))
	}
	if actorID == "" {
		return nil, false
	}
	actorNodeID := actorID
	if !strings.Contains(actorNodeID, ":") {
		actorNodeID = "person:" + strings.ToLower(actorNodeID)
	}

	targetNodeID, targetKind, targetName := parseTapActivityTarget(evt.Data["target"], source)
	if targetNodeID == "" {
		targetID := strings.TrimSpace(anyToString(firstPresent(evt.Data, "entity_id", "target_id", "id")))
		if targetID != "" {
			targetNodeID = fmt.Sprintf("%s:entity:%s", source, targetID)
			targetKind = graph.NodeKindCompany
			targetName = targetID
		}
	}
	if targetNodeID == "" {
		return nil, false
	}

	occurredAt := evt.Time.UTC()
	if ts, ok := parseTimeValue(firstPresent(evt.Data, "timestamp", "event_time", "occurred_at")); ok {
		occurredAt = ts.UTC()
	}
	action := strings.TrimSpace(anyToString(evt.Data["action"]))
	if action == "" {
		action = activityType
	}

	activityID := strings.TrimSpace(evt.ID)
	if activityID == "" {
		activityID = fmt.Sprintf("%d", occurredAt.UnixNano())
	}
	activityKind := deriveTapActivityNodeKind(source, activityType, evt.Data)
	activityNodeID := fmt.Sprintf("%s:%s:%s:%s", tapActivityNodePrefix(activityKind), source, activityType, activityID)
	metadata := mapFromAny(evt.Data["metadata"])
	if metadata == nil {
		metadata = map[string]any{}
	}
	writeMeta := graph.NormalizeWriteMetadata(
		occurredAt,
		occurredAt,
		nil,
		source,
		evt.ID,
		0.8,
		graph.WriteMetadataDefaults{
			Now:               occurredAt,
			SourceSystem:      source,
			SourceEventID:     evt.ID,
			SourceEventPrefix: "tap_activity",
			DefaultConfidence: 0.8,
		},
	)

	activityProps := map[string]any{
		"event_type":           evt.Type,
		"legacy_activity_type": activityType,
		"action":               action,
		"metadata":             metadata,
	}
	writeMeta.ApplyTo(activityProps)
	applyTapActivityKindProperties(activityProps, activityKind, activityID, activityType, action, actorNodeID, occurredAt, evt.Data)

	targetEdgeKind := graph.EdgeKindInteractedWith
	if activityKind != graph.NodeKindActivity {
		targetEdgeKind = graph.EdgeKindTargets
	}

	return &tapActivityEventPlan{
		Actor: &graph.Node{
			ID:       actorNodeID,
			Kind:     graph.NodeKindPerson,
			Name:     coalesceString(actorName, actorID),
			Provider: source,
			Risk:     graph.RiskNone,
			Properties: map[string]any{
				"email": actorID,
			},
		},
		Target: &graph.Node{
			ID:         targetNodeID,
			Kind:       targetKind,
			Name:       coalesceString(targetName, targetNodeID),
			Provider:   source,
			Risk:       graph.RiskNone,
			Properties: map[string]any{"source_system": source},
		},
		Activity: &graph.Node{
			ID:         activityNodeID,
			Kind:       activityKind,
			Name:       coalesceString(action, activityType),
			Provider:   source,
			Risk:       graph.RiskNone,
			Properties: activityProps,
		},
		ActorEdge: &graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", actorNodeID, activityNodeID, graph.EdgeKindInteractedWith),
			Source: actorNodeID,
			Target: activityNodeID,
			Kind:   graph.EdgeKindInteractedWith,
			Effect: graph.EdgeEffectAllow,
			Risk:   graph.RiskNone,
			Properties: map[string]any{
				"source_system": source,
			},
		},
		ActivityTarget: &graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", activityNodeID, targetNodeID, targetEdgeKind),
			Source: activityNodeID,
			Target: targetNodeID,
			Kind:   targetEdgeKind,
			Effect: graph.EdgeEffectAllow,
			Risk:   graph.RiskNone,
			Properties: map[string]any{
				"source_system": source,
			},
		},
	}, true
}
