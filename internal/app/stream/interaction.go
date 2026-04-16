package stream

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/setutil"
)

func (r *Runtime) handleTapInteractionEvent(ctx context.Context, eventType string, evt events.CloudEvent) error {
	plan, ok := BuildTapInteractionEventPlan(eventType, evt)
	if !ok {
		return nil
	}

	_, err := r.mutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		applyTapInteractionEventPlan(securityGraph, plan)
		return true, nil
	})
	return err
}

func applyTapInteractionEventPlan(securityGraph *graph.Graph, plan *InteractionEventPlan) {
	if securityGraph == nil || plan == nil {
		return
	}
	for _, participant := range plan.Participants {
		upsertTapInteractionPersonNode(securityGraph, participant, plan.Channel, plan.OccurredAt)
	}

	for i := 0; i < len(plan.Participants); i++ {
		for j := i + 1; j < len(plan.Participants); j++ {
			graph.UpsertInteractionEdge(securityGraph, graph.InteractionEdge{
				SourcePersonID: plan.Participants[i].ID,
				TargetPersonID: plan.Participants[j].ID,
				Channel:        plan.Channel,
				Type:           plan.InteractionType,
				Timestamp:      plan.OccurredAt,
				Duration:       plan.Duration,
				Weight:         plan.Weight,
			})
		}
	}
}

func upsertTapInteractionPersonNode(securityGraph *graph.Graph, participant InteractionParticipant, channel string, occurredAt time.Time) {
	if securityGraph == nil {
		return
	}
	personID := NormalizeTapInteractionPersonID(participant.ID)
	if personID == "" {
		return
	}

	properties := make(map[string]any)
	nodeKind := graph.NodeKindPerson
	nodeName := strings.TrimSpace(participant.Name)
	provider := strings.ToLower(strings.TrimSpace(channel))

	if existing, ok := securityGraph.GetNode(personID); ok && existing != nil {
		for key, value := range MapFromAny(existing.Properties) {
			properties[key] = value
		}
		if existing.Kind != "" {
			nodeKind = existing.Kind
		}
		if nodeKind == graph.NodeKindUser {
			nodeKind = graph.NodeKindPerson
		}
		if strings.TrimSpace(nodeName) == "" {
			nodeName = strings.TrimSpace(existing.Name)
		}
		if provider == "" {
			provider = strings.TrimSpace(existing.Provider)
		}
	}

	if strings.TrimSpace(nodeName) == "" {
		nodeName = strings.TrimPrefix(personID, "person:")
	}
	if !strings.Contains(nodeName, "@") {
		nodeName = strings.TrimSpace(nodeName)
	}

	email := strings.TrimPrefix(personID, "person:")
	if strings.Contains(email, "@") && strings.TrimSpace(AnyToString(properties["email"])) == "" {
		properties["email"] = email
	}

	sources := make(map[string]struct{})
	for _, source := range StringSliceFromAny(properties["source_systems"]) {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			continue
		}
		sources[source] = struct{}{}
	}
	if provider != "" {
		sources[provider] = struct{}{}
		properties["source_system"] = provider
	}
	if len(sources) > 0 {
		properties["source_systems"] = setutil.SortedStrings(sources)
	}
	if !occurredAt.IsZero() {
		properties["last_seen"] = occurredAt.UTC().Format(time.RFC3339)
	}

	securityGraph.AddNode(&graph.Node{
		ID:         personID,
		Kind:       nodeKind,
		Name:       nodeName,
		Provider:   provider,
		Properties: properties,
		Risk:       graph.RiskNone,
	})
}
