package app

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/setutil"
)

func (a *App) handleTapInteractionEvent(ctx context.Context, eventType string, evt events.CloudEvent) error {
	plan, ok := buildTapInteractionEventPlan(eventType, evt)
	if !ok {
		return nil
	}

	_, err := a.MutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		applyTapInteractionEventPlan(a, securityGraph, plan)
		return true, nil
	})
	return err
}

func applyTapInteractionEventPlan(a *App, securityGraph *graph.Graph, plan *tapInteractionEventPlan) {
	if a == nil || securityGraph == nil || plan == nil {
		return
	}
	for _, participant := range plan.Participants {
		a.upsertTapInteractionPersonNode(securityGraph, participant, plan.Channel, plan.OccurredAt)
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

func (a *App) upsertTapInteractionPersonNode(securityGraph *graph.Graph, participant tapInteractionParticipant, channel string, occurredAt time.Time) {
	if securityGraph == nil {
		return
	}
	personID := normalizeTapInteractionPersonID(participant.ID)
	if personID == "" {
		return
	}

	properties := make(map[string]any)
	nodeKind := graph.NodeKindPerson
	nodeName := strings.TrimSpace(participant.Name)
	provider := strings.ToLower(strings.TrimSpace(channel))

	if existing, ok := securityGraph.GetNode(personID); ok && existing != nil {
		for key, value := range mapFromAny(existing.Properties) {
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
	if strings.Contains(email, "@") && strings.TrimSpace(anyToString(properties["email"])) == "" {
		properties["email"] = email
	}

	sources := make(map[string]struct{})
	for _, source := range stringSliceFromAny(properties["source_systems"]) {
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
