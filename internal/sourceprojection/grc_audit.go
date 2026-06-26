package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcEventLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	eventLogID := firstAttribute(attrs, "event_log_id", "external_id")
	if eventLogID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	eventURN := projectionURN(tenantID, "grc_audit_event", provider, eventLogID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        eventURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "audit.event",
		Label:      firstAttribute(attrs, "action", "event_log_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"action":        firstAttribute(attrs, "action"),
			"event_log_id":  eventLogID,
			"source_system": provider,
		}),
	})
	if actorURN := grcEventActorURN(tenantID, provider, attrs); actorURN != "" {
		addEntity(entities, grcEventActorEntity(tenantID, event.GetSourceId(), actorURN, provider, attrs))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, eventURN, relationActedOn, map[string]string{
			"action":     firstAttribute(attrs, "action"),
			"actor_id":   firstAttribute(attrs, "actor_id"),
			"actor_type": grcEventActorType(attrs),
			"event_id":   event.GetId(),
		}))
	}
	for _, target := range grcEventTargets(attrs["targets"]) {
		targetURN := projectionURN(tenantID, "grc_audit_target", provider, target.typ, target.id)
		if targetURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "audit.target",
			Label:      eventActorLabel(target.typ, target.id),
			Attributes: grcAttributes(nil, map[string]string{
				"source_system": provider,
				"target_id":     target.id,
				"target_type":   target.typ,
			}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, targetURN, relationObservedOn, map[string]string{
			"action":      firstAttribute(attrs, "action"),
			"event_id":    event.GetId(),
			"match_type":  "grc_audit_event_target",
			"target_id":   target.id,
			"target_type": target.typ,
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

type grcEventTarget struct {
	typ string
	id  string
}

func grcEventTargets(raw string) []grcEventTarget {
	targets := []grcEventTarget{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		targetType, targetID, found := strings.Cut(part, ":")
		if !found {
			targetType = "resource"
			targetID = part
		}
		target := grcEventTarget{typ: strings.TrimSpace(targetType), id: strings.TrimSpace(targetID)}
		if target.id == "" {
			continue
		}
		key := target.typ + "\x00" + target.id
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func grcEventActorURN(tenantID string, provider string, attrs map[string]string) string {
	actorID := firstAttribute(attrs, "actor_id")
	if actorID == "" {
		return ""
	}
	actorType := grcEventActorType(attrs)
	if strings.EqualFold(actorType, "user") {
		return grcUserURN(tenantID, provider, actorID)
	}
	return projectionURN(tenantID, "grc_audit_actor", provider, actorType, actorID)
}

func grcEventActorEntity(tenantID string, sourceID string, actorURN string, provider string, attrs map[string]string) *ports.ProjectedEntity {
	actorType := grcEventActorType(attrs)
	actorID := firstAttribute(attrs, "actor_id")
	entityType := "audit.actor"
	if strings.EqualFold(actorType, "user") {
		entityType = "user"
	}
	attributes := map[string]string{
		"actor_id":      actorID,
		"actor_type":    actorType,
		"source_system": provider,
	}
	if entityType == "user" {
		attributes["user_id"] = actorID
	}
	return &ports.ProjectedEntity{
		URN:        actorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      eventActorLabel(actorType, actorID),
		Attributes: grcAttributes(nil, attributes),
	}
}

func grcEventActorType(attrs map[string]string) string {
	return firstNonEmpty(firstAttribute(attrs, "actor_type"), "resource")
}

func eventActorLabel(actorType string, actorID string) string {
	if strings.TrimSpace(actorType) == "" || strings.TrimSpace(actorType) == "resource" {
		return strings.TrimSpace(actorID)
	}
	return strings.TrimSpace(actorType) + ":" + strings.TrimSpace(actorID)
}
