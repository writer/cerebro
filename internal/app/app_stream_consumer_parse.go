package app

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func sourceSystemFromTapType(eventType string) string {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) >= 3 {
		return strings.ToLower(strings.TrimSpace(parts[2]))
	}
	return ""
}

func parseTapType(eventType string) (system string, entityType string, action string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 5 {
		return "", "", ""
	}
	if len(parts) >= 5 && strings.EqualFold(parts[2], "activity") {
		return strings.ToLower(parts[3]), strings.ToLower(parts[4]), strings.ToLower(parts[len(parts)-1])
	}
	system = strings.ToLower(parts[2])
	entityType = strings.ToLower(parts[3])
	action = strings.ToLower(parts[len(parts)-1])
	return system, entityType, action
}

func isTapActivityType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.activity.")
}

func isTapInteractionType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.interaction.")
}

type tapInteractionParticipant struct {
	ID   string
	Name string
}

func parseTapActivityActor(raw any) (id string, name string) {
	switch actor := raw.(type) {
	case string:
		return strings.TrimSpace(actor), ""
	case map[string]any:
		id = strings.TrimSpace(anyToString(firstPresent(actor, "email", "id", "user_id", "actor_id")))
		name = strings.TrimSpace(anyToString(firstPresent(actor, "name", "display_name", "full_name")))
		return id, name
	default:
		return "", ""
	}
}

func parseTapActivityTarget(raw any, defaultSystem string) (nodeID string, kind graph.NodeKind, name string) {
	switch target := raw.(type) {
	case string:
		targetID := strings.TrimSpace(target)
		if targetID == "" {
			return "", "", ""
		}
		return fmt.Sprintf("%s:entity:%s", defaultSystem, targetID), graph.NodeKindCompany, targetID
	case map[string]any:
		targetID := strings.TrimSpace(anyToString(firstPresent(target, "id", "entity_id", "target_id")))
		if targetID == "" {
			return "", "", ""
		}
		targetType := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "type", "entity_type", "kind"))))
		if targetType == "" {
			targetType = "entity"
		}
		system := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "system", "source"))))
		if system == "" {
			system = defaultSystem
		}
		name = strings.TrimSpace(anyToString(firstPresent(target, "name", "display_name", "title")))
		return fmt.Sprintf("%s:%s:%s", system, targetType, targetID), mapBusinessEntityKind(targetType), name
	default:
		return "", "", ""
	}
}

func parseTapInteractionType(eventType string) (channel string, interactionType string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 4 || !strings.EqualFold(parts[2], "interaction") {
		return "", ""
	}
	channel = strings.ToLower(strings.TrimSpace(parts[3]))
	if len(parts) > 4 {
		interactionType = strings.ToLower(strings.Join(parts[4:], "_"))
	}
	return channel, interactionType
}
