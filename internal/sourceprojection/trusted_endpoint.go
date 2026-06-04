package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func trustedEndpointProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	agentID := firstNonEmpty(
		attrs["agent_id"],
		stringValue(payload, "agent_id"),
		attrs["device_id"],
		stringValue(payload, "device_id"),
	)
	if agentID == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	agentURN := projectionURN(tenantID, "trusted_endpoint_agent", agentID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        agentURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "trusted_endpoint.agent",
		Label:      firstNonEmpty(attrs["hostname"], stringValue(payload, "hostname"), agentID),
		Attributes: map[string]string{
			"agent_id":       agentID,
			"device_id":      strings.TrimSpace(attrs["device_id"]),
			"hardware_key":   strings.TrimSpace(attrs["hardware_key"]),
			"hostname":       strings.TrimSpace(attrs["hostname"]),
			"source_product": "trusted_endpoint",
		},
	})
	endpointURN := trustedEndpointDeviceProjection(entities, links, tenantID, event, attrs, payload, agentURN, agentID)

	eventURN := projectionURN(tenantID, "trusted_endpoint_event", event.GetKind(), event.GetId())
	eventAttrs := map[string]string{
		"action":            strings.TrimSpace(attrs["action"]),
		"control_id":        strings.TrimSpace(attrs["control_id"]),
		"event_id":          event.GetId(),
		"finding_id":        strings.TrimSpace(attrs["finding_id"]),
		"kind":              event.GetKind(),
		"observation_table": strings.TrimSpace(attrs["observation_table"]),
		"outcome_result":    strings.TrimSpace(attrs["outcome_result"]),
		"severity":          strings.TrimSpace(attrs["severity"]),
		"source_product":    "trusted_endpoint",
		"at":                eventObservedAt(event),
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        eventURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: trustedEndpointEventEntityType(event.GetKind()),
		Label:      trustedEndpointEventLabel(event, attrs),
		Attributes: eventAttrs,
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), agentURN, eventURN, relationHasEvidence, map[string]string{
		"event_id": event.GetId(),
		"kind":     event.GetKind(),
		"at":       eventObservedAt(event),
	}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, agentURN, relationObservedOn, map[string]string{
		"event_id": event.GetId(),
		"kind":     event.GetKind(),
		"at":       eventObservedAt(event),
	}))
	trustedEndpointSpecificProjection(entities, links, tenantID, event, attrs, payload, eventURN, endpointURN)
	entitiesOut, linksOut := entitiesAndLinks(entities, links)
	return entitiesOut, linksOut, nil
}

func trustedEndpointDeviceProjection(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, payload map[string]any, agentURN string, agentID string) string {
	endpointID := firstNonEmpty(attrs["device_id"], stringValue(payload, "device_id"), attrs["hardware_key"], agentID)
	endpointURN := projectionURN(tenantID, "trusted_endpoint_device", endpointID)
	if endpointURN == "" {
		return ""
	}
	endpointAttrs := map[string]string{
		"agent_id":       agentID,
		"device_id":      endpointID,
		"hardware_uuid":  firstNonEmpty(attrs["hardware_key"], stringValue(payload, "hardware_uuid")),
		"hostname":       firstNonEmpty(attrs["hostname"], stringValue(payload, "hostname")),
		"serial_number":  firstNonEmpty(attrs["serial_number"], stringValue(payload, "serial_number")),
		"source_product": "trusted_endpoint",
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        endpointURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "trusted_endpoint.device",
		Label:      firstNonEmpty(endpointAttrs["hostname"], endpointID),
		Attributes: endpointAttrs,
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), agentURN, endpointURN, relationRepresents, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	addEndpointIdentifierLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, "device_id", endpointID, "1.00")
	addEndpointIdentifierLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, "hardware_uuid", endpointAttrs["hardware_uuid"], "0.98")
	addEndpointIdentifierLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, "serial_number", endpointAttrs["serial_number"], "0.95")
	addEndpointIdentifierLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, "hostname", endpointAttrs["hostname"], "0.60")
	addEndpointIdentifierLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, "trusted_endpoint_agent_id", agentID, "0.90")
	return endpointURN
}

func trustedEndpointSpecificProjection(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, payload map[string]any, eventURN string, endpointURN string) {
	switch event.GetKind() {
	case "trusted_endpoint.security_finding":
		findingID := firstNonEmpty(attrs["finding_id"], stringValue(payload, "finding_id"), event.GetId())
		findingURN := projectionURN(tenantID, "finding", findingID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "finding",
			Label:      findingID,
			Attributes: map[string]string{
				"finding_id": findingID,
				"severity":   firstNonEmpty(attrs["severity"], stringValue(payload, "severity")),
				"source":     "trusted_endpoint",
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		if endpointURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, endpointURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		}
	case "trusted_endpoint.grc_evidence":
		controlID := firstNonEmpty(attrs["control_id"], stringValue(payload, "control_id"))
		controlURN := projectionURN(tenantID, "grc_control", controlID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        controlURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "grc.control",
			Label:      controlID,
			Attributes: map[string]string{"control_id": controlID, "source": "trusted_endpoint"},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, controlURN, relationSupports, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	case "trusted_endpoint.repo_worktree_context", "trusted_endpoint.ai_workflow_risk":
		repoID := firstNonEmpty(attrs["repo_path_hash"], stringValue(payload, "repo_path_hash"), stringValue(payload, "repository"))
		repoURN := projectionURN(tenantID, "trusted_endpoint_repo", repoID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "trusted_endpoint.repo",
			Label:      repoID,
			Attributes: map[string]string{"repo_path_hash": repoID, "source": "trusted_endpoint"},
		})
		if endpointURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, repoURN, relationContains, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, repoURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	case "trusted_endpoint.action_outcome", "trusted_endpoint.trust_gate_decision":
		action := firstNonEmpty(attrs["action"], stringValue(payload, "action"), event.GetKind())
		actionURN := projectionURN(tenantID, "trusted_endpoint_action", action, event.GetId())
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "trusted_endpoint.action",
			Label:      action,
			Attributes: map[string]string{
				"action":         action,
				"decision":       firstNonEmpty(attrs["decision"], stringValue(payload, "decision")),
				"outcome_result": firstNonEmpty(attrs["outcome_result"], stringValue(payload, "outcome")),
				"source":         "trusted_endpoint",
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actionURN, eventURN, relationHasEvidence, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		if endpointURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actionURN, endpointURN, relationTargeted, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		}
	}
}

func trustedEndpointEventEntityType(kind string) string {
	switch strings.TrimSpace(kind) {
	case "trusted_endpoint.security_finding":
		return "trusted_endpoint.security_finding"
	case "trusted_endpoint.grc_evidence":
		return "trusted_endpoint.grc_evidence"
	case "trusted_endpoint.trust_gate_decision":
		return "trusted_endpoint.trust_gate_decision"
	case "trusted_endpoint.action_outcome":
		return "trusted_endpoint.action_outcome"
	default:
		return "trusted_endpoint.observation"
	}
}

func trustedEndpointEventLabel(event *cerebrov1.EventEnvelope, attrs map[string]string) string {
	return firstNonEmpty(
		attrs["finding_id"],
		attrs["control_id"],
		attrs["action"],
		attrs["observation_table"],
		event.GetKind(),
	)
}
