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

	decision := trustedEndpointNormalizeDecision(attrs["decision"])
	eventURN := projectionURN(tenantID, "trusted_endpoint_event", event.GetKind(), event.GetId())
	eventAttrs := map[string]string{
		"action":              strings.TrimSpace(attrs["action"]),
		"control_id":          strings.TrimSpace(attrs["control_id"]),
		"decision":            decision,
		"event_id":            event.GetId(),
		"finding_id":          strings.TrimSpace(attrs["finding_id"]),
		"kind":                event.GetKind(),
		"observation_table":   strings.TrimSpace(attrs["observation_table"]),
		"outcome_result":      strings.TrimSpace(attrs["outcome_result"]),
		"severity":            strings.TrimSpace(attrs["severity"]),
		"severity_normalized": trustedEndpointNormalizeSeverity(attrs["severity"]),
		"status_normalized":   trustedEndpointNormalizeStatus(event.GetKind(), attrs, decision),
		"source_product":      "trusted_endpoint",
		"at":                  eventObservedAt(event),
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
	entitiesOut, linksOut := entitiesAndLinks(entities, links)
	return entitiesOut, linksOut, nil
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

func trustedEndpointNormalizeDecision(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deny", "denied", "block", "blocked", "fail", "failed", "reject", "rejected":
		return "deny"
	case "allow", "allowed", "pass", "passed", "ok", "permit", "permitted", "approved":
		return "allow"
	case "error", "errored":
		return "error"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func trustedEndpointNormalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "crit", "p0", "sev0":
		return "CRITICAL"
	case "high", "p1", "sev1":
		return "HIGH"
	case "medium", "med", "moderate", "p2", "sev2":
		return "MEDIUM"
	case "low", "p3", "sev3":
		return "LOW"
	case "info", "informational", "none", "p4", "sev4":
		return "INFO"
	case "":
		return "UNKNOWN"
	default:
		return strings.ToUpper(strings.TrimSpace(value))
	}
}

func trustedEndpointNormalizeStatus(kind string, attrs map[string]string, decision string) string {
	switch strings.TrimSpace(kind) {
	case "trusted_endpoint.trust_gate_decision":
		switch decision {
		case "deny", "error":
			return "failing"
		case "allow":
			return "passing"
		}
	case "trusted_endpoint.security_finding":
		if trustedEndpointResolved(attrs) {
			return "passing"
		}
		return "failing"
	}
	return trustedEndpointStatusValue(firstNonEmpty(attrs["status"], attrs["outcome_result"]))
}

func trustedEndpointStatusValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fail", "failed", "failing", "non_compliant", "noncompliant", "violation", "open":
		return "failing"
	case "pass", "passed", "passing", "compliant", "ok", "success", "resolved", "closed":
		return "passing"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func trustedEndpointResolved(attrs map[string]string) bool {
	status := strings.ToLower(strings.TrimSpace(attrs["status"]))
	switch status {
	case "resolved", "closed", "remediated", "fixed":
		return true
	}
	return strings.TrimSpace(attrs["resolved_at"]) != ""
}
