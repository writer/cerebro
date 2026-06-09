package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func cerebroAPIAccessProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	serviceURN := projectionURN(tenantID, "service", "cerebro")
	accessURN := projectionURN(tenantID, "cerebro_api_access", firstNonEmpty(attrs["request_id"], event.GetId()))
	addEntity(entities, &ports.ProjectedEntity{
		URN:        serviceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "service",
		Label:      "Cerebro",
		Attributes: map[string]string{"service": "cerebro"},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accessURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "cerebro.api_access",
		Label:      strings.TrimSpace(firstNonEmpty(attrs["route"], attrs["connect_procedure"], event.GetId())),
		Attributes: cerebroAccessEntityAttributes(event, attrs),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceURN, accessURN, relationHasEvidence, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), accessURN, serviceURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	if principalURN := cerebroPrincipalURN(tenantID, attrs); principalURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        principalURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "cerebro.principal",
			Label:      cerebroPrincipalLabel(attrs),
			Attributes: cerebroPrincipalAttributes(attrs),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, accessURN, relationHasEvidence, map[string]string{"event_id": event.GetId(), "outcome": strings.TrimSpace(attrs["outcome_result"]), "at": eventObservedAt(event)}))
		if actor := strings.TrimSpace(firstNonEmpty(attrs["actor_user"], attrs["principal"])); actor != "" {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), principalURN, actor, event.GetOccurredAt())
		}
	}
	return identityProjectionResult(entities, links)
}

func cerebroAccessEntityAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string) map[string]string {
	out := map[string]string{"event_id": event.GetId(), "source_product": "cerebro", "at": eventObservedAt(event)}
	for _, key := range []string{"auth_mode", "client_ip", "connect_code", "connect_procedure", "denial_reason", "device_id", "duration_ms", "effective_status_code", "method", "operation_family", "operation_type", "outcome_result", "remote_ip", "request_id", "risk_level", "risk_score", "route", "source_ip", "status_code", "tenant_mismatch"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}

func cerebroPrincipalURN(tenantID string, attrs map[string]string) string {
	value := firstNonEmpty(attrs["principal"], attrs["device_id"], attrs["client_id"], attrs["credential_id"])
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "cerebro_principal", normalizeIdentifier(value))
}

func cerebroPrincipalLabel(attrs map[string]string) string {
	return firstNonEmpty(attrs["principal"], attrs["device_id"], attrs["client_id"], attrs["credential_id"])
}

func cerebroPrincipalAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{"source_product": "cerebro"}
	for _, key := range []string{"auth_mode", "client_id", "credential_id", "device_id", "principal", "principal_tenant_id", "risk_level", "risk_score"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}
