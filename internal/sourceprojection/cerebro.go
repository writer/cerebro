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
	routeURN := cerebroRouteURN(tenantID, attrs)
	if routeURN != "" {
		addCerebroRouteEntities(entities, links, tenantID, event, attrs, serviceURN, accessURN, routeURN)
	}
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
		if routeURN != "" {
			cerebroLinkPrincipalRouteAccess(links, tenantID, event, attrs, principalURN, routeURN)
		}
		credentialURN := cerebroCredentialURN(tenantID, attrs)
		if credentialURN != "" {
			addCerebroCredentialEntities(entities, links, tenantID, event, attrs, principalURN, credentialURN, routeURN)
		}
		addCerebroScopeEntities(entities, links, tenantID, event, attrs, principalURN, credentialURN, routeURN)
	}
	return identityProjectionResult(entities, links)
}

func cerebroAccessEntityAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string) map[string]string {
	out := map[string]string{"event_id": event.GetId(), "source_product": "cerebro", "at": eventObservedAt(event)}
	for _, key := range []string{"auth_mode", "client_id", "client_ip", "connect_code", "connect_procedure", "credential_id", "denial_reason", "device_id", "duration_ms", "effective_status_code", "effective_tenant_id", "matched_scope", "method", "missing_scopes", "operation_family", "operation_type", "outcome_result", "principal_tenant_id", "remote_ip", "request_id", "requested_tenant_id", "required_scopes", "risk_level", "risk_score", "route", "scopes", "sensitive_action", "source_ip", "status", "status_code", "tenant_mismatch"} {
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
	for _, key := range []string{"auth_mode", "client_id", "credential_id", "device_id", "effective_tenant_id", "principal", "principal_tenant_id", "requested_tenant_id", "risk_level", "risk_score", "scopes", "tenant_mismatch"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}

func addCerebroRouteEntities(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, serviceURN string, accessURN string, routeURN string) {
	operationFamilyURN := cerebroOperationFamilyURN(tenantID, attrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        routeURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "cerebro.route",
		Label:      firstNonEmpty(attrs["route"], attrs["connect_procedure"], attrs["operation_family"]),
		Attributes: cerebroRouteAttributes(attrs),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceURN, routeURN, relationSupports, cerebroEventLinkAttributes(event, "service_route")))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), routeURN, serviceURN, relationBelongsTo, cerebroEventLinkAttributes(event, "route_service")))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), routeURN, accessURN, relationHasEvidence, cerebroEventLinkAttributes(event, "route_access_observation")))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), accessURN, routeURN, relationObservedOn, cerebroEventLinkAttributes(event, "access_route")))
	if operationFamilyURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        operationFamilyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "cerebro.operation_family",
		Label:      strings.TrimSpace(attrs["operation_family"]),
		Attributes: map[string]string{
			"operation_family": strings.TrimSpace(attrs["operation_family"]),
			"operation_type":   strings.TrimSpace(attrs["operation_type"]),
			"source_product":   "cerebro",
		},
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), routeURN, operationFamilyURN, relationBelongsTo, cerebroEventLinkAttributes(event, "route_operation_family")))
}

func cerebroLinkPrincipalRouteAccess(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, principalURN string, routeURN string) {
	if cerebroAccessAllowed(attrs) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, routeURN, relationCanPerform, cerebroAccessLinkAttributes(event, attrs, "observed_allowed_route")))
		if operationFamilyURN := cerebroOperationFamilyURN(tenantID, attrs); operationFamilyURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, operationFamilyURN, relationCanPerform, cerebroAccessLinkAttributes(event, attrs, "observed_allowed_operation_family")))
		}
		return
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, routeURN, relationActedOn, cerebroAccessLinkAttributes(event, attrs, "observed_route_attempt")))
}

func addCerebroCredentialEntities(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, principalURN string, credentialURN string, routeURN string) {
	addEntity(entities, &ports.ProjectedEntity{
		URN:        credentialURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "cerebro.credential",
		Label:      firstNonEmpty(attrs["credential_id"], attrs["client_id"], attrs["device_id"]),
		Attributes: cerebroCredentialAttributes(attrs),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, credentialURN, relationAssignedTo, cerebroAccessLinkAttributes(event, attrs, "principal_credential")))
	if routeURN != "" && cerebroAccessAllowed(attrs) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, routeURN, relationCanPerform, cerebroAccessLinkAttributes(event, attrs, "credential_allowed_route")))
	}
}

func addCerebroScopeEntities(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, attrs map[string]string, principalURN string, credentialURN string, routeURN string) {
	for _, scope := range splitCerebroList(firstNonEmpty(attrs["required_scopes"], attrs["matched_scope"], attrs["scopes"])) {
		scopeURN := cerebroScopeURN(tenantID, scope)
		addCerebroScopeEntity(entities, tenantID, event.GetSourceId(), scopeURN, scope)
		if routeURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), scopeURN, routeURN, relationSupports, cerebroAccessLinkAttributes(event, attrs, "scope_route")))
		}
		if cerebroAccessAllowed(attrs) {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, scopeURN, relationCanPerform, cerebroAccessLinkAttributes(event, attrs, "principal_scope")))
			if credentialURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, scopeURN, relationCanPerform, cerebroAccessLinkAttributes(event, attrs, "credential_scope")))
			}
		}
	}
	for _, scope := range splitCerebroList(attrs["missing_scopes"]) {
		addCerebroScopeEntity(entities, tenantID, event.GetSourceId(), cerebroScopeURN(tenantID, scope), scope)
	}
}

func addCerebroScopeEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, scopeURN string, scope string) {
	if scopeURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        scopeURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "cerebro.scope",
		Label:      scope,
		Attributes: map[string]string{"scope": scope, "source_product": "cerebro"},
	})
}

func cerebroRouteURN(tenantID string, attrs map[string]string) string {
	routeID := firstNonEmpty(attrs["route"], attrs["connect_procedure"])
	if routeID == "" && (strings.TrimSpace(attrs["operation_family"]) != "" || strings.TrimSpace(attrs["operation_type"]) != "") {
		routeID = strings.Join([]string{strings.TrimSpace(attrs["operation_family"]), strings.TrimSpace(attrs["operation_type"])}, ":")
	}
	if routeID == "" {
		return ""
	}
	return projectionURN(tenantID, "cerebro_route", normalizeCerebroRouteID(routeID))
}

func cerebroOperationFamilyURN(tenantID string, attrs map[string]string) string {
	family := strings.TrimSpace(attrs["operation_family"])
	if family == "" {
		return ""
	}
	return projectionURN(tenantID, "cerebro_operation_family", normalizeIdentifier(family))
}

func cerebroCredentialURN(tenantID string, attrs map[string]string) string {
	value := firstNonEmpty(attrs["credential_id"], attrs["client_id"], attrs["device_id"])
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "cerebro_credential", normalizeIdentifier(value))
}

func cerebroScopeURN(tenantID string, scope string) string {
	if strings.TrimSpace(scope) == "" {
		return ""
	}
	return projectionURN(tenantID, "cerebro_scope", normalizeIdentifier(scope))
}

func cerebroRouteAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{"source_product": "cerebro"}
	for _, key := range []string{"connect_procedure", "method", "operation_family", "operation_type", "route", "sensitive_action"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}

func cerebroCredentialAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{"source_product": "cerebro"}
	for _, key := range []string{"auth_mode", "client_id", "credential_id", "device_id", "effective_tenant_id", "principal", "principal_tenant_id", "risk_level", "risk_score", "scopes"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}

func cerebroAccessLinkAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string, matchType string) map[string]string {
	out := cerebroEventLinkAttributes(event, matchType)
	for _, key := range []string{"auth_mode", "denial_reason", "effective_status_code", "effective_tenant_id", "missing_scopes", "outcome_result", "requested_tenant_id", "risk_level", "risk_score", "sensitive_action", "status_code", "tenant_mismatch"} {
		addProjectedAttribute(out, key, attrs[key])
	}
	return out
}

func cerebroEventLinkAttributes(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	out := map[string]string{"event_id": event.GetId()}
	addProjectedAttribute(out, "at", eventObservedAt(event))
	addProjectedAttribute(out, "match_type", matchType)
	return out
}

func cerebroAccessAllowed(attrs map[string]string) bool {
	outcome := normalizeIdentifier(firstNonEmpty(attrs["outcome_result"], attrs["status"]))
	if outcome == "allowed" || outcome == "allow" || outcome == "success" || outcome == "ok" {
		return true
	}
	status := strings.TrimSpace(firstNonEmpty(attrs["effective_status_code"], attrs["status_code"]))
	return strings.HasPrefix(status, "2")
}

func normalizeCerebroRouteID(value string) string {
	normalized := normalizeIdentifier(value)
	normalized = strings.ReplaceAll(normalized, " ", ":")
	for strings.Contains(normalized, "::") {
		normalized = strings.ReplaceAll(normalized, "::", ":")
	}
	return strings.Trim(normalized, ":")
}

func splitCerebroList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		trimmed := strings.Trim(strings.TrimSpace(part), "[]\"'")
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
