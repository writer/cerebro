package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func pagerDutyServiceURN(tenantID string, serviceID string) string {
	return projectionURN(tenantID, "pagerduty_service", strings.TrimSpace(serviceID))
}

func pagerDutyEscalationPolicyURN(tenantID string, escalationPolicyID string) string {
	return projectionURN(tenantID, "pagerduty_escalation_policy", strings.TrimSpace(escalationPolicyID))
}

func pagerDutyVendorURN(tenantID string, vendorID string) string {
	return projectionURN(tenantID, "pagerduty_vendor", strings.TrimSpace(vendorID))
}

// pagerDutyServiceProjections materializes the PagerDuty service entity, links
// it to the escalation policy that provides its incident-response coverage, and
// annotates the service with current escalation-coverage posture so a durable
// finding can anchor on whether the service currently has a valid escalation
// path rather than on a transient event.
func pagerDutyServiceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	tenant := primary.TenantID
	attrs := event.GetAttributes()
	escalationPolicyID := strings.TrimSpace(attrs["escalation_policy_id"])
	hasEscalation := escalationPolicyID != ""
	primary.Attributes["has_escalation_policy"] = boolString(hasEscalation)
	primary.Attributes["active"] = boolString(pagerDutyServiceActive(attrs))
	if !hasEscalation || tenant == "" {
		return entities, links, nil
	}
	escalationURN := pagerDutyEscalationPolicyURN(tenant, escalationPolicyID)
	entities = append(entities, &ports.ProjectedEntity{
		URN:        escalationURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "pagerduty.escalation_policy",
		Label:      firstNonEmpty(strings.TrimSpace(attrs["escalation_policy_name"]), escalationPolicyID),
		Attributes: map[string]string{"escalation_policy_id": escalationPolicyID},
	})
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "pagerduty_escalation_policy",
	}
	links = append(links,
		projectedLink(tenant, event.GetSourceId(), primary.URN, escalationURN, relationDependsOn, linkAttrs),
		projectedLink(tenant, event.GetSourceId(), escalationURN, primary.URN, relationSupports, linkAttrs),
	)
	return entities, links, nil
}

// pagerDutyIntegrationProjections materializes the PagerDuty integration entity
// and links it to the service it feeds and the vendor that provides it, so the
// responder topology resolves which third-party tooling routes signals into
// which service.
func pagerDutyIntegrationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	tenant := primary.TenantID
	if tenant == "" {
		return entities, links, nil
	}
	attrs := event.GetAttributes()
	if serviceID := strings.TrimSpace(attrs["service_id"]); serviceID != "" {
		serviceURN := pagerDutyServiceURN(tenant, serviceID)
		entities = append(entities, &ports.ProjectedEntity{
			URN:        serviceURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "pagerduty.service",
			Label:      firstNonEmpty(strings.TrimSpace(attrs["service_name"]), serviceID),
			Attributes: map[string]string{"service_id": serviceID},
		})
		linkAttrs := map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "pagerduty_service",
		}
		links = append(links,
			projectedLink(tenant, event.GetSourceId(), primary.URN, serviceURN, relationBelongsTo, linkAttrs),
			projectedLink(tenant, event.GetSourceId(), serviceURN, primary.URN, relationContains, linkAttrs),
		)
	}
	if vendorID := strings.TrimSpace(attrs["vendor_id"]); vendorID != "" {
		vendorURN := pagerDutyVendorURN(tenant, vendorID)
		entities = append(entities, &ports.ProjectedEntity{
			URN:        vendorURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "pagerduty.vendor",
			Label:      firstNonEmpty(strings.TrimSpace(attrs["vendor_name"]), vendorID),
			Attributes: map[string]string{"vendor_id": vendorID},
		})
		links = append(links, projectedLink(tenant, event.GetSourceId(), primary.URN, vendorURN, relationDependsOn, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "pagerduty_vendor",
		}))
	}
	return entities, links, nil
}

// pagerDutyServiceActive reports whether a PagerDuty service is in a state where
// it can receive and route incidents. Disabled or removed services are excluded
// so decommissioned services do not surface as escalation-coverage gaps.
func pagerDutyServiceActive(attrs map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(attrs["status"])) {
	case "disabled", "deleted", "inactive", "removed":
		return false
	default:
		return true
	}
}
