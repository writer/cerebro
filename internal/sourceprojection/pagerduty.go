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

func pagerDutyScheduleURN(tenantID string, scheduleID string) string {
	return projectionURN(tenantID, "pagerduty_schedule", strings.TrimSpace(scheduleID))
}

func pagerDutyTeamURN(tenantID string, teamID string) string {
	return projectionURN(tenantID, "pagerduty_team", strings.TrimSpace(teamID))
}

func pagerDutyUserURN(tenantID string, userID string) string {
	return projectionURN(tenantID, "pagerduty_user", strings.TrimSpace(userID))
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

func pagerDutyEscalationPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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
	entityMap := map[string]*ports.ProjectedEntity{}
	linkMap := map[string]*ports.ProjectedLink{}
	for _, entity := range entities {
		addEntity(entityMap, entity)
	}
	for _, link := range links {
		addLink(linkMap, link)
	}
	for _, team := range pagerDutyEscalationPolicyTeams(event) {
		teamURN := pagerDutyTeamURN(tenant, team.id)
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        teamURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "pagerduty.team",
			Label:      firstNonEmpty(team.label, team.id),
			Attributes: map[string]string{"team_id": team.id},
		})
		linkAttrs := pagerDutyLinkAttrs(event, "pagerduty_escalation_policy_team")
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), primary.URN, teamURN, relationBelongsTo, linkAttrs))
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), teamURN, primary.URN, relationContains, linkAttrs))
	}
	for _, target := range pagerDutyEscalationPolicyTargets(event) {
		targetURN := ""
		entityType := ""
		attrs := map[string]string{}
		switch target.kind {
		case "schedule":
			targetURN = pagerDutyScheduleURN(tenant, target.id)
			entityType = "pagerduty.schedule"
			attrs["schedule_id"] = target.id
		case "user":
			targetURN = pagerDutyUserURN(tenant, target.id)
			entityType = "pagerduty.user"
			attrs["user_id"] = target.id
		default:
			continue
		}
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      firstNonEmpty(target.label, target.id),
			Attributes: attrs,
		})
		linkAttrs := pagerDutyLinkAttrs(event, "pagerduty_escalation_policy_target")
		linkAttrs["target_type"] = target.kind
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), primary.URN, targetURN, relationDependsOn, linkAttrs))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entityMap, linkMap)
	return projectedEntities, projectedLinks, nil
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

type pagerDutyRef struct {
	id    string
	label string
	kind  string
}

func pagerDutyLinkAttrs(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	return map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": matchType,
	}
}

func pagerDutyEscalationPolicyTeams(event *cerebrov1.EventEnvelope) []pagerDutyRef {
	payload := payloadMap(event)
	rawTeams, ok := payload["teams"].([]any)
	if !ok {
		return nil
	}
	refs := []pagerDutyRef{}
	seen := map[string]struct{}{}
	for _, raw := range rawTeams {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := strings.TrimSpace(stringValue(item, "id"))
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		refs = append(refs, pagerDutyRef{id: id, label: firstNonEmpty(stringValue(item, "summary"), stringValue(item, "name"))})
	}
	return refs
}

func pagerDutyEscalationPolicyTargets(event *cerebrov1.EventEnvelope) []pagerDutyRef {
	payload := payloadMap(event)
	rawRules, ok := payload["escalation_rules"].([]any)
	if !ok {
		return nil
	}
	refs := []pagerDutyRef{}
	seen := map[string]struct{}{}
	for _, rawRule := range rawRules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		rawTargets, ok := rule["targets"].([]any)
		if !ok {
			continue
		}
		for _, rawTarget := range rawTargets {
			target, ok := rawTarget.(map[string]any)
			if !ok {
				continue
			}
			kind := pagerDutyTargetKind(stringValue(target, "type"))
			if kind == "" {
				continue
			}
			id := strings.TrimSpace(stringValue(target, "id"))
			if id == "" {
				continue
			}
			key := kind + ":" + id
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, pagerDutyRef{id: id, label: firstNonEmpty(stringValue(target, "summary"), stringValue(target, "name")), kind: kind})
		}
	}
	return refs
}

func pagerDutyTargetKind(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "schedule_reference":
		return "schedule"
	case "user_reference":
		return "user"
	default:
		return ""
	}
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
