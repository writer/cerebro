package sourceprojection

import (
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	sentinelOneEntityAgent     = "sentinelone.agent"
	sentinelOneEntityThreat    = "sentinelone.threat"
	sentinelOneEntitySite      = "sentinelone.site"
	sentinelOneEntityGroup     = "sentinelone.group"
	sentinelOneEntityActivity  = "sentinelone.activity"
	sentinelOneEntityExclusion = "sentinelone.exclusion"
	sentinelOneEntityAccount   = "sentinelone.account"
	sentinelOneEntityApp       = "sentinelone.installed_application"
)

func sentinelOneAgentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	agentID := strings.TrimSpace(attrs["agent_id"])
	if agentID == "" {
		return nil, nil, nil
	}
	agentURN := sentinelOneAgentURN(tenant, agentID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        agentURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityAgent,
		Label:      firstNonEmpty(attrs["computer_name"], attrs["uuid"], agentID),
		Attributes: map[string]string{
			"agent_id":          agentID,
			"agent_uuid":        strings.TrimSpace(attrs["uuid"]),
			"computer_name":     strings.TrimSpace(attrs["computer_name"]),
			"os_name":           strings.TrimSpace(attrs["os_name"]),
			"os_type":           strings.TrimSpace(attrs["os_type"]),
			"os_revision":       strings.TrimSpace(attrs["os_revision"]),
			"agent_version":     strings.TrimSpace(attrs["agent_version"]),
			"is_active":         strings.TrimSpace(attrs["is_active"]),
			"is_decommissioned": strings.TrimSpace(attrs["is_decommissioned"]),
			"is_uninstalled":    strings.TrimSpace(attrs["is_uninstalled"]),
			"is_up_to_date":     strings.TrimSpace(attrs["is_up_to_date"]),
			"is_infected":       strings.TrimSpace(attrs["infected"]),
			"active_threats":    strings.TrimSpace(attrs["active_threats"]),
			"last_active_date":  strings.TrimSpace(attrs["last_active_date"]),
			"machine_type":      strings.TrimSpace(attrs["machine_type"]),
			"model_name":        strings.TrimSpace(attrs["model_name"]),
			"serial_number":     strings.TrimSpace(attrs["serial_number"]),
			"external_ip":       strings.TrimSpace(attrs["external_ip"]),
			"domain":            strings.TrimSpace(attrs["domain"]),
			"network_status":    strings.TrimSpace(attrs["network_status"]),
			"operational_state": strings.TrimSpace(attrs["operational_state"]),
			"mitigation_mode":   strings.TrimSpace(attrs["mitigation_mode"]),
			"site_id":           strings.TrimSpace(attrs["site_id"]),
			"site_name":         strings.TrimSpace(attrs["site_name"]),
			"group_id":          strings.TrimSpace(attrs["group_id"]),
			"group_name":        strings.TrimSpace(attrs["group_name"]),
			"account_id":        strings.TrimSpace(attrs["account_id"]),
			"account_name":      strings.TrimSpace(attrs["account_name"]),
			"tenant_host":       strings.TrimSpace(attrs["tenant_host"]),
			"event_id":          event.GetId(),
			"at":                eventObservedAt(event),
		},
	})

	addSentinelOneScopeLinks(entities, links, tenant, event, agentURN, attrs)

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneThreatProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	threatID := strings.TrimSpace(attrs["threat_id"])
	if threatID == "" {
		return nil, nil, nil
	}
	threatURN := sentinelOneThreatURN(tenant, threatID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        threatURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityThreat,
		Label:      firstNonEmpty(attrs["threat_name"], attrs["classification"], threatID),
		Attributes: map[string]string{
			"threat_id":             threatID,
			"classification":        strings.TrimSpace(attrs["classification"]),
			"classification_source": strings.TrimSpace(attrs["classification_source"]),
			"analyst_verdict":       strings.TrimSpace(attrs["analyst_verdict"]),
			"incident_status":       strings.TrimSpace(attrs["incident_status"]),
			"confidence_level":      strings.TrimSpace(attrs["confidence_level"]),
			"mitigation_status":     strings.TrimSpace(attrs["mitigation_status"]),
			"detection_type":        strings.TrimSpace(attrs["detection_type"]),
			"is_fileless":           strings.TrimSpace(attrs["is_fileless"]),
			"file_path":             strings.TrimSpace(attrs["file_path"]),
			"sha256":                strings.TrimSpace(attrs["sha256"]),
			"mitre_tactics":         strings.TrimSpace(attrs["mitre_tactics"]),
			"mitre_techniques":      strings.TrimSpace(attrs["mitre_techniques"]),
			"indicator_categories":  strings.TrimSpace(attrs["indicator_categories"]),
			"site_id":               strings.TrimSpace(attrs["site_id"]),
			"group_id":              strings.TrimSpace(attrs["group_id"]),
			"tenant_host":           strings.TrimSpace(attrs["tenant_host"]),
			"threat_name":           strings.TrimSpace(attrs["threat_name"]),
			"is_infected":           strings.TrimSpace(attrs["is_infected"]),
			"active_threats":        strings.TrimSpace(attrs["active_threats"]),
			"event_id":              event.GetId(),
			"at":                    eventObservedAt(event),
		},
	})

	agentID := firstNonEmpty(strings.TrimSpace(attrs["agent_id"]), strings.TrimSpace(attrs["agent_uuid"]))
	if agentID != "" {
		agentURN := sentinelOneAgentURN(tenant, agentID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        agentURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntityAgent,
			Label:      firstNonEmpty(attrs["computer_name"], attrs["agent_name"], agentID),
			Attributes: map[string]string{
				"agent_id":       agentID,
				"computer_name":  strings.TrimSpace(attrs["computer_name"]),
				"os_name":        strings.TrimSpace(attrs["agent_os_name"]),
				"os_type":        strings.TrimSpace(attrs["agent_os_type"]),
				"is_active":      strings.TrimSpace(attrs["is_active"]),
				"is_infected":    strings.TrimSpace(attrs["is_infected"]),
				"active_threats": strings.TrimSpace(attrs["active_threats"]),
				"site_id":        strings.TrimSpace(attrs["site_id"]),
				"group_id":       strings.TrimSpace(attrs["group_id"]),
				"tenant_host":    strings.TrimSpace(attrs["tenant_host"]),
				"event_id":       event.GetId(),
				"at":             eventObservedAt(event),
			},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, threatURN, relationAffectedBy, map[string]string{
			"event_id":          event.GetId(),
			"at":                eventObservedAt(event),
			"classification":    strings.TrimSpace(attrs["classification"]),
			"analyst_verdict":   strings.TrimSpace(attrs["analyst_verdict"]),
			"incident_status":   strings.TrimSpace(attrs["incident_status"]),
			"mitigation_status": strings.TrimSpace(attrs["mitigation_status"]),
		}))
	}

	addSentinelOneScopeLinks(entities, links, tenant, event, threatURN, attrs)

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneSiteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	siteID := strings.TrimSpace(attrs["site_id"])
	if siteID == "" {
		return nil, nil, nil
	}
	siteURN := sentinelOneSiteURN(tenant, siteID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        siteURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntitySite,
		Label:      firstNonEmpty(attrs["site_name"], siteID),
		Attributes: map[string]string{
			"site_id":      siteID,
			"site_name":    strings.TrimSpace(attrs["site_name"]),
			"site_type":    strings.TrimSpace(attrs["site_type"]),
			"state":        strings.TrimSpace(attrs["state"]),
			"is_default":   strings.TrimSpace(attrs["is_default"]),
			"account_id":   strings.TrimSpace(attrs["account_id"]),
			"account_name": strings.TrimSpace(attrs["account_name"]),
			"tenant_host":  strings.TrimSpace(attrs["tenant_host"]),
		},
	})

	if accountID := strings.TrimSpace(attrs["account_id"]); accountID != "" {
		accountURN := sentinelOneAccountURN(tenant, accountID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        accountURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntityAccount,
			Label:      firstNonEmpty(attrs["account_name"], accountID),
			Attributes: map[string]string{"account_id": accountID, "account_name": strings.TrimSpace(attrs["account_name"])},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), siteURN, accountURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	groupID := strings.TrimSpace(attrs["group_id"])
	if groupID == "" {
		return nil, nil, nil
	}
	groupURN := sentinelOneGroupURN(tenant, groupID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        groupURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityGroup,
		Label:      firstNonEmpty(attrs["group_name"], groupID),
		Attributes: map[string]string{
			"group_id":     groupID,
			"group_name":   strings.TrimSpace(attrs["group_name"]),
			"type":         strings.TrimSpace(attrs["type"]),
			"is_default":   strings.TrimSpace(attrs["is_default"]),
			"site_id":      strings.TrimSpace(attrs["site_id"]),
			"total_agents": strings.TrimSpace(attrs["total_agents"]),
			"tenant_host":  strings.TrimSpace(attrs["tenant_host"]),
		},
	})

	if siteID := strings.TrimSpace(attrs["site_id"]); siteID != "" {
		siteURN := sentinelOneSiteURN(tenant, siteID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        siteURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntitySite,
			Label:      firstNonEmpty(attrs["site_name"], siteID),
			Attributes: map[string]string{"site_id": siteID, "site_name": strings.TrimSpace(attrs["site_name"])},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), groupURN, siteURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneActivityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	activityID := strings.TrimSpace(attrs["activity_id"])
	if activityID == "" {
		return nil, nil, nil
	}
	activityURN := projectionURN(tenant, "sentinelone_activity", activityID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        activityURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityActivity,
		Label:      firstNonEmpty(attrs["primary_description"], activityID),
		Attributes: map[string]string{
			"activity_id":         activityID,
			"activity_type":       strings.TrimSpace(attrs["activity_type"]),
			"activity_uuid":       strings.TrimSpace(attrs["activity_uuid"]),
			"primary_description": strings.TrimSpace(attrs["primary_description"]),
			"agent_id":            strings.TrimSpace(attrs["agent_id"]),
			"site_id":             strings.TrimSpace(attrs["site_id"]),
			"group_id":            strings.TrimSpace(attrs["group_id"]),
			"threat_id":           strings.TrimSpace(attrs["threat_id"]),
			"user_id":             strings.TrimSpace(attrs["user_id"]),
			"os_family":           strings.TrimSpace(attrs["os_family"]),
			"tenant_host":         strings.TrimSpace(attrs["tenant_host"]),
			"event_id":            event.GetId(),
			"at":                  eventObservedAt(event),
		},
	})

	if agentID := strings.TrimSpace(attrs["agent_id"]); agentID != "" {
		agentURN := sentinelOneAgentURN(tenant, agentID)
		addLink(links, projectedLink(tenant, event.GetSourceId(), activityURN, agentURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	}
	if threatID := strings.TrimSpace(attrs["threat_id"]); threatID != "" {
		threatURN := sentinelOneThreatURN(tenant, threatID)
		addLink(links, projectedLink(tenant, event.GetSourceId(), activityURN, threatURN, relationActedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneExclusionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	exclusionID := strings.TrimSpace(attrs["exclusion_id"])
	if exclusionID == "" {
		return nil, nil, nil
	}
	exclusionURN := projectionURN(tenant, "sentinelone_exclusion", exclusionID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        exclusionURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityExclusion,
		Label:      firstNonEmpty(attrs["value"], exclusionID),
		Attributes: map[string]string{
			"exclusion_id":        exclusionID,
			"exclusion_type":      strings.TrimSpace(attrs["exclusion_type"]),
			"mode":                strings.TrimSpace(attrs["mode"]),
			"source":              strings.TrimSpace(attrs["source"]),
			"os_type":             strings.TrimSpace(attrs["os_type"]),
			"path_exclusion_type": strings.TrimSpace(attrs["path_exclusion_type"]),
			"scope":               strings.TrimSpace(attrs["scope"]),
			"scope_name":          strings.TrimSpace(attrs["scope_name"]),
			"scope_path":          strings.TrimSpace(attrs["scope_path"]),
			"value":               strings.TrimSpace(attrs["value"]),
			"not_recommended":     strings.TrimSpace(attrs["not_recommended"]),
			"include_children":    strings.TrimSpace(attrs["include_children"]),
			"include_parents":     strings.TrimSpace(attrs["include_parents"]),
			"imported":            strings.TrimSpace(attrs["imported"]),
			"actions":             strings.TrimSpace(attrs["actions"]),
			"tenant_host":         strings.TrimSpace(attrs["tenant_host"]),
		},
	})

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneApplicationInventoryProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	agentID := strings.TrimSpace(attrs["agent_id"])
	name := strings.TrimSpace(attrs["application_name"])
	publisher := strings.TrimSpace(attrs["publisher"])
	version := strings.TrimSpace(attrs["version"])
	if agentID == "" || name == "" {
		return nil, nil, nil
	}
	parts := []string{publisher, name, version}
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		cleaned = append(cleaned, normalizeIdentifier(p))
	}
	if len(cleaned) == 0 {
		cleaned = []string{normalizeIdentifier(name)}
	}
	identity := strings.Join(cleaned, "|")
	appURN := projectionURN(tenant, "sentinelone_installed_app", agentID, identity)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        appURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityApp,
		Label:      strings.TrimSpace(strings.Join([]string{publisher, name, version}, " ")),
		Attributes: map[string]string{
			"agent_id":       agentID,
			"name":           name,
			"publisher":      publisher,
			"version":        version,
			"installed_date": strings.TrimSpace(attrs["installed_date"]),
			"tenant_host":    strings.TrimSpace(attrs["tenant_host"]),
		},
	})
	agentURN := sentinelOneAgentURN(tenant, agentID)
	addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, appURN, relationContains, map[string]string{"event_id": event.GetId()}))

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addSentinelOneScopeLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, fromURN string, attrs map[string]string) {
	if siteID := strings.TrimSpace(attrs["site_id"]); siteID != "" {
		siteURN := sentinelOneSiteURN(tenant, siteID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        siteURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntitySite,
			Label:      firstNonEmpty(attrs["site_name"], siteID),
			Attributes: map[string]string{"site_id": siteID, "site_name": strings.TrimSpace(attrs["site_name"])},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), fromURN, siteURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	if groupID := strings.TrimSpace(attrs["group_id"]); groupID != "" {
		groupURN := sentinelOneGroupURN(tenant, groupID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntityGroup,
			Label:      firstNonEmpty(attrs["group_name"], groupID),
			Attributes: map[string]string{"group_id": groupID, "group_name": strings.TrimSpace(attrs["group_name"]), "site_id": strings.TrimSpace(attrs["site_id"])},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), fromURN, groupURN, relationMemberOf, map[string]string{"event_id": event.GetId()}))
	}
}

func sentinelOneAgentURN(tenant string, agentID string) string {
	return projectionURN(tenant, "sentinelone_agent", agentID)
}

func sentinelOneThreatURN(tenant string, threatID string) string {
	return projectionURN(tenant, "sentinelone_threat", threatID)
}

func sentinelOneSiteURN(tenant string, siteID string) string {
	return projectionURN(tenant, "sentinelone_site", siteID)
}

func sentinelOneGroupURN(tenant string, groupID string) string {
	return projectionURN(tenant, "sentinelone_group", groupID)
}

func sentinelOneAccountURN(tenant string, accountID string) string {
	return projectionURN(tenant, "sentinelone_account", accountID)
}

func eventObservedAt(event *cerebrov1.EventEnvelope) string {
	if event == nil || event.GetOccurredAt() == nil || !event.GetOccurredAt().IsValid() {
		return ""
	}
	return event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339)
}
