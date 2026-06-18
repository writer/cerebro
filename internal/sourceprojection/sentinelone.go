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
	firewallControlState := sentinelOneFirewallControlState(attrs["firewall_enabled"])
	addEntity(entities, &ports.ProjectedEntity{
		URN:        agentURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: sentinelOneEntityAgent,
		Label:      firstNonEmpty(attrs["computer_name"], attrs["uuid"], agentID),
		Attributes: map[string]string{
			"agent_id":             agentID,
			"agent_uuid":           strings.TrimSpace(attrs["uuid"]),
			"computer_name":        strings.TrimSpace(attrs["computer_name"]),
			"hostname":             strings.TrimSpace(firstNonEmpty(attrs["hostname"], attrs["computer_name"])),
			"os_name":              strings.TrimSpace(attrs["os_name"]),
			"os_type":              strings.TrimSpace(attrs["os_type"]),
			"os_revision":          strings.TrimSpace(attrs["os_revision"]),
			"agent_version":        strings.TrimSpace(attrs["agent_version"]),
			"is_active":            strings.TrimSpace(attrs["is_active"]),
			"is_decommissioned":    strings.TrimSpace(attrs["is_decommissioned"]),
			"is_pending_uninstall": strings.TrimSpace(attrs["is_pending_uninstall"]),
			"is_uninstalled":       strings.TrimSpace(attrs["is_uninstalled"]),
			"is_up_to_date":        strings.TrimSpace(attrs["is_up_to_date"]),
			"is_infected":          strings.TrimSpace(attrs["infected"]),
			"firewall_enabled":     strings.TrimSpace(attrs["firewall_enabled"]),
			"control_type":         sentinelOneFirewallControlType(firewallControlState),
			"control_state":        firewallControlState,
			"active_threats":       strings.TrimSpace(attrs["active_threats"]),
			"last_active_date":     strings.TrimSpace(attrs["last_active_date"]),
			"machine_type":         strings.TrimSpace(attrs["machine_type"]),
			"model_name":           strings.TrimSpace(attrs["model_name"]),
			"serial_number":        strings.TrimSpace(attrs["serial_number"]),
			"agent_ip_v4":          strings.TrimSpace(attrs["agent_ip_v4"]),
			"agent_ip_v6":          strings.TrimSpace(attrs["agent_ip_v6"]),
			"external_ip":          strings.TrimSpace(attrs["external_ip"]),
			"group_ip":             strings.TrimSpace(attrs["group_ip"]),
			"ip":                   strings.TrimSpace(attrs["ip"]),
			"ip_addresses":         strings.TrimSpace(attrs["ip_addresses"]),
			"last_ip_to_mgmt":      strings.TrimSpace(attrs["last_ip_to_mgmt"]),
			"domain":               strings.TrimSpace(attrs["domain"]),
			"network_status":       strings.TrimSpace(attrs["network_status"]),
			"operational_state":    strings.TrimSpace(attrs["operational_state"]),
			"mitigation_mode":      strings.TrimSpace(attrs["mitigation_mode"]),
			"site_id":              strings.TrimSpace(attrs["site_id"]),
			"site_name":            strings.TrimSpace(attrs["site_name"]),
			"group_id":             strings.TrimSpace(attrs["group_id"]),
			"group_name":           strings.TrimSpace(attrs["group_name"]),
			"account_id":           strings.TrimSpace(attrs["account_id"]),
			"account_name":         strings.TrimSpace(attrs["account_name"]),
			"tenant_host":          strings.TrimSpace(attrs["tenant_host"]),
			"event_id":             event.GetId(),
			"at":                   eventObservedAt(event),
		},
	})

	addSentinelOneScopeLinks(entities, links, tenant, event, agentURN, attrs)
	addSentinelOneInternetContext(entities, links, tenant, event, agentURN, attrs)
	addSentinelOneOwnerIdentityLinks(entities, links, tenant, event, agentURN, attrs)

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneFirewallControlState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "yes", "y", "enabled", "active", "on", "protected":
		return "enabled"
	case "0", "f", "false", "no", "n", "disabled", "inactive", "off", "unprotected", "not_protected":
		return "disabled"
	default:
		return ""
	}
}

func sentinelOneFirewallControlType(controlState string) string {
	if controlState == "" {
		return ""
	}
	return "firewall"
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
			"threat_id":              threatID,
			"classification":         strings.TrimSpace(attrs["classification"]),
			"classification_norm":    strings.TrimSpace(attrs["classification_norm"]),
			"classification_source":  strings.TrimSpace(attrs["classification_source"]),
			"analyst_verdict":        strings.TrimSpace(attrs["analyst_verdict"]),
			"analyst_verdict_norm":   strings.TrimSpace(attrs["analyst_verdict_norm"]),
			"automatically_resolved": strings.TrimSpace(attrs["automatically_resolved"]),
			"incident_status":        strings.TrimSpace(attrs["incident_status"]),
			"incident_status_norm":   strings.TrimSpace(attrs["incident_status_norm"]),
			"confidence_level":       strings.TrimSpace(attrs["confidence_level"]),
			"mitigation_status":      strings.TrimSpace(attrs["mitigation_status"]),
			"mitigation_status_norm": strings.TrimSpace(attrs["mitigation_status_norm"]),
			"detection_type":         strings.TrimSpace(attrs["detection_type"]),
			"is_fileless":            strings.TrimSpace(attrs["is_fileless"]),
			"file_path":              strings.TrimSpace(attrs["file_path"]),
			"sha256":                 strings.TrimSpace(attrs["sha256"]),
			"mitre_tactics":          strings.TrimSpace(attrs["mitre_tactics"]),
			"mitre_techniques":       strings.TrimSpace(attrs["mitre_techniques"]),
			"indicator_categories":   strings.TrimSpace(attrs["indicator_categories"]),
			"site_id":                strings.TrimSpace(attrs["site_id"]),
			"group_id":               strings.TrimSpace(attrs["group_id"]),
			"tenant_host":            strings.TrimSpace(attrs["tenant_host"]),
			"threat_name":            strings.TrimSpace(attrs["threat_name"]),
			"is_infected":            strings.TrimSpace(attrs["is_infected"]),
			"active_threats":         strings.TrimSpace(attrs["active_threats"]),
			"event_id":               event.GetId(),
			"at":                     eventObservedAt(event),
		},
	})
	addSentinelOneThreatClassificationLinks(entities, links, tenant, event, threatURN, attrs)

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
				"hostname":       strings.TrimSpace(firstNonEmpty(attrs["hostname"], attrs["computer_name"], attrs["agent_name"])),
				"os_name":        strings.TrimSpace(attrs["agent_os_name"]),
				"os_type":        strings.TrimSpace(attrs["agent_os_type"]),
				"is_active":      strings.TrimSpace(attrs["is_active"]),
				"is_infected":    strings.TrimSpace(attrs["is_infected"]),
				"active_threats": strings.TrimSpace(attrs["active_threats"]),
				"agent_ip_v4":    strings.TrimSpace(attrs["agent_ip_v4"]),
				"agent_ip_v6":    strings.TrimSpace(attrs["agent_ip_v6"]),
				"external_ip":    strings.TrimSpace(attrs["external_ip"]),
				"ip":             firstNonEmpty(strings.TrimSpace(attrs["ip"]), strings.TrimSpace(attrs["external_ip"]), strings.TrimSpace(attrs["agent_ip_v4"]), strings.TrimSpace(attrs["agent_ip_v6"])),
				"ip_addresses":   strings.TrimSpace(attrs["ip_addresses"]),
				"site_id":        strings.TrimSpace(attrs["site_id"]),
				"group_id":       strings.TrimSpace(attrs["group_id"]),
				"tenant_host":    strings.TrimSpace(attrs["tenant_host"]),
				"event_id":       event.GetId(),
				"at":             eventObservedAt(event),
			},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, threatURN, relationAffectedBy, map[string]string{
			"event_id":               event.GetId(),
			"at":                     eventObservedAt(event),
			"classification":         strings.TrimSpace(attrs["classification"]),
			"analyst_verdict":        strings.TrimSpace(attrs["analyst_verdict"]),
			"incident_status":        strings.TrimSpace(attrs["incident_status"]),
			"mitigation_status":      strings.TrimSpace(attrs["mitigation_status"]),
			"mitigation_status_norm": strings.TrimSpace(attrs["mitigation_status_norm"]),
		}))
		addSentinelOneInternetContext(entities, links, tenant, event, agentURN, attrs)
		addSentinelOneOwnerIdentityLinks(entities, links, tenant, event, agentURN, attrs)
	}

	addSentinelOneScopeLinks(entities, links, tenant, event, threatURN, attrs)

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addSentinelOneInternetContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, agentURN string, attrs map[string]string) {
	for _, rawIPs := range []string{attrs["external_ip"], attrs["agent_ip_v4"], attrs["agent_ip_v6"], attrs["ip"], attrs["ip_addresses"]} {
		for _, rawIP := range splitCloudAttributeList(rawIPs) {
			ipURN, ip := internetIPURN(tenant, rawIP)
			if ipURN == "" {
				continue
			}
			addInternetIPEntity(entities, tenant, event.GetSourceId(), ipURN, ip)
			addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, ipURN, relationHasIdentifier, map[string]string{
				"confidence": "0.80",
				"at":         eventObservedAt(event),
				"event_id":   event.GetId(),
				"ip":         ip,
				"match_type": "sentinelone_agent_ip",
			}))
		}
	}
	rawHost := firstNonEmpty(attrs["hostname"], attrs["computer_name"], attrs["agent_name"])
	addEndpointIdentifierLink(entities, links, tenant, event.GetSourceId(), event, agentURN, "hostname", rawHost, "0.80")
	host := internetHostIfLikely(rawHost)
	if host == "" {
		return
	}
	hostURN, host := internetHostURN(tenant, host)
	if hostURN == "" {
		return
	}
	addInternetHostEntity(entities, tenant, event.GetSourceId(), hostURN, host)
	addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, hostURN, relationHasIdentifier, map[string]string{
		"confidence": "0.70",
		"at":         eventObservedAt(event),
		"event_id":   event.GetId(),
		"host":       host,
		"match_type": "sentinelone_agent_hostname",
	}))
}

func addSentinelOneOwnerIdentityLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, agentURN string, attrs map[string]string) {
	if agentURN == "" {
		return
	}
	ownerEmail := strings.TrimSpace(firstNonEmpty(attrs["user_mail"], attrs["user_email"], extractEmailIdentifier(attrs["user_name"])))
	if ownerEmail != "" {
		addIdentifierLink(entities, links, tenant, event.GetSourceId(), event.GetId(), agentURN, ownerEmail, event.GetOccurredAt())
		identityURN, _ := canonicalIdentityURN(tenant, ownerEmail)
		if identityURN != "" {
			linkAttrs := map[string]string{
				"at":         eventObservedAt(event),
				"confidence": "0.85",
				"event_id":   event.GetId(),
				"match_type": "sentinelone_owner_email",
			}
			addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, identityURN, relationOwnedBy, linkAttrs))
		}
	}
	ownerUser := strings.TrimSpace(attrs["user_name"])
	if ownerUser != "" {
		addEndpointIdentifierLink(entities, links, tenant, event.GetSourceId(), event, agentURN, "sentinelone_user_name", ownerUser, "0.60")
	}
	addEndpointIdentifierLink(entities, links, tenant, event.GetSourceId(), event, agentURN, "sentinelone_user_id", attrs["user_id"], "0.70")
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
		Label:      firstNonEmpty(attrs["primary_description"], attrs["description"], attrs["activity_uuid"], activityID),
		Attributes: compactAttributes(map[string]string{
			"activity_id":           activityID,
			"activity_type":         strings.TrimSpace(attrs["activity_type"]),
			"activity_uuid":         strings.TrimSpace(attrs["activity_uuid"]),
			"agent_id":              strings.TrimSpace(attrs["agent_id"]),
			"agent_updated_version": strings.TrimSpace(attrs["agent_updated_version"]),
			"description":           strings.TrimSpace(attrs["description"]),
			"group_id":              strings.TrimSpace(attrs["group_id"]),
			"os_family":             strings.TrimSpace(attrs["os_family"]),
			"primary_description":   strings.TrimSpace(attrs["primary_description"]),
			"secondary_description": strings.TrimSpace(attrs["secondary_description"]),
			"site_id":               strings.TrimSpace(attrs["site_id"]),
			"tenant_host":           strings.TrimSpace(attrs["tenant_host"]),
			"threat_id":             strings.TrimSpace(attrs["threat_id"]),
			"user_id":               strings.TrimSpace(attrs["user_id"]),
			"event_id":              event.GetId(),
			"at":                    eventObservedAt(event),
		}),
	})

	if agentID := strings.TrimSpace(attrs["agent_id"]); agentID != "" {
		agentURN := sentinelOneAgentURN(tenant, agentID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        agentURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntityAgent,
			Label:      firstNonEmpty(attrs["computer_name"], attrs["agent_name"], agentID),
			Attributes: compactAttributes(map[string]string{
				"agent_id":    agentID,
				"hostname":    strings.TrimSpace(firstNonEmpty(attrs["hostname"], attrs["computer_name"], attrs["agent_name"])),
				"site_id":     strings.TrimSpace(attrs["site_id"]),
				"group_id":    strings.TrimSpace(attrs["group_id"]),
				"tenant_host": strings.TrimSpace(attrs["tenant_host"]),
				"event_id":    event.GetId(),
				"at":          eventObservedAt(event),
			}),
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), agentURN, activityURN, relationHasEvidence, sentinelOneActivityLinkAttributes(event, "sentinelone_agent_activity")))
		addLink(links, projectedLink(tenant, event.GetSourceId(), activityURN, agentURN, relationObservedOn, sentinelOneActivityLinkAttributes(event, "sentinelone_activity_agent")))
		addSentinelOneScopeLinks(entities, links, tenant, event, agentURN, attrs)
		addSentinelOneInternetContext(entities, links, tenant, event, agentURN, attrs)
		addSentinelOneOwnerIdentityLinks(entities, links, tenant, event, agentURN, attrs)
	}
	if threatID := strings.TrimSpace(attrs["threat_id"]); threatID != "" {
		threatURN := sentinelOneThreatURN(tenant, threatID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        threatURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: sentinelOneEntityThreat,
			Label:      firstNonEmpty(attrs["threat_name"], threatID),
			Attributes: compactAttributes(map[string]string{
				"threat_id":   threatID,
				"site_id":     strings.TrimSpace(attrs["site_id"]),
				"group_id":    strings.TrimSpace(attrs["group_id"]),
				"tenant_host": strings.TrimSpace(attrs["tenant_host"]),
				"event_id":    event.GetId(),
				"at":          eventObservedAt(event),
			}),
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), threatURN, activityURN, relationHasEvidence, sentinelOneActivityLinkAttributes(event, "sentinelone_threat_activity")))
		addLink(links, projectedLink(tenant, event.GetSourceId(), activityURN, threatURN, relationObservedOn, sentinelOneActivityLinkAttributes(event, "sentinelone_activity_threat")))
		addSentinelOneScopeLinks(entities, links, tenant, event, threatURN, attrs)
	}
	addSentinelOneScopeLinks(entities, links, tenant, event, activityURN, attrs)

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sentinelOneActivityLinkAttributes(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	attrs := compactAttributes(map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": matchType,
	})
	sourceAttrs := event.GetAttributes()
	addProjectedAttribute(attrs, "activity_id", sourceAttrs["activity_id"])
	addProjectedAttribute(attrs, "activity_type", sourceAttrs["activity_type"])
	return attrs
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

func addSentinelOneThreatClassificationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, threatURN string, attrs map[string]string) {
	classification := firstNonEmpty(attrs["classification_norm"], attrs["classification"])
	if classification != "" {
		classificationURN := projectionURN(tenant, "sentinelone_threat_classification", normalizeIdentifier(classification))
		addEntity(entities, &ports.ProjectedEntity{
			URN:        classificationURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "sentinelone.threat.classification",
			Label:      firstNonEmpty(attrs["classification"], classification),
			Attributes: compactAttributes(map[string]string{
				"classification":        attrs["classification"],
				"classification_norm":   normalizeIdentifier(classification),
				"classification_source": attrs["classification_source"],
			}),
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), threatURN, classificationURN, relationHasClassification, map[string]string{"event_id": event.GetId(), "source_attribute": "classification"}))
	}
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "analyst_verdict", firstNonEmpty(attrs["analyst_verdict_norm"], attrs["analyst_verdict"]))
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "incident_status", firstNonEmpty(attrs["incident_status_norm"], attrs["incident_status"]))
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "mitigation_status", firstNonEmpty(attrs["mitigation_status_norm"], attrs["mitigation_status"]))
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "detection_type", attrs["detection_type"])
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "mitre_tactic", attrs["mitre_tactics"])
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "mitre_technique", attrs["mitre_techniques"])
	addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "indicator_category", attrs["indicator_categories"])
	if projectionBool(attrs["is_fileless"]) {
		addSentinelOneThreatTagLinks(entities, links, tenant, event, threatURN, "threat_property", "fileless")
	}
}

func addSentinelOneThreatTagLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, threatURN string, key string, rawValues string) {
	for _, value := range splitCSV(rawValues) {
		tagValue := normalizeIdentifier(key) + ":" + normalizeIdentifier(value)
		tagURN := projectionURN(tenant, "sentinelone_threat_tag", tagValue)
		if tagURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tagURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "sentinelone.threat.tag",
			Label:      tagValue,
			Attributes: map[string]string{"tag": tagValue, "tag_key": key, "tag_value": value},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), threatURN, tagURN, relationTaggedAs, map[string]string{"event_id": event.GetId(), "source_attribute": key}))
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
