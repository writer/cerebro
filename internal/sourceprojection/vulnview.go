package sourceprojection

import (
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func vulnViewVulnerabilityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	assetURN := vulnViewAssetURN(tenantID, attrs)
	if assetURN != "" {
		addEntity(entities, vulnViewAssetEntity(tenantID, event.GetSourceId(), assetURN, attrs))
	}

	findingURN := projectionURN(tenantID, "vulnview_finding", firstAttribute(attrs, "external_id", "template_id", "name"))
	if findingURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "vulnview.finding",
			Label:      firstAttribute(attrs, "name", "template_id", "external_id"),
			Attributes: map[string]string{
				"description": firstAttribute(attrs, "description"),
				"matched_at":  firstAttribute(attrs, "matched_at"),
				"scan_id":     firstAttribute(attrs, "scan_id"),
				"scan_name":   firstAttribute(attrs, "scan_name"),
				"severity":    firstAttribute(attrs, "severity"),
				"site_id":     firstAttribute(attrs, "site_id"),
				"template_id": firstAttribute(attrs, "template_id", "vulnerability_id"),
				"type":        firstAttribute(attrs, "type", "vulnerability_type"),
			},
		})
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, assetURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
		}
	}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)
	if vulnerabilityURN != "" {
		evidenceAttrs := vulnerabilityEvidenceAttributes(event, attrs)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, vulnerabilityURN, relationAffectedBy, evidenceAttrs))
		}
		if findingURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, vulnerabilityURN, relationAffectedBy, evidenceAttrs))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func vulnViewAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	if assetURN := vulnViewAssetURN(tenantID, attrs); assetURN != "" {
		addEntity(entities, vulnViewAssetEntity(tenantID, event.GetSourceId(), assetURN, attrs))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func vulnViewDNSAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	assetURN := vulnViewAssetURN(tenantID, attrs)
	if assetURN != "" {
		addEntity(entities, vulnViewAssetEntity(tenantID, event.GetSourceId(), assetURN, attrs))
	}
	alertID := firstAttribute(attrs, "external_id", "alert", "name")
	alertURN := projectionURN(tenantID, "vulnview_dns_alert", alertID)
	if alertURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        alertURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "vulnview.dns_alert",
			Label:      firstAttribute(attrs, "name", "alert", "external_id"),
			Attributes: map[string]string{
				"alert":        firstAttribute(attrs, "alert", "name"),
				"description":  firstAttribute(attrs, "description"),
				"record_type":  firstAttribute(attrs, "record_type"),
				"record_value": firstAttribute(attrs, "record_value"),
				"severity":     firstAttribute(attrs, "severity"),
			},
		})
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, alertURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, assetURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
		}
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func vulnViewAssetURN(tenantID string, attrs map[string]string) string {
	assetID := vulnViewAssetID(attrs)
	if assetID == "" {
		return ""
	}
	return projectionURN(tenantID, "external_asset", assetID)
}

func vulnViewAssetID(attrs map[string]string) string {
	raw := firstAttribute(attrs, "asset_id", "target_id", "host", "matched_at", "target_name")
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		if parsed.Port() != "" {
			return strings.ToLower(parsed.Hostname() + ":" + parsed.Port())
		}
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")))
}

func vulnViewAssetEntity(tenantID string, sourceID string, urn string, attrs map[string]string) *ports.ProjectedEntity {
	assetID := vulnViewAssetID(attrs)
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "external.asset",
		Label:      firstNonEmpty(firstAttribute(attrs, "asset_name", "target_name", "host"), assetID),
		Attributes: map[string]string{
			"asset_id":         assetID,
			"asset_type":       "external_asset",
			"findings_count":   firstAttribute(attrs, "findings_count"),
			"highest_severity": firstAttribute(attrs, "highest_severity", "severity"),
			"source_system":    "vulnview",
			"sites":            firstAttribute(attrs, "sites", "site_name", "site_id"),
		},
	}
}
