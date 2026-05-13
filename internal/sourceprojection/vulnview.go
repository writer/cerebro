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
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, assetURN, relationRepresents, firstAttribute(attrs, "asset_id", "host", "target_id", "matched_at"), "vulnview_asset_host", "0.95")
	}
	vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, assetURN, "")

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
		vulnViewAddTemplateContext(entities, links, tenantID, event.GetSourceId(), event, findingURN, attrs)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, assetURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
		}
		vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, "", findingURN)
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
	links := map[string]*ports.ProjectedLink{}
	if assetURN := vulnViewAssetURN(tenantID, attrs); assetURN != "" {
		addEntity(entities, vulnViewAssetEntity(tenantID, event.GetSourceId(), assetURN, attrs))
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, assetURN, relationRepresents, firstAttribute(attrs, "asset_id", "target_id", "host", "asset_name"), "vulnview_asset_host", "0.95")
		vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, assetURN, "")
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
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
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, assetURN, relationRepresents, firstAttribute(attrs, "asset_id", "target_id", "target_name", "asset_name"), "vulnview_asset_host", "0.95")
		vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, assetURN, "")
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
		vulnViewAddDNSAlertTypeContext(entities, links, tenantID, event.GetSourceId(), event, alertURN, attrs)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, alertURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, assetURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
		}
		vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, "", alertURN)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func vulnViewSiteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entities := map[string]*ports.ProjectedEntity{}
	for _, site := range vulnViewSiteRefs(event.GetAttributes()) {
		addEntity(entities, vulnViewSiteEntity(tenantID, event.GetSourceId(), site))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func vulnViewScanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, scan := range vulnViewScanRefs(event.GetAttributes()) {
		scanEntity := vulnViewScanEntity(tenantID, event.GetSourceId(), scan, event.GetAttributes())
		addEntity(entities, scanEntity)
		addCloudAccountContext(entities, links, tenantID, event.GetSourceId(), event.GetId(), scanEntity.URN, event.GetAttributes())
		for _, site := range vulnViewSiteRefs(event.GetAttributes()) {
			siteEntity := vulnViewSiteEntity(tenantID, event.GetSourceId(), site)
			addEntity(entities, siteEntity)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), scanEntity.URN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
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

type vulnViewRef struct {
	URN   string
	ID    string
	Name  string
	Label string
}

func vulnViewAddSiteAndScanContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, assetURN string, evidenceURN string) {
	attrs := event.GetAttributes()
	sites := vulnViewSiteRefs(attrs)
	scans := vulnViewScanRefs(attrs)
	for _, site := range sites {
		siteEntity := vulnViewSiteEntity(tenantID, sourceID, site)
		addEntity(entities, siteEntity)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, assetURN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if evidenceURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, evidenceURN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	for _, scan := range scans {
		scanEntity := vulnViewScanEntity(tenantID, sourceID, scan, attrs)
		addEntity(entities, scanEntity)
		addCloudAccountContext(entities, links, tenantID, sourceID, event.GetId(), scanEntity.URN, attrs)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, assetURN, scanEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if evidenceURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, evidenceURN, scanEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
}

func vulnViewAddTemplateContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, findingURN string, attrs map[string]string) {
	templateID := firstAttribute(attrs, "template_id", "vulnerability_id", "type")
	templateURN := projectionURN(tenantID, "vulnview_template", templateID)
	if templateURN == "" || findingURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        templateURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.template",
		Label:      firstAttribute(attrs, "template_id", "name", "vulnerability_id", "type"),
		Attributes: vulnViewAttributes(map[string]string{
			"name":        firstAttribute(attrs, "name"),
			"severity":    firstAttribute(attrs, "severity"),
			"template_id": templateID,
			"type":        firstAttribute(attrs, "type"),
		}),
	})
	addLink(links, projectedLink(tenantID, sourceID, findingURN, templateURN, relationHasClassification, map[string]string{"event_id": event.GetId(), "template_id": templateID}))
}

func vulnViewAddDNSAlertTypeContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, alertURN string, attrs map[string]string) {
	alertType := firstAttribute(attrs, "alert", "name")
	typeURN := projectionURN(tenantID, "vulnview_dns_alert_type", alertType)
	if typeURN == "" || alertURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        typeURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.dns_alert_type",
		Label:      alertType,
		Attributes: vulnViewAttributes(map[string]string{
			"alert_type": alertType,
			"severity":   firstAttribute(attrs, "severity"),
		}),
	})
	addLink(links, projectedLink(tenantID, sourceID, alertURN, typeURN, relationHasClassification, map[string]string{"alert_type": alertType, "event_id": event.GetId()}))
}

func vulnViewSiteRefs(attrs map[string]string) []vulnViewRef {
	refs := []vulnViewRef{}
	seen := map[string]struct{}{}
	add := func(id string, name string) {
		id = strings.TrimSpace(id)
		name = strings.TrimSpace(name)
		key := firstNonEmpty(id, name)
		if key == "" {
			return
		}
		dedupe := normalizeIdentifier(firstNonEmpty(id, name))
		if _, ok := seen[dedupe]; ok {
			return
		}
		seen[dedupe] = struct{}{}
		refs = append(refs, vulnViewRef{ID: id, Name: name, Label: firstNonEmpty(name, id)})
	}
	siteNameKeys := []string{"site_name"}
	if strings.EqualFold(strings.TrimSpace(attrs["family"]), "site") {
		siteNameKeys = append(siteNameKeys, "name")
	}
	add(firstAttribute(attrs, "site_id"), firstAttribute(attrs, siteNameKeys...))
	for _, name := range splitVulnViewList(firstAttribute(attrs, "sites")) {
		add("", name)
	}
	return refs
}

func vulnViewScanRefs(attrs map[string]string) []vulnViewRef {
	refs := []vulnViewRef{}
	seen := map[string]struct{}{}
	add := func(id string, name string) {
		id = strings.TrimSpace(id)
		name = strings.TrimSpace(name)
		key := firstNonEmpty(id, name)
		if key == "" {
			return
		}
		dedupe := normalizeIdentifier(key)
		if _, ok := seen[dedupe]; ok {
			return
		}
		seen[dedupe] = struct{}{}
		refs = append(refs, vulnViewRef{ID: id, Name: name, Label: firstNonEmpty(name, id)})
	}
	scanNameKeys := []string{"scan_name"}
	if strings.EqualFold(strings.TrimSpace(attrs["family"]), "scan") {
		scanNameKeys = append(scanNameKeys, "name")
	}
	add(firstAttribute(attrs, "scan_id"), firstAttribute(attrs, scanNameKeys...))
	for _, name := range splitVulnViewList(firstAttribute(attrs, "scan_names")) {
		add("", name)
	}
	return refs
}

func vulnViewSiteEntity(tenantID string, sourceID string, ref vulnViewRef) *ports.ProjectedEntity {
	ref.URN = projectionURN(tenantID, "vulnview_site", firstNonEmpty(ref.Name, ref.ID))
	return &ports.ProjectedEntity{
		URN:        ref.URN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.site",
		Label:      ref.Label,
		Attributes: vulnViewAttributes(map[string]string{
			"site_id":       ref.ID,
			"site_name":     ref.Name,
			"source_system": "vulnview",
		}),
	}
}

func vulnViewScanEntity(tenantID string, sourceID string, ref vulnViewRef, attrs map[string]string) *ports.ProjectedEntity {
	ref.URN = projectionURN(tenantID, "vulnview_scan", firstNonEmpty(ref.Name, ref.ID))
	return &ports.ProjectedEntity{
		URN:        ref.URN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.scan",
		Label:      ref.Label,
		Attributes: vulnViewAttributes(map[string]string{
			"cloud_account_id": firstAttribute(attrs, "cloud_account_id"),
			"completed_at":     firstAttribute(attrs, "completed_at"),
			"created_at":       firstAttribute(attrs, "created_at"),
			"findings_count":   firstAttribute(attrs, "findings_count"),
			"results_key":      firstAttribute(attrs, "results_key"),
			"scan_id":          ref.ID,
			"scan_name":        ref.Name,
			"scan_type":        firstAttribute(attrs, "scan_type"),
			"source_system":    "vulnview",
			"started_at":       firstAttribute(attrs, "started_at"),
			"status":           firstAttribute(attrs, "status"),
			"target":           firstAttribute(attrs, "target"),
		}),
	}
}

func vulnViewAttributes(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func splitVulnViewList(raw string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		key := normalizeIdentifier(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, value)
	}
	return values
}
