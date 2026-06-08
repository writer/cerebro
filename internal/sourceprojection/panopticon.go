package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func panopticonAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "alert_id", "case_id", "severity", "status", "title", "ioc_id", "ioc_type", "value", "asset_id", "asset_type", "asset_name")
	payload := payloadMap(event)
	alertID := firstAttribute(attrs, "alert_id")
	if alertID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	alertURN := panopticonAddAlertEntity(entities, tenantID, event.GetSourceId(), event.GetId(), attrs)
	caseURN := panopticonAddCaseEntity(entities, tenantID, event.GetSourceId(), event.GetId(), map[string]string{
		"case_id": firstNonEmpty(firstAttribute(attrs, "case_id"), stringValue(payload, "case_id")),
	})
	if caseURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_alert_case")))
	}
	for _, iocURN := range panopticonAddIOCs(entities, tenantID, event.GetSourceId(), event.GetId(), attrs, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, iocURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_alert_ioc")))
	}
	for _, assetURN := range panopticonAddAssets(entities, tenantID, event.GetSourceId(), event.GetId(), attrs, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, assetURN, relationObservedOn, panopticonLinkAttributes(event, "panopticon_alert_asset")))
	}
	for _, evidenceURN := range panopticonAddEvidencePointers(entities, tenantID, event.GetSourceId(), event.GetId(), payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, evidenceURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_alert_evidence_cas")))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func panopticonCaseProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "case_id", "status", "title")
	payload := payloadMap(event)
	caseID := firstAttribute(attrs, "case_id")
	if caseID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	caseURN := panopticonAddCaseEntity(entities, tenantID, event.GetSourceId(), event.GetId(), attrs)
	for _, alert := range panopticonObjects(payload, "alerts", "linked_alerts") {
		alertURN := panopticonAddAlertEntity(entities, tenantID, event.GetSourceId(), event.GetId(), panopticonAttributesFromObject(alert, "alert_id", "id", "severity", "status", "title"))
		if alertURN == "" {
			continue
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, alertURN, relationContains, panopticonLinkAttributes(event, "panopticon_case_alert")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_alert_case")))
	}
	for _, iocURN := range panopticonAddIOCs(entities, tenantID, event.GetSourceId(), event.GetId(), nil, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, iocURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_case_ioc")))
	}
	for _, assetURN := range panopticonAddAssets(entities, tenantID, event.GetSourceId(), event.GetId(), nil, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, assetURN, relationContains, panopticonLinkAttributes(event, "panopticon_case_asset")))
	}
	for _, evidenceURN := range panopticonAddEvidencePointers(entities, tenantID, event.GetSourceId(), event.GetId(), payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, evidenceURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_case_evidence_cas")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_evidence_cas_case")))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func panopticonIOCProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "ioc_id", "ioc_type", "value", "case_id", "alert_id")
	payload := payloadMap(event)
	iocID := firstAttribute(attrs, "ioc_id")
	value := firstAttribute(attrs, "value")
	if iocID == "" && value == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	iocURN := panopticonAddIOCEntity(entities, tenantID, event.GetSourceId(), event.GetId(), attrs)
	caseURN := panopticonAddCaseEntity(entities, tenantID, event.GetSourceId(), event.GetId(), map[string]string{
		"case_id": firstNonEmpty(firstAttribute(attrs, "case_id"), stringValue(payload, "case_id")),
	})
	if caseURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), iocURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_ioc_case")))
	}
	alertURN := panopticonAddAlertEntity(entities, tenantID, event.GetSourceId(), event.GetId(), map[string]string{
		"alert_id": firstNonEmpty(firstAttribute(attrs, "alert_id"), stringValue(payload, "alert_id")),
	})
	if alertURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, iocURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_alert_ioc")))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func panopticonProjectionAttributes(event *cerebrov1.EventEnvelope, keys ...string) map[string]string {
	attrs := make(map[string]string, len(event.GetAttributes())+len(keys))
	for key, value := range event.GetAttributes() {
		key = strings.TrimSpace(key)
		if key != "" {
			attrs[key] = value
		}
	}
	payload := payloadMap(event)
	for _, key := range keys {
		if firstAttribute(attrs, key) != "" {
			continue
		}
		if value := stringValue(payload, key); value != "" {
			attrs[key] = value
		}
	}
	return attrs
}

func panopticonAddAlertEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string) string {
	alertID := firstAttribute(attrs, "alert_id", "id")
	if alertID == "" {
		return ""
	}
	alertURN := projectionURN(tenantID, "panopticon_alert", alertID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        alertURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "panopticon.alert",
		Label:      firstAttribute(attrs, "title", "alert_id", "id"),
		Attributes: compactAttributes(map[string]string{
			"alert_id": alertID,
			"severity": firstAttribute(attrs, "severity"),
			"status":   firstAttribute(attrs, "status"),
			"title":    firstAttribute(attrs, "title"),
			"event_id": eventID,
		}),
	})
	return alertURN
}

func panopticonAddCaseEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string) string {
	caseID := firstAttribute(attrs, "case_id", "id")
	if caseID == "" {
		return ""
	}
	caseURN := projectionURN(tenantID, "panopticon_case", caseID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        caseURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "panopticon.case",
		Label:      firstAttribute(attrs, "title", "case_id", "id"),
		Attributes: compactAttributes(map[string]string{
			"case_id":  caseID,
			"status":   firstAttribute(attrs, "status"),
			"title":    firstAttribute(attrs, "title"),
			"event_id": eventID,
		}),
	})
	return caseURN
}

func panopticonAddIOCEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string) string {
	iocID := firstAttribute(attrs, "ioc_id", "id")
	value := firstAttribute(attrs, "value")
	identity := firstNonEmpty(iocID, value)
	if identity == "" {
		return ""
	}
	iocURN := projectionURN(tenantID, "panopticon_ioc", identity)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        iocURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "panopticon.ioc",
		Label:      firstNonEmpty(value, iocID),
		Attributes: compactAttributes(map[string]string{
			"ioc_id":   iocID,
			"ioc_type": firstAttribute(attrs, "ioc_type", "type"),
			"value":    value,
			"event_id": eventID,
		}),
	})
	return iocURN
}

func panopticonAddAssetEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string) string {
	assetID := firstAttribute(attrs, "asset_id", "id", "urn", "hostname", "name")
	if assetID == "" {
		return ""
	}
	assetURN := projectionURN(tenantID, "panopticon_asset", assetID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        assetURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "panopticon.asset",
		Label:      firstAttribute(attrs, "name", "hostname", "asset_id", "id"),
		Attributes: compactAttributes(map[string]string{
			"asset_id":   firstAttribute(attrs, "asset_id", "id"),
			"asset_type": firstAttribute(attrs, "asset_type", "type"),
			"hostname":   firstAttribute(attrs, "hostname"),
			"name":       firstAttribute(attrs, "name"),
			"event_id":   eventID,
		}),
	})
	return assetURN
}

func panopticonAddIOCs(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string, payload map[string]any) []string {
	seen := map[string]struct{}{}
	var urns []string
	if len(attrs) != 0 && (firstAttribute(attrs, "ioc_id", "value") != "") {
		if urn := panopticonAddIOCEntity(entities, tenantID, sourceID, eventID, attrs); urn != "" {
			seen[urn] = struct{}{}
			urns = append(urns, urn)
		}
	}
	for _, ioc := range panopticonObjects(payload, "iocs", "indicators", "observables") {
		urn := panopticonAddIOCEntity(entities, tenantID, sourceID, eventID, panopticonAttributesFromObject(ioc, "ioc_id", "id", "ioc_type", "type", "value"))
		if urn == "" {
			continue
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns
}

func panopticonAddAssets(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, attrs map[string]string, payload map[string]any) []string {
	seen := map[string]struct{}{}
	var urns []string
	if len(attrs) != 0 && firstAttribute(attrs, "asset_id", "asset_name") != "" {
		assetAttrs := map[string]string{
			"asset_id":   firstAttribute(attrs, "asset_id"),
			"asset_type": firstAttribute(attrs, "asset_type"),
			"name":       firstAttribute(attrs, "asset_name"),
			"hostname":   firstAttribute(attrs, "hostname"),
		}
		if urn := panopticonAddAssetEntity(entities, tenantID, sourceID, eventID, assetAttrs); urn != "" {
			seen[urn] = struct{}{}
			urns = append(urns, urn)
		}
	}
	for _, asset := range panopticonObjects(payload, "assets", "affected_assets", "hosts", "endpoints") {
		urn := panopticonAddAssetEntity(entities, tenantID, sourceID, eventID, panopticonAttributesFromObject(asset, "asset_id", "id", "asset_type", "type", "hostname", "name", "urn"))
		if urn == "" {
			continue
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns
}

func panopticonAddEvidencePointers(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, eventID string, payload map[string]any) []string {
	seen := map[string]struct{}{}
	var urns []string
	for _, evidence := range panopticonObjects(payload, "evidence", "evidence_pointers", "captures") {
		pointer := panopticonEvidencePointer(evidence)
		if pointer == "" {
			continue
		}
		evidenceID := firstNonEmpty(panopticonString(evidence, "evidence_id", "id"), pointer, panopticonString(evidence, "sha256"))
		evidenceURN := projectionURN(tenantID, "evidence_cas_pointer", evidenceID)
		if evidenceURN == "" {
			continue
		}
		attributes := compactAttributes(map[string]string{
			"evidence_id":      panopticonString(evidence, "evidence_id", "id"),
			"evidence_cas":     pointer,
			"evidence_cas_uri": pointer,
			"sha256":           panopticonString(evidence, "sha256", "digest"),
			"content_type":     panopticonString(evidence, "content_type"),
			"ref_type":         panopticonString(evidence, "ref_type"),
			"source_path":      panopticonString(evidence, "source_path"),
			"chain_of_custody_id": firstNonEmpty(
				panopticonString(evidence, "chain_of_custody_id"),
				panopticonString(evidence, "custody_id"),
			),
			"evidence_type": "evidence_cas.pointer",
			"pointer_only":  "true",
			"event_id":      eventID,
		})
		if panopticonHasValue(evidence, "chain_of_custody") {
			attributes["chain_of_custody_present"] = "true"
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "evidence.cas.pointer",
			Label:      firstNonEmpty(panopticonString(evidence, "label", "name"), evidenceID),
			Attributes: attributes,
		})
		if _, ok := seen[evidenceURN]; ok {
			continue
		}
		seen[evidenceURN] = struct{}{}
		urns = append(urns, evidenceURN)
	}
	return urns
}

func panopticonEvidencePointer(evidence map[string]any) string {
	if pointer := panopticonString(evidence, "evidence_cas", "evidence_cas_uri", "uri", "cas_uri", "pointer"); pointer != "" {
		return pointer
	}
	if custom := panopticonMap(evidence["custom_attributes"]); len(custom) != 0 {
		return panopticonString(custom, "evidence_cas", "evidence_cas_uri", "uri")
	}
	return ""
}

func panopticonObjects(payload map[string]any, keys ...string) []map[string]any {
	if len(payload) == 0 {
		return nil
	}
	var objects []map[string]any
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				if object := panopticonMap(item); len(object) != 0 {
					objects = append(objects, object)
				}
			}
		case []map[string]any:
			objects = append(objects, typed...)
		case map[string]any:
			objects = append(objects, typed)
		}
	}
	return objects
}

func panopticonAttributesFromObject(object map[string]any, keys ...string) map[string]string {
	attrs := make(map[string]string, len(keys))
	for _, key := range keys {
		if value := panopticonString(object, key); value != "" {
			attrs[key] = value
		}
	}
	if attrs["alert_id"] == "" && attrs["id"] != "" {
		attrs["alert_id"] = attrs["id"]
	}
	if attrs["ioc_id"] == "" && attrs["id"] != "" {
		attrs["ioc_id"] = attrs["id"]
	}
	if attrs["asset_id"] == "" && attrs["id"] != "" {
		attrs["asset_id"] = attrs["id"]
	}
	return attrs
}

func panopticonMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		return nil
	}
}

func panopticonString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(values, key); value != "" {
			return value
		}
	}
	return ""
}

func panopticonHasValue(values map[string]any, key string) bool {
	if len(values) == 0 {
		return false
	}
	value, ok := values[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) != 0
	case map[string]any:
		return len(typed) != 0
	default:
		return true
	}
}

func panopticonLinkAttributes(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	return compactAttributes(map[string]string{
		"event_id":    event.GetId(),
		"at":          eventObservedAt(event),
		"match_type":  matchType,
		"source_kind": event.GetKind(),
	})
}
