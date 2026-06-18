package sourceprojection

import (
	"regexp"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var (
	panopticonAWSInstancePattern      = regexp.MustCompile(`\bi-[0-9a-fA-F]{8,17}\b`)
	panopticonGCPProjectFieldPattern  = regexp.MustCompile(`(?i)\b(?:gcp|google)\s*project(?:\s+id)?\s*[:=]?\s*([a-z][a-z0-9-]{4,28}[a-z0-9])\b`)
	panopticonGitHubRepositoryPattern = regexp.MustCompile(`\b[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\b`)
	panopticonGitHubURLPattern        = regexp.MustCompile(`(?i)(?:https?://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?\b`)
	panopticonIPv4Pattern             = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	panopticonKubernetesPairPattern   = regexp.MustCompile(`\(([a-z0-9][a-z0-9.-]*)/([a-z0-9][a-z0-9.-]*)\)`)
	panopticonURLPattern              = regexp.MustCompile(`https?://[^\s)"']+`)
)

var panopticonAssetAttributeKeys = []string{
	"account_id",
	"agent_id",
	"asset_id",
	"asset_name",
	"asset_type",
	"cloud_provider",
	"cloud_resource_id",
	"computer_name",
	"device_id",
	"device_name",
	"device_uuid",
	"endpoint_id",
	"endpoint_type",
	"external_id",
	"hostname",
	"id",
	"name",
	"instance_id",
	"provider",
	"resource_arn",
	"resource_id",
	"resource_name",
	"resource_provider",
	"resource_type",
	"resource_urn",
	"serial_number",
	"self_link",
	"source_product",
	"source_provider",
	"target_id",
	"type",
	"urn",
	"uri",
	"aws_account_id",
	"business_critical",
	"crown_jewel",
	"data_classification",
	"data_sensitivity",
	"domain",
	"endpoint",
	"external_exposure",
	"gcp_project_id",
	"identity_principal_id",
	"internet_exposed",
	"network_interface_ids",
	"network_security_group_ids",
	"network_subnet_ids",
	"owner",
	"project_id",
	"public",
	"public_endpoint",
	"public_host",
	"public_ip",
	"public_network_access",
	"region",
	"resource_group",
	"resource_group_name",
	"role_arn",
	"role_name",
	"runtime_identity",
	"runtime_role_arn",
	"runtime_role_name",
	"runtime_service_account",
	"scope",
	"security_group_ids",
	"sensitivity",
	"service_account_email",
	"subnet_id",
	"subnet_ids",
	"subscription_id",
	"team",
	"tier0",
	"user_assigned_principal_ids",
	"vpc",
	"vpc_id",
	"zone",
}

type panopticonAssetStitchTarget struct {
	urn        string
	sourceID   string
	entityType string
	label      string
	attrs      map[string]string
	matchType  string
	matchKey   string
	matchValue string
}

func panopticonAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "alert_id", "severity", "status", "title", "case_id")
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
		"title":   firstNonEmpty(firstAttribute(attrs, "case_title"), stringValue(payload, "case_title")),
		"status":  firstNonEmpty(firstAttribute(attrs, "case_status"), stringValue(payload, "case_status")),
	})
	if caseURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, alertURN, relationContains, panopticonLinkAttributes(event, "panopticon_case_alert")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_alert_case")))
	}
	for _, iocURN := range panopticonAddIOCs(entities, tenantID, event.GetSourceId(), event.GetId(), attrs, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, iocURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_alert_ioc")))
	}
	for _, assetURN := range panopticonAddAssets(entities, tenantID, event.GetSourceId(), event.GetId(), attrs, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, assetURN, relationTargeted, panopticonLinkAttributes(event, "panopticon_alert_asset")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, alertURN, relationAffectedBy, panopticonLinkAttributes(event, "panopticon_asset_alert")))
	}
	for _, evidenceURN := range panopticonAddEvidencePointers(entities, links, tenantID, event, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, evidenceURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_alert_evidence_cas")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, alertURN, relationObservedOn, panopticonLinkAttributes(event, "panopticon_evidence_cas_alert")))
	}
	panopticonAddIOCContextAnchors(entities, links, tenantID, event.GetSourceId(), event, nil, payload)
	panopticonAddAssetContextAnchors(entities, links, tenantID, event.GetSourceId(), event, nil, payload)
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
	for _, evidenceURN := range panopticonAddEvidencePointers(entities, links, tenantID, event, payload) {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, evidenceURN, relationHasEvidence, panopticonLinkAttributes(event, "panopticon_case_evidence_cas")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, caseURN, relationBelongsTo, panopticonLinkAttributes(event, "panopticon_evidence_cas_case")))
	}
	panopticonAddContextAnchors(entities, links, tenantID, event.GetSourceId(), event, caseURN, relationAssociatedWith, attrs, payload, "panopticon_case_context")
	panopticonAddIOCContextAnchors(entities, links, tenantID, event.GetSourceId(), event, nil, payload)
	panopticonAddAssetContextAnchors(entities, links, tenantID, event.GetSourceId(), event, nil, payload)
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
	panopticonAddContextAnchors(entities, links, tenantID, event.GetSourceId(), event, iocURN, relationRepresents, attrs, payload, "panopticon_ioc_context")
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
			"agent_id":          firstAttribute(attrs, "agent_id"),
			"asset_id":          firstAttribute(attrs, "asset_id", "id"),
			"asset_type":        firstAttribute(attrs, "asset_type", "type"),
			"device_id":         firstAttribute(attrs, "device_id"),
			"device_uuid":       firstAttribute(attrs, "device_uuid"),
			"hostname":          firstAttribute(attrs, "hostname"),
			"name":              firstAttribute(attrs, "name", "asset_name", "device_name", "computer_name", "resource_name"),
			"provider":          firstAttribute(attrs, "provider", "source_provider", "resource_provider", "cloud_provider", "source_product"),
			"resource_arn":      firstAttribute(attrs, "resource_arn"),
			"resource_id":       firstAttribute(attrs, "resource_id", "cloud_resource_id"),
			"resource_provider": firstAttribute(attrs, "resource_provider", "cloud_provider"),
			"resource_type":     firstAttribute(attrs, "resource_type", "endpoint_type"),
			"resource_urn":      firstAttribute(attrs, "resource_urn", "urn"),
			"serial_number":     firstAttribute(attrs, "serial_number"),
			"event_id":          eventID,
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
		assetAttrs := panopticonAssetAttributes(attrs)
		if urn := panopticonAddAssetEntity(entities, tenantID, sourceID, eventID, assetAttrs); urn != "" {
			seen[urn] = struct{}{}
			urns = append(urns, urn)
		}
	}
	for _, asset := range panopticonObjects(payload, "assets", "affected_assets", "hosts", "endpoints") {
		urn := panopticonAddAssetEntity(entities, tenantID, sourceID, eventID, panopticonAssetAttributesFromObject(asset))
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

func panopticonAddEvidencePointers(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, payload map[string]any) []string {
	sourceID := event.GetSourceId()
	eventID := event.GetId()
	seen := map[string]struct{}{}
	var urns []string
	for _, evidence := range panopticonObjects(payload, "evidence", "evidences", "evidence_pointers", "captures") {
		pointer := panopticonEvidencePointer(evidence)
		if pointer == "" {
			continue
		}
		evidenceID := firstNonEmpty(panopticonString(evidence, "evidence_id", "id"), pointer, panopticonString(evidence, "sha256"))
		evidenceURN := projectionURN(tenantID, "evidence_cas_pointer", evidenceID)
		if evidenceURN == "" {
			continue
		}
		objectURNs := panopticonEvidenceCASObjectURNs(tenantID, evidence, pointer)
		objectURN := firstNonEmpty(objectURNs...)
		attributes := compactAttributes(map[string]string{
			"evidence_id":              panopticonString(evidence, "evidence_id", "id"),
			"evidence_cas":             pointer,
			"evidence_cas_uri":         pointer,
			"evidence_cas_object_urn":  objectURN,
			"evidence_cas_object_urns": strings.Join(objectURNs, ","),
			"sha256":                   panopticonEvidenceDigest(evidence),
			"content_type":             panopticonString(evidence, "content_type"),
			"ref_type":                 panopticonString(evidence, "ref_type"),
			"source_path":              panopticonString(evidence, "source_path"),
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
		for _, objectURN := range objectURNs {
			addLink(links, projectedLink(tenantID, sourceID, evidenceURN, objectURN, relationRepresents, panopticonAnchorAttributes(event, "panopticon_evidence_cas_object", "evidence_cas_object_urn", objectURN)))
		}
		if _, ok := seen[evidenceURN]; ok {
			continue
		}
		seen[evidenceURN] = struct{}{}
		urns = append(urns, evidenceURN)
	}
	return urns
}

// panopticonEvidenceCASObjectURNs returns tenant-scoped candidate Evidence CAS
// object URNs for an evidence reference. EvidenceCAS may project the canonical
// runtime evidence under either legacy metadata.evidence_id or the CAS URI, so
// Panopticon preserves both graph-visible joins when both identifiers are
// present.
func panopticonEvidenceCASObjectURNs(tenantID string, evidence map[string]any, pointer string) []string {
	objectIDs := panopticonEvidenceCASObjectIDs(evidence, pointer)
	urns := make([]string, 0, len(objectIDs))
	for _, objectID := range objectIDs {
		if urn := projectionURN(tenantID, "runtime_evidence", objectID); urn != "" {
			urns = append(urns, urn)
		}
	}
	return urns
}

func panopticonEvidenceCASObjectIDs(evidence map[string]any, pointer string) []string {
	candidates := []string{
		panopticonString(evidence, "evidence_id", "id"),
		pointer,
	}
	if pointer == "" {
		candidates = append(candidates, panopticonEvidenceDigest(evidence))
	}
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		ids = append(ids, candidate)
	}
	return ids
}

func panopticonEvidencePointer(evidence map[string]any) string {
	if pointer := panopticonString(evidence, "evidence_cas", "evidence_cas_uri", "uri", "cas_uri", "pointer"); pointer != "" {
		return pointer
	}
	if custom := panopticonMap(evidence["custom_attributes"]); len(custom) != 0 {
		if pointer := panopticonString(custom, "evidence_cas", "evidence_cas_uri", "uri"); pointer != "" {
			return pointer
		}
		if evidenceCAS := panopticonMap(custom["evidence_cas"]); len(evidenceCAS) != 0 {
			if pointer := panopticonString(evidenceCAS, "uri", "evidence_cas_uri", "cas_uri", "pointer"); pointer != "" {
				return pointer
			}
		}
	}
	if custody := panopticonMap(evidence["chain_of_custody"]); len(custody) != 0 {
		if pointer := panopticonString(custody, "evidence_cas", "evidence_cas_uri", "uri"); pointer != "" {
			return pointer
		}
		if evidenceCAS := panopticonMap(custody["evidence_cas"]); len(evidenceCAS) != 0 {
			return panopticonString(evidenceCAS, "uri", "evidence_cas_uri", "cas_uri", "pointer")
		}
	}
	return ""
}

func panopticonEvidenceDigest(evidence map[string]any) string {
	if digest := panopticonString(evidence, "sha256", "digest", "file_hash"); digest != "" {
		return digest
	}
	if custom := panopticonMap(evidence["custom_attributes"]); len(custom) != 0 {
		if evidenceCAS := panopticonMap(custom["evidence_cas"]); len(evidenceCAS) != 0 {
			return panopticonString(evidenceCAS, "sha256", "digest", "file_hash")
		}
	}
	return ""
}

type panopticonContextSample struct {
	key   string
	value string
}

func panopticonAddIOCContextAnchors(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, attrs map[string]string, payload map[string]any) {
	if len(attrs) != 0 && (firstAttribute(attrs, "ioc_id", "value") != "") {
		iocURN := panopticonAddIOCEntity(entities, tenantID, sourceID, event.GetId(), attrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, iocURN, relationRepresents, attrs, nil, "panopticon_ioc_context")
	}
	for _, ioc := range panopticonObjects(payload, "iocs", "indicators", "observables") {
		iocAttrs := panopticonAttributesFromObject(ioc, "ioc_id", "id", "ioc_type", "type", "value")
		iocURN := panopticonAddIOCEntity(entities, tenantID, sourceID, event.GetId(), iocAttrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, iocURN, relationRepresents, iocAttrs, ioc, "panopticon_ioc_context")
	}
}

func panopticonAddAssetContextAnchors(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, attrs map[string]string, payload map[string]any) {
	if len(attrs) != 0 && firstAttribute(attrs, "asset_id", "asset_name") != "" {
		assetAttrs := panopticonAssetAttributes(attrs)
		assetURN := panopticonAddAssetEntity(entities, tenantID, sourceID, event.GetId(), assetAttrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, assetURN, relationRepresents, assetAttrs, nil, "panopticon_asset_context")
		panopticonAddAssetStitching(entities, links, tenantID, sourceID, event, assetURN, assetAttrs)
	}
	for _, asset := range panopticonObjects(payload, "assets", "affected_assets", "hosts", "endpoints") {
		assetAttrs := panopticonAssetAttributesFromObject(asset)
		assetURN := panopticonAddAssetEntity(entities, tenantID, sourceID, event.GetId(), assetAttrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, assetURN, relationRepresents, assetAttrs, asset, "panopticon_asset_context")
		panopticonAddAssetStitching(entities, links, tenantID, sourceID, event, assetURN, assetAttrs)
	}
}

func panopticonAssetAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range panopticonAssetAttributeKeys {
		if value := firstAttribute(attrs, key); value != "" {
			out[key] = value
		}
	}
	if out["name"] == "" {
		out["name"] = firstAttribute(attrs, "asset_name", "device_name", "computer_name", "resource_name")
	}
	if out["asset_type"] == "" {
		out["asset_type"] = firstAttribute(attrs, "type", "resource_type", "endpoint_type")
	}
	return out
}

func panopticonAssetAttributesFromObject(object map[string]any) map[string]string {
	out := map[string]string{}
	for _, key := range panopticonAssetAttributeKeys {
		if value := panopticonString(object, key); value != "" {
			out[key] = value
		}
	}
	if out["asset_type"] == "" {
		out["asset_type"] = firstNonEmpty(out["type"], out["resource_type"], out["endpoint_type"])
	}
	if out["name"] == "" {
		out["name"] = firstNonEmpty(out["asset_name"], out["device_name"], out["computer_name"], out["resource_name"])
	}
	if out["asset_id"] == "" && out["id"] != "" {
		out["asset_id"] = out["id"]
	}
	return out
}

func panopticonAddAssetStitching(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, assetURN string, attrs map[string]string) {
	if strings.TrimSpace(assetURN) == "" {
		return
	}
	seen := map[string]struct{}{}
	for _, target := range panopticonAssetStitchTargets(tenantID, sourceID, attrs) {
		if target.urn == "" {
			continue
		}
		if _, ok := seen[target.urn]; ok {
			continue
		}
		seen[target.urn] = struct{}{}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        target.urn,
			TenantID:   tenantID,
			SourceID:   firstNonEmpty(target.sourceID, sourceID),
			EntityType: target.entityType,
			Label:      target.label,
			Attributes: target.attrs,
		})
		addLink(links, projectedLink(tenantID, sourceID, assetURN, target.urn, relationRepresents, panopticonAssetStitchAttributes(event, target)))
		panopticonAddCloudAssetEnrichment(entities, links, tenantID, sourceID, event, target, attrs)
	}
}

func panopticonAssetStitchTargets(tenantID string, sourceID string, attrs map[string]string) []panopticonAssetStitchTarget {
	var targets []panopticonAssetStitchTarget
	if target := panopticonExplicitAssetURNTarget(tenantID, attrs); target.urn != "" {
		targets = append(targets, target)
	}
	if target := panopticonEndpointAssetTarget(tenantID, attrs); target.urn != "" {
		targets = append(targets, target)
	}
	if target := panopticonCloudAssetTarget(tenantID, sourceID, attrs); target.urn != "" {
		targets = append(targets, target)
	}
	return targets
}

func panopticonExplicitAssetURNTarget(tenantID string, attrs map[string]string) panopticonAssetStitchTarget {
	urn := firstAttribute(attrs, "urn", "resource_urn")
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if !panopticonAllowedCanonicalAssetURN(tenantID, urn) {
		return panopticonAssetStitchTarget{}
	}
	kind := parts[3]
	matchValue := strings.Join(parts[4:], ":")
	return panopticonAssetStitchTarget{
		urn:        urn,
		sourceID:   panopticonCanonicalAssetSourceID(kind),
		entityType: panopticonCanonicalAssetEntityType(kind),
		label:      firstNonEmpty(firstAttribute(attrs, "name", "hostname", "resource_name", "device_name", "computer_name"), matchValue, urn),
		attrs: compactAttributes(map[string]string{
			"canonical_urn":       urn,
			"source_product":      panopticonCanonicalAssetSourceID(kind),
			"resource_id":         matchValue,
			"resource_provider":   panopticonCanonicalAssetProvider(kind),
			"resource_type":       panopticonCanonicalAssetResourceType(kind),
			"panopticon_stitched": "true",
		}),
		matchType:  "panopticon_asset_cerebro_urn",
		matchKey:   "urn",
		matchValue: urn,
	}
}

func panopticonEndpointAssetTarget(tenantID string, attrs map[string]string) panopticonAssetStitchTarget {
	provider := panopticonAssetProvider(attrs)
	switch provider {
	case "sentinelone":
		agentID := firstAttribute(attrs, "agent_id", "sentinelone_agent_id")
		if agentID == "" {
			return panopticonAssetStitchTarget{}
		}
		return panopticonAssetStitchTarget{
			urn:        sentinelOneAgentURN(tenantID, agentID),
			sourceID:   "sentinelone",
			entityType: sentinelOneEntityAgent,
			label:      firstAttribute(attrs, "computer_name", "hostname", "name", "device_name", "agent_id"),
			attrs: compactAttributes(map[string]string{
				"agent_id":            agentID,
				"computer_name":       firstAttribute(attrs, "computer_name", "name", "device_name"),
				"hostname":            firstAttribute(attrs, "hostname", "computer_name"),
				"source_product":      "sentinelone",
				"panopticon_stitched": "true",
			}),
			matchType:  "panopticon_asset_sentinelone_agent_id",
			matchKey:   "agent_id",
			matchValue: agentID,
		}
	case "kolide":
		return panopticonEndpointDeviceTarget(tenantID, attrs, kolideEndpointProfile, "panopticon_asset_kolide_device_id")
	case "kandji":
		return panopticonEndpointDeviceTarget(tenantID, attrs, kandjiEndpointProfile, "panopticon_asset_kandji_device_id")
	default:
		return panopticonAssetStitchTarget{}
	}
}

func panopticonEndpointDeviceTarget(tenantID string, attrs map[string]string, profile endpointProjectionProfile, matchType string) panopticonAssetStitchTarget {
	deviceID, matchKey := panopticonFirstAssetAttribute(attrs, "device_id", "device_uuid", "serial_number", "external_id")
	if deviceID == "" {
		return panopticonAssetStitchTarget{}
	}
	return panopticonAssetStitchTarget{
		urn:        projectionURN(tenantID, profile.EndpointKind, deviceID),
		sourceID:   profile.Provider,
		entityType: profile.EndpointType,
		label:      firstAttribute(attrs, "device_name", "hostname", "computer_name", "name", "serial_number"),
		attrs: compactAttributes(map[string]string{
			"device_id":           deviceID,
			"device_uuid":         firstAttribute(attrs, "device_uuid"),
			"hostname":            firstAttribute(attrs, "hostname", "computer_name"),
			"serial_number":       firstAttribute(attrs, "serial_number"),
			"source_product":      profile.Provider,
			"panopticon_stitched": "true",
		}),
		matchType:  matchType,
		matchKey:   matchKey,
		matchValue: deviceID,
	}
}

func panopticonCloudAssetTarget(tenantID string, sourceID string, attrs map[string]string) panopticonAssetStitchTarget {
	provider := panopticonAssetProvider(attrs)
	if provider != "aws" && provider != "azure" && provider != "gcp" {
		return panopticonAssetStitchTarget{}
	}
	resourceID, matchKey := panopticonCloudResourceID(provider, attrs)
	if resourceID == "" {
		return panopticonAssetStitchTarget{}
	}
	if strings.HasPrefix(resourceID, "urn:cerebro:") && !panopticonAllowedCanonicalAssetURN(tenantID, resourceID) {
		return panopticonAssetStitchTarget{}
	}
	resourceType := panopticonCloudResourceType(provider, attrs, resourceID)
	if resourceType == "" {
		return panopticonAssetStitchTarget{}
	}
	if !panopticonAllowedCanonicalAssetKind(provider + "_" + resourceType) {
		return panopticonAssetStitchTarget{}
	}
	resourceURN := firstAttribute(attrs, "resource_urn")
	targetURN := resourceURN
	if targetURN == "" {
		targetURN = projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	}
	return panopticonAssetStitchTarget{
		urn:        targetURN,
		sourceID:   provider,
		entityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
		label:      firstAttribute(attrs, "resource_name", "name", "asset_name", "hostname", "resource_id"),
		attrs:      panopticonCloudAssetEntityAttributes(provider, sourceID, attrs, resourceID, resourceType, targetURN),
		matchType:  "panopticon_asset_" + provider + "_resource_id",
		matchKey:   matchKey,
		matchValue: resourceID,
	}
}

func panopticonAddCloudAssetEnrichment(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, target panopticonAssetStitchTarget, attrs map[string]string) {
	provider := target.sourceID
	if provider != "aws" && provider != "azure" && provider != "gcp" {
		return
	}
	cloudAttrs := panopticonCloudAssetEntityAttributes(provider, sourceID, attrs, target.attrs["resource_id"], target.attrs["resource_type"], target.urn)
	accountID := cloudResourceAccountID(provider, cloudAttrs, cloudAttrs["resource_id"], target.urn)
	if accountID != "" {
		cloudAttrs["domain"] = firstNonEmpty(cloudAttrs["domain"], accountID)
		addCloudAccountLink(entities, links, tenantID, sourceID, event, target.urn, accountID, provider)
	}
	addAzureResourceGroupLinks(entities, links, tenantID, sourceID, event, identityProjectionProfile{Provider: provider}, cloudAttrs, target.urn)
	addCloudResourceOwnerLink(entities, links, tenantID, event, target.urn, firstNonEmpty(cloudAttrs["owner"], cloudAttrs["team"]))
	addCloudResourceClassificationLinks(entities, links, tenantID, event, target.urn, cloudAttrs, cloudResourceProjectionOptions{})
	if provider == "aws" {
		addAWSNetworkContextLinks(entities, links, tenantID, sourceID, event, target.urn, cloudAttrs)
	}
}

func panopticonCloudAssetEntityAttributes(provider string, sourceID string, attrs map[string]string, resourceID string, resourceType string, targetURN string) map[string]string {
	out := compactAttributes(cloneStringMap(attrs))
	out["resource_id"] = firstNonEmpty(resourceID, out["resource_id"], out["cloud_resource_id"])
	out["resource_provider"] = provider
	out["resource_type"] = resourceType
	out["resource_urn"] = firstNonEmpty(out["resource_urn"], targetURN)
	out["source_product"] = firstNonEmpty(provider, sourceID)
	out["panopticon_stitched"] = "true"
	switch provider {
	case "aws":
		if accountID := cloudResourceAccountID(provider, out, out["resource_id"], targetURN); accountID != "" {
			out["account_id"] = firstNonEmpty(out["account_id"], accountID)
			out["domain"] = firstNonEmpty(out["domain"], accountID)
		}
	case "azure":
		if subscriptionID := cloudResourceAccountID(provider, out, out["resource_id"], targetURN); subscriptionID != "" {
			out["subscription_id"] = firstNonEmpty(out["subscription_id"], subscriptionID)
		}
	case "gcp":
		if projectID := cloudResourceAccountID(provider, out, out["resource_id"], targetURN); projectID != "" {
			out["project_id"] = firstNonEmpty(out["project_id"], projectID)
			out["gcp_project_id"] = firstNonEmpty(out["gcp_project_id"], projectID)
		}
	}
	return out
}

func panopticonAssetProvider(attrs map[string]string) string {
	provider := normalizeCloudProvider(firstAttribute(attrs, "resource_provider", "cloud_provider", "source_provider", "provider", "source_product"))
	switch provider {
	case "sentinel_one", "sentinel-one":
		return "sentinelone"
	case "amazon", "amazonaws":
		return "aws"
	case "google":
		return "gcp"
	case "microsoft":
		return "azure"
	case "aws", "azure", "gcp", "sentinelone", "kolide", "kandji":
		return provider
	}
	assetType := normalizeIdentifier(firstAttribute(attrs, "asset_type", "type", "resource_type", "endpoint_type"))
	switch {
	case strings.HasPrefix(assetType, "sentinelone") || strings.HasPrefix(assetType, "sentinel_one"):
		return "sentinelone"
	case strings.HasPrefix(assetType, "kolide"):
		return "kolide"
	case strings.HasPrefix(assetType, "kandji"):
		return "kandji"
	case strings.HasPrefix(assetType, "aws"):
		return "aws"
	case strings.HasPrefix(assetType, "azure"):
		return "azure"
	case strings.HasPrefix(assetType, "gcp") || strings.HasPrefix(assetType, "google_cloud"):
		return "gcp"
	default:
		return ""
	}
}

func panopticonCloudResourceType(provider string, attrs map[string]string, resourceID string) string {
	rawType := firstAttribute(attrs, "resource_type", "asset_type", "type")
	resourceType := panopticonCloudResourceTypeAlias(provider, rawType)
	resourceType = strings.TrimPrefix(resourceType, provider+"_")
	if resourceType != "" {
		return resourceType
	}
	switch provider {
	case "aws":
		return panopticonAWSResourceTypeFromARN(firstNonEmpty(firstAttribute(attrs, "resource_arn"), resourceID))
	case "azure":
		return panopticonAzureResourceTypeFromID(resourceID)
	case "gcp":
		rawResourceID := firstAttribute(attrs, "resource_id", "cloud_resource_id", "self_link", "uri")
		return panopticonGCPResourceTypeFromID(firstNonEmpty(rawResourceID, resourceID))
	}
	return ""
}

func panopticonCloudResourceID(provider string, attrs map[string]string) (string, string) {
	if resourceURN := firstAttribute(attrs, "resource_urn"); resourceURN != "" {
		return resourceURN, "resource_urn"
	}
	for _, key := range []string{"resource_arn", "resource_id", "cloud_resource_id", "self_link", "uri"} {
		value := firstAttribute(attrs, key)
		if value == "" {
			continue
		}
		if provider == "aws" {
			value = panopticonNormalizeAWSResourceID(attrs, value)
		}
		if provider == "gcp" {
			value = panopticonNormalizeGCPResourceID(attrs, key, value)
		}
		return value, key
	}
	return "", ""
}

func panopticonNormalizeAWSResourceID(attrs map[string]string, value string) string {
	resourceType := panopticonCloudResourceTypeAlias("aws", firstAttribute(attrs, "resource_type", "asset_type", "type"))
	if resourceType == "" {
		resourceType = panopticonAWSResourceTypeFromARN(value)
	}
	parts := strings.SplitN(strings.TrimSpace(value), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[5] == "" {
		return value
	}
	resource := parts[5]
	for _, prefix := range panopticonAWSBareIDResourcePrefixes(resourceType) {
		for _, separator := range []string{"/", ":"} {
			if after, ok := strings.CutPrefix(resource, prefix+separator); ok && strings.TrimSpace(after) != "" {
				return strings.TrimSpace(after)
			}
		}
	}
	return value
}

func panopticonAWSBareIDResourcePrefixes(resourceType string) []string {
	switch resourceType {
	case "ec2_instance":
		return []string{"instance"}
	case "network_interface":
		return []string{"network-interface", "network_interface"}
	case "security_group":
		return []string{"security-group", "security_group"}
	case "subnet":
		return []string{"subnet"}
	case "vpc":
		return []string{"vpc"}
	default:
		return nil
	}
}

func panopticonCloudResourceTypeAlias(provider string, value string) string {
	normalized := normalizeCloudType(value)
	normalized = strings.ReplaceAll(normalized, ":", "_")
	switch provider {
	case "aws":
		switch normalized {
		case "aws_ec2_instance", "aws__ec2__instance", "server":
			return "ec2_instance"
		case "aws_s3_bucket":
			return "s3_bucket"
		case "aws_lambda_function":
			return "lambda_function"
		}
	case "azure":
		switch normalized {
		case "microsoft_compute_virtualmachines", "azure_virtual_machine":
			return "virtual_machine"
		case "microsoft_storage_storageaccounts":
			return "storage_account"
		case "microsoft_keyvault_vaults":
			return "key_vault"
		case "microsoft_keyvault_vaults_secrets":
			return "key_vault_secret"
		case "microsoft_sql_servers_databases":
			return "sql_database"
		}
	case "gcp":
		switch normalized {
		case "run_googleapis_com_service", "cloud_run_service", "cloudrun_service":
			return "cloud_run_service"
		case "sqladmin_googleapis_com_instance", "cloud_sql_instance", "cloudsql_instance", "sql_instance":
			return "cloud_sql_instance"
		case "container_googleapis_com_cluster", "gke_cluster", "kubernetes_cluster":
			return "gke_cluster"
		case "compute_googleapis_com_instance", "compute_instance":
			return "compute_instance"
		case "storage_googleapis_com_bucket", "storage_bucket", "bucket", "gcs_bucket":
			return "gcs_bucket"
		}
	}
	return normalized
}

func panopticonAWSResourceTypeFromARN(value string) string {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] == "" || parts[5] == "" {
		return ""
	}
	service := normalizeIdentifier(parts[2])
	resource := strings.TrimSpace(parts[5])
	resourceKind := resource
	if before, _, ok := strings.Cut(resourceKind, "/"); ok {
		resourceKind = before
	}
	if before, _, ok := strings.Cut(resourceKind, ":"); ok {
		resourceKind = before
	}
	resourceKind = normalizeCloudType(resourceKind)
	if alias := panopticonAWSARNResourceTypeAlias(service, resourceKind); alias != "" {
		return alias
	}
	if service == "s3" && resourceKind != "" {
		resourceKind = "bucket"
	}
	if service == "" || resourceKind == "" {
		return ""
	}
	return service + "_" + resourceKind
}

func panopticonAWSARNResourceTypeAlias(service string, resourceKind string) string {
	switch service + ":" + resourceKind {
	case "apprunner:service":
		return "apprunner_service"
	case "ec2:instance":
		return "ec2_instance"
	case "ec2:volume":
		return "ebs_volume"
	case "ec2:snapshot":
		return "ebs_snapshot"
	case "ec2:security_group":
		return "security_group"
	case "ec2:subnet":
		return "subnet"
	case "ec2:vpc":
		return "vpc"
	case "ec2:network_interface":
		return "network_interface"
	case "ecs:service":
		return "ecs_service"
	case "ecs:task":
		return "ecs_task"
	case "ecs:task_definition":
		return "ecs_task_definition"
	case "elasticache:cluster":
		return "elasticache_cluster"
	case "kinesis:stream":
		return "kinesis_stream"
	case "lambda:function":
		return "lambda_function"
	case "rds:db":
		return "rds_instance"
	case "s3:bucket":
		return "s3_bucket"
	}
	return ""
}

func panopticonAzureResourceTypeFromID(value string) string {
	namespace, typeName := panopticonAzureProviderType(value)
	if namespace == "" || typeName == "" {
		return ""
	}
	return panopticonCloudResourceTypeAlias("azure", namespace+"/"+typeName)
}

func panopticonAzureProviderType(value string) (string, string) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	for index := 0; index+2 < len(parts); index++ {
		if strings.EqualFold(parts[index], "providers") {
			namespace := strings.TrimSpace(parts[index+1])
			typeName := strings.TrimSpace(parts[index+2])
			if index+4 < len(parts) && strings.EqualFold(namespace, "Microsoft.KeyVault") && strings.EqualFold(typeName, "vaults") && strings.EqualFold(parts[index+4], "secrets") {
				typeName += "/secrets"
			}
			if index+4 < len(parts) && strings.EqualFold(namespace, "Microsoft.Sql") && strings.EqualFold(typeName, "servers") && strings.EqualFold(parts[index+4], "databases") {
				typeName += "/databases"
			}
			return namespace, typeName
		}
	}
	return "", ""
}

func panopticonGCPResourceTypeFromID(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(lower, "storage.googleapis.com/") && strings.Contains(lower, "/buckets/"):
		return "gcs_bucket"
	case strings.Contains(lower, "sqladmin.googleapis.com/") && strings.Contains(lower, "/instances/"):
		return "cloud_sql_instance"
	case strings.Contains(lower, "container.googleapis.com/") && strings.Contains(lower, "/clusters/"):
		return "gke_cluster"
	case strings.Contains(lower, "run.googleapis.com/") && strings.Contains(lower, "/services/"):
		return "cloud_run_service"
	case strings.Contains(lower, "/locations/") && strings.Contains(lower, "/services/"):
		return "cloud_run_service"
	case strings.Contains(lower, "compute.googleapis.com/") && strings.Contains(lower, "/instances/"):
		return "compute_instance"
	case strings.Contains(lower, "/zones/") && strings.Contains(lower, "/instances/"):
		return "compute_instance"
	default:
		return ""
	}
}

func panopticonNormalizeGCPResourceID(attrs map[string]string, key string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	resourceType := panopticonCloudResourceTypeAlias("gcp", firstAttribute(attrs, "resource_type", "asset_type", "type"))
	if resourceType == "" {
		resourceType = panopticonGCPResourceTypeFromID(value)
	}
	switch resourceType {
	case "compute_instance":
		return firstNonEmpty(firstAttribute(attrs, "instance_id", "resource_name", "name"), panopticonLastPathSegment(value))
	case "cloud_sql_instance", "gke_cluster":
		if key == "self_link" || strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
			return value
		}
		return firstNonEmpty(firstAttribute(attrs, "self_link"), value)
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "storage.googleapis.com/") && strings.Contains(lower, "/buckets/") {
		parts := strings.Split(value, "/")
		for index := 0; index+1 < len(parts); index++ {
			if parts[index] == "buckets" && strings.TrimSpace(parts[index+1]) != "" {
				return strings.TrimSpace(parts[index+1])
			}
		}
	}
	if index := strings.Index(value, "/projects/"); index >= 0 {
		return strings.TrimPrefix(value[index:], "/")
	}
	if strings.HasPrefix(value, "projects/") {
		return value
	}
	return value
}

func panopticonLastPathSegment(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return strings.TrimSpace(parts[len(parts)-1])
}

func panopticonFirstAssetAttribute(attrs map[string]string, keys ...string) (string, string) {
	for _, key := range keys {
		if value := firstAttribute(attrs, key); value != "" {
			return value, key
		}
	}
	return "", ""
}

func panopticonAllowedCanonicalAssetKind(kind string) bool {
	switch kind {
	case
		"sentinelone_agent",
		"kolide_device",
		"kandji_device",
		"aws_access_analyzer",
		"aws_acm_certificate",
		"aws_apigateway_integration",
		"aws_apigateway_route",
		"aws_apigateway_stage",
		"aws_apprunner_service",
		"aws_athena_data_catalog",
		"aws_athena_workgroup",
		"aws_backup_plan",
		"aws_backup_protected_resource",
		"aws_backup_recovery_point",
		"aws_backup_vault",
		"aws_batch_compute_environment",
		"aws_batch_job_queue",
		"aws_cloudfront_key_group",
		"aws_cloudfront_origin_access_control",
		"aws_cloudfront_public_key",
		"aws_cloudfront_response_headers_policy",
		"aws_cloudtrail",
		"aws_cloudwatch_alarm",
		"aws_cloudwatch_log_group",
		"aws_config_recorder",
		"aws_datasync_location",
		"aws_datasync_task",
		"aws_docdb_cluster",
		"aws_docdb_instance",
		"aws_dynamodb_backup",
		"aws_dynamodb_stream",
		"aws_dynamodb_table",
		"aws_ebs_snapshot",
		"aws_ebs_volume",
		"aws_ec2_instance",
		"aws_ecr_repository",
		"aws_ecs_service",
		"aws_ecs_task",
		"aws_ecs_task_definition",
		"aws_efs_access_point",
		"aws_efs_file_system",
		"aws_eks_cluster",
		"aws_eks_fargate_profile",
		"aws_eks_nodegroup",
		"aws_elasticache_cluster",
		"aws_elasticache_replication_group",
		"aws_elasticache_subnet_group",
		"aws_elbv2_listener",
		"aws_elbv2_target_group",
		"aws_eventbridge_archive",
		"aws_eventbridge_event_bus",
		"aws_eventbridge_pipe",
		"aws_eventbridge_rule",
		"aws_firehose_delivery_stream",
		"aws_fsx_file_system",
		"aws_globalaccelerator_accelerator",
		"aws_globalaccelerator_endpoint_group",
		"aws_globalaccelerator_listener",
		"aws_glue_crawler",
		"aws_glue_database",
		"aws_glue_job",
		"aws_glue_table",
		"aws_internet_gateway",
		"aws_kinesis_stream",
		"aws_kms_key",
		"aws_lambda_function",
		"aws_msk_cluster",
		"aws_nat_gateway",
		"aws_neptune_cluster",
		"aws_neptune_instance",
		"aws_network_firewall",
		"aws_network_interface",
		"aws_opensearch_domain",
		"aws_opensearch_serverless_collection",
		"aws_opensearch_serverless_security_policy",
		"aws_rds_instance",
		"aws_redshift_cluster",
		"aws_route53_resolver_endpoint",
		"aws_route53_resolver_rule",
		"aws_route_table",
		"aws_s3_access_point",
		"aws_s3_bucket",
		"aws_s3_multi_region_access_point",
		"aws_scheduler_schedule",
		"aws_scheduler_schedule_group",
		"aws_secret",
		"aws_security_group",
		"aws_sns_topic",
		"aws_sqs_queue",
		"aws_ssm_association",
		"aws_ssm_document",
		"aws_ssm_managed_instance",
		"aws_ssm_parameter",
		"aws_stepfunctions_activity",
		"aws_stepfunctions_state_machine",
		"aws_subnet",
		"aws_vpc",
		"aws_vpc_endpoint",
		"aws_vpclattice_listener",
		"aws_vpclattice_service",
		"aws_vpclattice_target_group",
		"aws_wafv2_web_acl",
		"azure_aks_cluster",
		"azure_app_service",
		"azure_container_registry",
		"azure_cosmos_account",
		"azure_function_app",
		"azure_key_vault",
		"azure_key_vault_key",
		"azure_key_vault_secret",
		"azure_sql_database",
		"azure_sql_server",
		"azure_storage_account",
		"azure_virtual_machine",
		"gcp_artifact_registry_image",
		"gcp_artifact_registry_repository",
		"gcp_cloud_function",
		"gcp_cloud_run_service",
		"gcp_cloud_sql_instance",
		"gcp_compute_instance",
		"gcp_gcs_bucket",
		"gcp_gke_cluster",
		"gcp_kms_key",
		"gcp_secret_manager_secret":
		return true
	}
	return false
}

func panopticonAllowedCanonicalAssetURN(tenantID string, urn string) bool {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	return len(parts) >= 4 && parts[0] == "urn" && parts[1] == "cerebro" && parts[2] == tenantID && panopticonAllowedCanonicalAssetKind(parts[3])
}

func panopticonCanonicalAssetSourceID(kind string) string {
	switch {
	case kind == "sentinelone_agent":
		return "sentinelone"
	case kind == "kolide_device":
		return "kolide"
	case kind == "kandji_device":
		return "kandji"
	case strings.HasPrefix(kind, "aws_"):
		return "aws"
	case strings.HasPrefix(kind, "azure_"):
		return "azure"
	case strings.HasPrefix(kind, "gcp_"):
		return "gcp"
	default:
		return ""
	}
}

func panopticonCanonicalAssetProvider(kind string) string {
	sourceID := panopticonCanonicalAssetSourceID(kind)
	if sourceID == "sentinelone" || sourceID == "kolide" || sourceID == "kandji" {
		return ""
	}
	return sourceID
}

func panopticonCanonicalAssetResourceType(kind string) string {
	for _, prefix := range []string{"aws_", "azure_", "gcp_"} {
		if strings.HasPrefix(kind, prefix) {
			return strings.TrimPrefix(kind, prefix)
		}
	}
	return ""
}

func panopticonCanonicalAssetEntityType(kind string) string {
	switch kind {
	case "sentinelone_agent":
		return sentinelOneEntityAgent
	case "kolide_device":
		return kolideEndpointProfile.EndpointType
	case "kandji_device":
		return kandjiEndpointProfile.EndpointType
	default:
		sourceID := panopticonCanonicalAssetSourceID(kind)
		if sourceID == "" {
			return ""
		}
		resourceType := strings.TrimPrefix(kind, sourceID+"_")
		return sourceID + "." + strings.ReplaceAll(resourceType, "_", ".")
	}
}

func panopticonAssetStitchAttributes(event *cerebrov1.EventEnvelope, target panopticonAssetStitchTarget) map[string]string {
	attrs := panopticonLinkAttributes(event, target.matchType)
	attrs["confidence"] = "0.99"
	attrs["evidence_type"] = "provider_asset_identifier"
	addProjectedAttribute(attrs, "identifier_key", target.matchKey)
	addProjectedAttribute(attrs, "identifier_value", target.matchValue)
	addProjectedAttribute(attrs, "target_urn", target.urn)
	return attrs
}

func panopticonAddContextAnchors(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, attrs map[string]string, payload map[string]any, matchPrefix string) {
	if strings.TrimSpace(fromURN) == "" {
		return
	}
	samples := panopticonContextSamples(attrs, payload)
	for _, ip := range panopticonContextIPs(samples) {
		panopticonAddInternetIPAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, ip, matchPrefix+"_ip")
	}
	for _, host := range panopticonContextHosts(samples) {
		panopticonAddInternetHostAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, host, matchPrefix+"_host")
	}
	for _, instanceID := range panopticonContextAWSInstances(samples) {
		panopticonAddAWSInstanceAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, instanceID, matchPrefix+"_aws_instance")
	}
	for _, repository := range panopticonContextGitHubRepositories(samples) {
		panopticonAddGitHubRepositoryAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, repository, matchPrefix+"_github_code_repository")
	}
	for _, projectID := range panopticonContextGCPProjects(samples) {
		panopticonAddCloudAccountAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, "gcp", projectID, matchPrefix+"_gcp_project")
	}
	panopticonAddKubernetesContextAnchors(entities, links, tenantID, sourceID, event, fromURN, relation, samples, matchPrefix)
	for _, sample := range samples {
		for _, email := range emailIdentifierPattern.FindAllString(sample.value, -1) {
			addIdentifierLink(entities, links, tenantID, sourceID, event.GetId(), fromURN, email, event.GetOccurredAt())
			if panopticonOwnerField(sample.key) {
				identityURN, _ := canonicalIdentityURN(tenantID, email)
				if identityURN != "" {
					addLink(links, projectedLink(tenantID, sourceID, fromURN, identityURN, relationOwnedBy, panopticonAnchorAttributes(event, matchPrefix+"_owner_email", "email", strings.ToLower(email))))
				}
			}
		}
	}
}

func panopticonAddInternetIPAnchor(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, rawIP string, matchType string) {
	ipURN, ip := internetIPURN(tenantID, rawIP)
	if ipURN == "" {
		return
	}
	addInternetIPEntity(entities, tenantID, sourceID, ipURN, ip)
	addLink(links, projectedLink(tenantID, sourceID, fromURN, ipURN, relation, panopticonAnchorAttributes(event, matchType, "ip", ip)))
}

func panopticonAddInternetHostAnchor(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, rawHost string, matchType string) {
	hostURN, host := internetHostURN(tenantID, rawHost)
	if hostURN == "" {
		return
	}
	addInternetHostEntity(entities, tenantID, sourceID, hostURN, host)
	addLink(links, projectedLink(tenantID, sourceID, fromURN, hostURN, relation, panopticonAnchorAttributes(event, matchType, "host", host)))
	if domainURN, domain := internetDomainURN(tenantID, host); domainURN != "" && domainURN != hostURN {
		addInternetDomainEntity(entities, tenantID, sourceID, domainURN, domain)
		addLink(links, projectedLink(tenantID, sourceID, hostURN, domainURN, relationBelongsTo, panopticonAnchorAttributes(event, matchType+"_domain", "domain", domain)))
	}
}

func panopticonAddAWSInstanceAnchor(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, instanceID string, matchType string) {
	instanceID = strings.ToLower(strings.TrimSpace(instanceID))
	instanceURN := projectionURN(tenantID, "aws_ec2_instance", instanceID)
	if instanceURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        instanceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ec2.instance",
		Label:      instanceID,
		Attributes: compactAttributes(map[string]string{
			"instance_id":       instanceID,
			"resource_id":       instanceID,
			"resource_provider": "aws",
			"resource_type":     "ec2_instance",
		}),
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, instanceURN, relation, panopticonAnchorAttributes(event, matchType, "instance_id", instanceID)))
}

func panopticonAddGitHubRepositoryAnchor(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, repository string, matchType string) {
	repository = normalizeGitHubRepository(repository)
	if repository == "" {
		return
	}
	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repoURN == "" {
		return
	}
	owner, _, _ := strings.Cut(repository, "/")
	addEntity(entities, &ports.ProjectedEntity{
		URN:        repoURN,
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.code.repository",
		Label:      repository,
		Attributes: compactAttributes(map[string]string{"owner_login": owner, "repository": repository}),
	})
	if orgURN := projectionURN(tenantID, "github_org", owner); orgURN != "" && owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   "github",
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner, "owner_login": owner},
		})
		addLink(links, projectedLink(tenantID, sourceID, repoURN, orgURN, relationBelongsTo, panopticonAnchorAttributes(event, matchType+"_owner", "owner_login", owner)))
	}
	addLink(links, projectedLink(tenantID, sourceID, fromURN, repoURN, relation, panopticonAnchorAttributes(event, matchType, "repository", repository)))
}

func panopticonAddCloudAccountAnchor(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, provider string, accountID string, matchType string) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return
	}
	accountURN := cloudAccountURN(tenantID, accountID)
	if accountURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accountURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "cloud.account",
		Label:      accountID,
		Attributes: compactAttributes(map[string]string{"account_id": accountID, "provider": provider}),
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, accountURN, relation, panopticonAnchorAttributes(event, matchType, "account_id", accountID)))
}

func panopticonAddKubernetesContextAnchors(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, samples []panopticonContextSample, matchPrefix string) {
	attrs := panopticonKubernetesAttributes(samples)
	if len(attrs) == 0 {
		return
	}
	clusterURN := kubernetesClusterURN(tenantID, attrs)
	namespaceURN := kubernetesNamespaceURN(tenantID, attrs)
	workloadURN := kubernetesWorkloadURN(tenantID, attrs)
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, attrs)
	addKubernetesCluster(entities, tenantID, sourceID, attrs, clusterURN)
	addKubernetesNamespace(entities, tenantID, sourceID, attrs, namespaceURN)
	if workloadURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        workloadURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.workload",
			Label:      firstNonEmpty(attrs["workload_name"], attrs["name"]),
			Attributes: compactAttributes(attrs),
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, workloadURN, relation, panopticonAnchorAttributes(event, matchPrefix+"_kubernetes_workload", "workload_name", attrs["workload_name"])))
		if namespaceURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, workloadURN, namespaceURN, relationBelongsTo, panopticonAnchorAttributes(event, matchPrefix+"_kubernetes_namespace", "namespace", attrs["namespace"])))
		}
		if serviceAccountURN != "" && strings.TrimSpace(attrs["service_account_name"]) != "" {
			addEntity(entities, &ports.ProjectedEntity{
				URN:        serviceAccountURN,
				TenantID:   tenantID,
				SourceID:   sourceID,
				EntityType: "kubernetes.service_account",
				Label:      attrs["service_account_name"],
				Attributes: compactAttributes(attrs),
			})
			addLink(links, projectedLink(tenantID, sourceID, workloadURN, serviceAccountURN, relationRunsAs, panopticonAnchorAttributes(event, matchPrefix+"_kubernetes_service_account", "service_account_name", attrs["service_account_name"])))
			addLink(links, projectedLink(tenantID, sourceID, serviceAccountURN, namespaceURN, relationBelongsTo, panopticonAnchorAttributes(event, matchPrefix+"_kubernetes_service_account_namespace", "namespace", attrs["namespace"])))
		}
	}
	addKubernetesClusterLinks(entities, links, tenantID, sourceID, event, attrs, namespaceURN, clusterURN)
}

func panopticonContextSamples(attrs map[string]string, payload map[string]any) []panopticonContextSample {
	samples := make([]panopticonContextSample, 0, len(attrs))
	for key, value := range attrs {
		value = strings.TrimSpace(value)
		if strings.TrimSpace(key) == "" || value == "" {
			continue
		}
		samples = append(samples, panopticonContextSample{key: strings.ToLower(strings.TrimSpace(key)), value: value})
	}
	panopticonCollectPayloadSamples(&samples, "", payload, 0)
	return samples
}

func panopticonCollectPayloadSamples(samples *[]panopticonContextSample, keyPath string, value any, depth int) {
	if len(*samples) >= 256 || depth > 5 || panopticonSkippedContextKey(keyPath) {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childKey := strings.ToLower(strings.Trim(strings.TrimSpace(keyPath+"."+key), "."))
			panopticonCollectPayloadSamples(samples, childKey, child, depth+1)
		}
	case []any:
		for _, child := range typed {
			panopticonCollectPayloadSamples(samples, keyPath, child, depth+1)
		}
	case []map[string]any:
		for _, child := range typed {
			panopticonCollectPayloadSamples(samples, keyPath, child, depth+1)
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed != "" && len(trimmed) <= 8192 {
			*samples = append(*samples, panopticonContextSample{key: strings.ToLower(strings.Trim(keyPath, ".")), value: trimmed})
		}
	}
}

func panopticonSkippedContextKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{
		"api_key",
		"apikey",
		"authorization",
		"bearer",
		"body",
		"bytes",
		"content",
		"cookie",
		"credential",
		"key",
		"password",
		"passwd",
		"private",
		"pwd",
		"raw",
		"secret",
		"signature",
		"token",
	} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func panopticonContextIPs(samples []panopticonContextSample) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sample := range samples {
		if !panopticonIPContextSample(sample) {
			continue
		}
		for _, candidate := range panopticonIPv4Pattern.FindAllString(sample.value, -1) {
			ip := internetIP(candidate)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

func panopticonContextHosts(samples []panopticonContextSample) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sample := range samples {
		if panopticonHostField(sample.key) {
			panopticonAppendHostCandidate(&out, seen, sample.value)
		}
		for _, rawURL := range panopticonURLPattern.FindAllString(sample.value, -1) {
			panopticonAppendHostCandidate(&out, seen, rawURL)
		}
	}
	return out
}

func panopticonAppendHostCandidate(out *[]string, seen map[string]struct{}, raw string) {
	host := internetHostIfLikely(raw)
	if host == "" || internetIP(host) != "" {
		return
	}
	if _, ok := seen[host]; ok {
		return
	}
	seen[host] = struct{}{}
	*out = append(*out, host)
}

func panopticonContextAWSInstances(samples []panopticonContextSample) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sample := range samples {
		for _, match := range panopticonAWSInstancePattern.FindAllString(sample.value, -1) {
			instanceID := strings.ToLower(match)
			if _, ok := seen[instanceID]; ok {
				continue
			}
			seen[instanceID] = struct{}{}
			out = append(out, instanceID)
		}
	}
	return out
}

func panopticonContextGitHubRepositories(samples []panopticonContextSample) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sample := range samples {
		for _, match := range panopticonGitHubURLPattern.FindAllStringSubmatch(sample.value, -1) {
			if len(match) > 1 {
				panopticonAppendGitHubRepository(&out, seen, match[1])
			}
		}
		if !panopticonGitHubContext(sample) {
			continue
		}
		bareValue := panopticonGitHubURLPattern.ReplaceAllString(sample.value, " ")
		for _, match := range panopticonGitHubRepositoryPattern.FindAllString(bareValue, -1) {
			panopticonAppendGitHubRepository(&out, seen, match)
		}
	}
	return out
}

func panopticonAppendGitHubRepository(out *[]string, seen map[string]struct{}, raw string) {
	repository := normalizeGitHubRepository(strings.Trim(raw, ".,;:()[]{}<>\"'"))
	if repository == "" {
		return
	}
	if _, ok := seen[repository]; ok {
		return
	}
	seen[repository] = struct{}{}
	*out = append(*out, repository)
}

func panopticonContextGCPProjects(samples []panopticonContextSample) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sample := range samples {
		if panopticonGCPProjectField(sample.key) {
			panopticonAppendGCPProject(&out, seen, sample.value)
		}
		for _, match := range panopticonGCPProjectFieldPattern.FindAllStringSubmatch(sample.value, -1) {
			if len(match) > 1 {
				panopticonAppendGCPProject(&out, seen, match[1])
			}
		}
	}
	return out
}

func panopticonAppendGCPProject(out *[]string, seen map[string]struct{}, raw string) {
	projectID := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), ".,;:()[]{}<>\"'")
	if projectID == "" || !strings.Contains(projectID, "-") {
		return
	}
	if _, ok := seen[projectID]; ok {
		return
	}
	seen[projectID] = struct{}{}
	*out = append(*out, projectID)
}

func panopticonKubernetesAttributes(samples []panopticonContextSample) map[string]string {
	attrs := map[string]string{}
	for _, sample := range samples {
		key := sample.key
		value := strings.TrimSpace(sample.value)
		switch {
		case strings.HasSuffix(key, "cluster_id") || strings.HasSuffix(key, "kubernetes_cluster_id"):
			attrs["cluster_id"] = firstNonEmpty(attrs["cluster_id"], value)
		case strings.HasSuffix(key, "cluster_name") || strings.HasSuffix(key, "kubernetes_cluster_name"):
			attrs["cluster_name"] = firstNonEmpty(attrs["cluster_name"], value)
		case strings.HasSuffix(key, "namespace") || strings.HasSuffix(key, "kubernetes_namespace"):
			attrs["namespace"] = firstNonEmpty(attrs["namespace"], value)
		case strings.HasSuffix(key, "workload_name") || strings.HasSuffix(key, "kubernetes_workload_name"):
			attrs["workload_name"] = firstNonEmpty(attrs["workload_name"], value)
		case strings.HasSuffix(key, "workload_kind") || strings.HasSuffix(key, "kubernetes_workload_kind"):
			attrs["workload_kind"] = firstNonEmpty(attrs["workload_kind"], value)
		case strings.HasSuffix(key, "service_account") || strings.HasSuffix(key, "service_account_name"):
			attrs["service_account_name"] = firstNonEmpty(attrs["service_account_name"], value)
		case strings.HasSuffix(key, "cloud_provider") || strings.HasSuffix(key, "provider"):
			attrs["cloud_provider"] = firstNonEmpty(attrs["cloud_provider"], value)
		case strings.HasSuffix(key, "cloud_account_id") || strings.HasSuffix(key, "account_id"):
			attrs["cloud_account_id"] = firstNonEmpty(attrs["cloud_account_id"], value)
		case strings.HasSuffix(key, "gcp_project_id") || strings.HasSuffix(key, "project_id"):
			attrs["gcp_project_id"] = firstNonEmpty(attrs["gcp_project_id"], value)
		}
		if strings.Contains(strings.ToLower(sample.value), "tetragon") || strings.Contains(key, "kubernetes") {
			for _, match := range panopticonKubernetesPairPattern.FindAllStringSubmatch(sample.value, -1) {
				if len(match) > 2 {
					attrs["namespace"] = firstNonEmpty(attrs["namespace"], match[1])
					attrs["workload_name"] = firstNonEmpty(attrs["workload_name"], match[2])
				}
			}
		}
	}
	if firstNonEmpty(attrs["namespace"], attrs["workload_name"], attrs["service_account_name"]) == "" {
		return nil
	}
	if firstNonEmpty(attrs["cluster_id"], attrs["cluster_name"]) == "" {
		attrs["cluster_id"] = "panopticon-inferred"
		attrs["cluster_inferred"] = "true"
	}
	if attrs["workload_name"] != "" && attrs["workload_kind"] == "" {
		attrs["workload_kind"] = "Deployment"
	}
	return attrs
}

func panopticonHostField(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"host", "hostname", "domain", "fqdn", "url", "uri", "website"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func panopticonGitHubContext(sample panopticonContextSample) bool {
	key := strings.ToLower(sample.key)
	value := strings.ToLower(sample.value)
	return strings.Contains(key, "github") || panopticonRepositoryField(key) || strings.Contains(value, "github")
}

func panopticonGCPProjectField(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "gcp_project") || strings.Contains(key, "project_id") || strings.Contains(key, "projectid")
}

func panopticonRepositoryField(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "repo" || key == "repository" {
		return true
	}
	if strings.HasPrefix(key, "repo_") || strings.HasPrefix(key, "repository_") || strings.HasPrefix(key, "repo.") || strings.HasPrefix(key, "repository.") {
		return true
	}
	for _, marker := range []string{"_repo", "_repository", ".repo", ".repository", "-repo", "-repository"} {
		if strings.HasSuffix(key, marker) || strings.Contains(key, marker+"_") || strings.Contains(key, marker+".") {
			return true
		}
	}
	return false
}

func panopticonIPContextSample(sample panopticonContextSample) bool {
	key := strings.ToLower(sample.key)
	for _, marker := range []string{"version", "build", "release", "semver"} {
		if strings.Contains(key, marker) {
			return false
		}
	}
	if key == "" || panopticonHostField(key) {
		return true
	}
	for _, marker := range []string{"ip", "address", "title", "description", "summary", "value", "ioc", "indicator", "observable"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func panopticonOwnerField(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"owner", "assignee", "assigned_to", "assigned", "user_email"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func panopticonAnchorAttributes(event *cerebrov1.EventEnvelope, matchType string, key string, value string) map[string]string {
	attrs := panopticonLinkAttributes(event, matchType)
	addProjectedAttribute(attrs, key, value)
	return attrs
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
