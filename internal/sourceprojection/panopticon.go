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
	panopticonAddContextAnchors(entities, links, tenantID, event.GetSourceId(), event, alertURN, relationAssociatedWith, attrs, payload, "panopticon_alert_context")
	panopticonAddIOCContextAnchors(entities, links, tenantID, event.GetSourceId(), event, attrs, payload)
	panopticonAddAssetContextAnchors(entities, links, tenantID, event.GetSourceId(), event, attrs, payload)
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
		attributes := compactAttributes(map[string]string{
			"evidence_id":      panopticonString(evidence, "evidence_id", "id"),
			"evidence_cas":     pointer,
			"evidence_cas_uri": pointer,
			"sha256":           panopticonEvidenceDigest(evidence),
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
		assetAttrs := map[string]string{
			"asset_id":   firstAttribute(attrs, "asset_id"),
			"asset_type": firstAttribute(attrs, "asset_type"),
			"name":       firstAttribute(attrs, "asset_name"),
			"hostname":   firstAttribute(attrs, "hostname"),
		}
		assetURN := panopticonAddAssetEntity(entities, tenantID, sourceID, event.GetId(), assetAttrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, assetURN, relationRepresents, assetAttrs, nil, "panopticon_asset_context")
	}
	for _, asset := range panopticonObjects(payload, "assets", "affected_assets", "hosts", "endpoints") {
		assetAttrs := panopticonAttributesFromObject(asset, "asset_id", "id", "asset_type", "type", "hostname", "name", "urn")
		assetURN := panopticonAddAssetEntity(entities, tenantID, sourceID, event.GetId(), assetAttrs)
		panopticonAddContextAnchors(entities, links, tenantID, sourceID, event, assetURN, relationRepresents, assetAttrs, asset, "panopticon_asset_context")
	}
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
		panopticonAddGitHubRepositoryAnchor(entities, links, tenantID, sourceID, event, fromURN, relation, repository, matchPrefix+"_github_repo")
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
	repoURN := projectionURN(tenantID, "github_repo", repository)
	if repoURN == "" {
		return
	}
	owner, _, _ := strings.Cut(repository, "/")
	addEntity(entities, &ports.ProjectedEntity{
		URN:        repoURN,
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.repo",
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
