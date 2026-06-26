package sourceprojection

import (
	"encoding/json"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcVulnerableAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	targetID := firstAttribute(attrs, "target_id", "asset_id", "resource_id", "endpoint_id", "external_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if targetURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, grcTargetEntity(tenantID, event.GetSourceId(), targetURN, targetID, attrs, provider))
	for _, host := range grcTargetHosts(attrs) {
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, targetURN, relationRepresents, host, "grc_vulnerable_asset_host", "0.95")
	}
	for _, ip := range grcTargetIPs(attrs) {
		addInternetIPLink(entities, links, tenantID, event.GetSourceId(), event, targetURN, ip, "grc_vulnerable_asset_ip", "0.95")
	}
	addGRCPlatformAssetLinks(entities, links, tenantID, event.GetSourceId(), event, targetURN, attrs)

	integrationID := firstAttribute(attrs, "integration_id")
	if integrationURN := grcIntegrationURN(tenantID, provider, integrationID); integrationURN != "" {
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, event.GetSourceId(), integrationURN, integrationID, provider))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
	}

	referenceAttrsList := grcVulnerableAssetReferenceAttrs(attrs)
	if len(referenceAttrsList) > 0 {
		for _, referenceAttrs := range referenceAttrsList {
			vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), referenceAttrs)
			if vulnerabilityURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, referenceAttrs)))
			}
			for _, packageAttrs := range grcVulnerableAssetPackageAttrs(referenceAttrs) {
				packageURN := vulnerabilityPackageURN(tenantID, packageAttrs, "grc")
				canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), packageAttrs, "grc")
				if packageURN != "" {
					addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, packageAttrs, "grc")
					addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, packageAttrs)))
					if vulnerabilityURN != "" {
						addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, packageAttrs)))
					}
				}
				if packageURN != "" && canonicalPackageURN != "" {
					addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, packageAttrs, "grc")))
				}
				if canonicalPackageURN != "" && vulnerabilityURN != "" {
					addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, packageAttrs)))
				}
			}
		}
		projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
		return projectedEntities, projectedLinks, nil
	}

	for _, vulnerabilityAttrs := range grcVulnerableAssetVulnerabilityAttrs(attrs) {
		vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), vulnerabilityAttrs)
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, vulnerabilityAttrs)))
		}
	}
	for _, packageAttrs := range grcVulnerableAssetPackageAttrs(attrs) {
		packageURN := vulnerabilityPackageURN(tenantID, packageAttrs, "grc")
		canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), packageAttrs, "grc")
		if packageURN != "" {
			addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, packageAttrs, "grc")
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, packageAttrs)))
		}
		if packageURN != "" && canonicalPackageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, packageAttrs, "grc")))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerableAssetReferenceAttrs(attrs map[string]string) []map[string]string {
	rawReferences := strings.TrimSpace(attrs["vulnerability_package_refs"])
	if rawReferences == "" {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	var references []struct {
		VulnerabilityID   string `json:"vulnerability_id"`
		VulnerabilityName string `json:"vulnerability_name"`
		PackageIdentifier string `json:"package_identifier"`
	}
	if err := json.Unmarshal([]byte(rawReferences), &references); err != nil {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	packageIdentifiers := grcAttributeSequence(attrs["package_identifiers"])
	result := make([]map[string]string, 0, len(references))
	for i, reference := range references {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := firstNonEmptyString(reference.VulnerabilityID, stringAt(vulnerabilityIDs, i)); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := firstNonEmptyString(reference.VulnerabilityName, stringAt(vulnerabilityNames, i)); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := firstNonEmptyString(reference.PackageIdentifier, stringAt(packageIdentifiers, i)); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	for i := len(references); i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := stringAt(packageIdentifiers, i); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	if len(result) == 0 {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	return result
}

func grcVulnerableAssetFlatReferenceAttrs(attrs map[string]string) []map[string]string {
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	packageIdentifiers := grcAttributeSequence(attrs["package_identifiers"])
	if (len(vulnerabilityIDs) == 0 && len(vulnerabilityNames) == 0) || len(packageIdentifiers) == 0 {
		return nil
	}
	total := maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers))
	result := make([]map[string]string, 0, total)
	for i := 0; i < total; i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := stringAt(packageIdentifiers, i); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	return result
}

func grcVulnerableAssetCleanReferenceAttrs(attrs map[string]string) map[string]string {
	referenceAttrs := grcProjectionAttrsWith(attrs)
	for _, key := range []string{
		"cve_id",
		"ghsa_id",
		"identifier",
		"name",
		"package",
		"package_identifiers",
		"package_purl",
		"title",
		"vulnerability_id",
		"vulnerability_ids",
		"vulnerability_names",
		"vulnerability_package_refs",
	} {
		delete(referenceAttrs, key)
	}
	return referenceAttrs
}

func grcVulnerableAssetVulnerabilityAttrs(attrs map[string]string) []map[string]string {
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	if len(vulnerabilityIDs) == 0 && len(vulnerabilityNames) == 0 && canonicalVulnerabilityIdentifier(attrs) != "" {
		return []map[string]string{attrs}
	}
	total := maxInt(len(vulnerabilityIDs), len(vulnerabilityNames))
	result := make([]map[string]string, 0, total)
	for i := 0; i < total; i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if canonicalVulnerabilityIdentifier(referenceAttrs) != "" {
			result = append(result, referenceAttrs)
		}
	}
	return result
}

func grcVulnerableAssetPackageAttrs(attrs map[string]string) []map[string]string {
	packages := grcAttributeList(strings.Join([]string{attrs["package_identifiers"], attrs["package"], attrs["package_purl"]}, ","))
	if len(packages) == 0 && vulnerablePackageName(attrs) != "" {
		return []map[string]string{attrs}
	}
	result := make([]map[string]string, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, grcProjectionAttrsWith(attrs, "package", pkg, "package_purl", pkg))
	}
	return result
}
