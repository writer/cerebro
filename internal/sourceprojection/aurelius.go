package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func aureliusImageScanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := aureliusProjectionAttributes(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	imageURN := aureliusImageURN(tenantID, attrs)
	if imageURN != "" {
		addEntity(entities, aureliusImageEntity(tenantID, event.GetSourceId(), imageURN, attrs))
	}

	scanID := firstAttribute(attrs, "scan_id", "image_digest")
	scanURN := projectionURN(tenantID, "aurelius_image_scan", scanID)
	if scanURN != "" {
		scanAttrs := map[string]string{}
		addAureliusAttribute(scanAttrs, "completed_at", firstAttribute(attrs, "completed_at"))
		addAureliusAttribute(scanAttrs, "image_digest", firstAttribute(attrs, "image_digest"))
		addAureliusAttribute(scanAttrs, "registry", firstAttribute(attrs, "registry"))
		addAureliusAttribute(scanAttrs, "scanner", firstAttribute(attrs, "scanner"))
		addAureliusAttribute(scanAttrs, "status", firstAttribute(attrs, "status"))
		addAureliusAttribute(scanAttrs, "verdict", firstAttribute(attrs, "verdict"))
		addEntity(entities, &ports.ProjectedEntity{
			URN:        scanURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.image_scan",
			Label:      firstAttribute(attrs, "scan_id", "image_digest"),
			Attributes: scanAttrs,
		})
		if imageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), scanURN, imageURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, scanURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusVerdictProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := aureliusProjectionAttributes(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	imageURN := aureliusImageURN(tenantID, attrs)
	if imageURN != "" {
		addEntity(entities, aureliusImageEntity(tenantID, event.GetSourceId(), imageURN, attrs))
	}

	verdictKey := firstAttribute(attrs, "image_digest")
	verdictURN := projectionURN(tenantID, "aurelius_verdict", verdictKey)
	if verdictURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        verdictURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.verdict",
			Label:      firstAttribute(attrs, "verdict", "image_digest"),
			Attributes: map[string]string{
				"blocking_findings": firstAttribute(attrs, "blocking_findings"),
				"excepted_findings": firstAttribute(attrs, "excepted_findings"),
				"image_digest":      firstAttribute(attrs, "image_digest"),
				"verdict":           firstAttribute(attrs, "verdict"),
			},
		})
		if imageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), verdictURN, imageURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, verdictURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := aureliusProjectionAttributes(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	imageURN := aureliusImageURN(tenantID, attrs)
	if imageURN != "" {
		addEntity(entities, aureliusImageEntity(tenantID, event.GetSourceId(), imageURN, attrs))
	}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)
	if vulnerabilityURN != "" && imageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
	}
	packageURN := vulnerabilityPackageURN(tenantID, attrs, "aurelius")
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attrs, "aurelius")
	if packageURN != "" {
		addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, attrs, "aurelius")
		if imageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, packageURN, relationContains, map[string]string{"event_id": event.GetId()}))
		}
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attrs, "aurelius")))
	}
	if canonicalPackageURN != "" && vulnerabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusCatalogPromotionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := aureliusProjectionAttributes(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	imageURN := aureliusImageURN(tenantID, attrs)
	if imageURN != "" {
		addEntity(entities, aureliusImageEntity(tenantID, event.GetSourceId(), imageURN, attrs))
	}

	track := firstAttribute(attrs, "track")
	trackURN := projectionURN(tenantID, "aurelius_catalog_track", track)
	if trackURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        trackURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.catalog_track",
			Label:      track,
			Attributes: map[string]string{
				"track": track,
			},
		})
	}

	promotionKey := track + "|" + firstAttribute(attrs, "image_digest")
	promotionURN := projectionURN(tenantID, "aurelius_catalog_promotion", promotionKey)
	if promotionURN != "" {
		promotionAttrs := map[string]string{}
		addAureliusAttribute(promotionAttrs, "image_digest", firstAttribute(attrs, "image_digest"))
		addAureliusAttribute(promotionAttrs, "promoted_by", firstAttribute(attrs, "promoted_by"))
		addAureliusAttribute(promotionAttrs, "promoted_at", firstAttribute(attrs, "promoted_at"))
		addAureliusAttribute(promotionAttrs, "track", track)
		addAureliusAttribute(promotionAttrs, "verdict", firstAttribute(attrs, "verdict"))
		addEntity(entities, &ports.ProjectedEntity{
			URN:        promotionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.catalog_promotion",
			Label:      strings.TrimSpace(track + ":" + firstAttribute(attrs, "image_digest")),
			Attributes: promotionAttrs,
		})
		if imageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), promotionURN, imageURN, relationRepresents, map[string]string{"event_id": event.GetId()}))
		}
		if trackURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), promotionURN, trackURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusPolicyExceptionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := aureliusProjectionAttributes(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)

	exceptionKey := firstAttribute(attrs, "exception_id", "cve_id")
	exceptionURN := projectionURN(tenantID, "aurelius_policy_exception", exceptionKey)
	if exceptionURN != "" {
		exceptionAttrs := map[string]string{}
		addAureliusAttribute(exceptionAttrs, "approver", firstAttribute(attrs, "approver"))
		addAureliusAttribute(exceptionAttrs, "cve_id", firstAttribute(attrs, "cve_id"))
		addAureliusAttribute(exceptionAttrs, "expires_at", firstAttribute(attrs, "expires_at"))
		addAureliusAttribute(exceptionAttrs, "reason", firstAttribute(attrs, "reason"))
		addAureliusAttribute(exceptionAttrs, "scope", firstAttribute(attrs, "scope"))
		addAureliusAttribute(exceptionAttrs, "status", firstAttribute(attrs, "status"))
		addEntity(entities, &ports.ProjectedEntity{
			URN:        exceptionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.policy_exception",
			Label:      firstAttribute(attrs, "cve_id", "exception_id"),
			Attributes: exceptionAttrs,
		})
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), exceptionURN, vulnerabilityURN, relationRepresents, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusImageURN(tenantID string, attrs map[string]string) string {
	id := firstAttribute(attrs, "image_uri", "image_digest", "image")
	if id == "" {
		return ""
	}
	return projectionURN(tenantID, "gcp_artifact_registry_image", id)
}

func aureliusImageEntity(tenantID, sourceID, urn string, attrs map[string]string) *ports.ProjectedEntity {
	imageAttrs := map[string]string{}
	addAureliusAttribute(imageAttrs, "digest", firstAttribute(attrs, "image_digest"))
	addAureliusAttribute(imageAttrs, "image_uri", firstAttribute(attrs, "image_uri"))
	addAureliusAttribute(imageAttrs, "registry", firstAttribute(attrs, "registry"))
	addAureliusAttribute(imageAttrs, "repository", firstAttribute(attrs, "repository"))
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "gcp.artifact_registry_image",
		Label:      firstAttribute(attrs, "image_uri", "image", "image_digest"),
		Attributes: imageAttrs,
	}
}

func aureliusProjectionAttributes(event *cerebrov1.EventEnvelope) map[string]string {
	attrs := make(map[string]string, len(event.GetAttributes()))
	for key, value := range event.GetAttributes() {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		attrs[key] = value
	}
	payload := payloadMap(event)
	for _, key := range []string{
		"approver",
		"blocking_findings",
		"completed_at",
		"cve_id",
		"excepted_findings",
		"exception_id",
		"expires_at",
		"fixed_version",
		"image",
		"image_digest",
		"image_uri",
		"installed_version",
		"package",
		"promoted_at",
		"promoted_by",
		"reason",
		"registry",
		"repository",
		"scanner",
		"scope",
		"scan_id",
		"severity",
		"status",
		"track",
		"verdict",
	} {
		if firstAttribute(attrs, key) != "" {
			continue
		}
		if value := stringValue(payload, key); value != "" {
			attrs[key] = value
		}
	}
	return attrs
}

func addAureliusAttribute(attrs map[string]string, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		attrs[key] = value
	}
}
