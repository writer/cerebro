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
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	imageURN := aureliusImageURN(tenantID, attrs)
	if imageURN != "" {
		addEntity(entities, aureliusImageEntity(tenantID, event.GetSourceId(), imageURN, attrs))
	}

	scanID := firstAttribute(attrs, "scan_id", "image_digest")
	scanURN := projectionURN(tenantID, "aurelius_image_scan", scanID)
	if scanURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        scanURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.image_scan",
			Label:      firstAttribute(attrs, "scan_id", "image_digest"),
			Attributes: map[string]string{
				"completed_at": firstAttribute(attrs, "completed_at"),
				"image_digest": firstAttribute(attrs, "image_digest"),
				"registry":     firstAttribute(attrs, "registry"),
				"scanner":      firstAttribute(attrs, "scanner"),
				"status":       firstAttribute(attrs, "status"),
				"verdict":      firstAttribute(attrs, "verdict"),
			},
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
	attrs := event.GetAttributes()
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
	attrs := event.GetAttributes()
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

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func aureliusCatalogPromotionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
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
		addEntity(entities, &ports.ProjectedEntity{
			URN:        promotionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.catalog_promotion",
			Label:      strings.TrimSpace(track + ":" + firstAttribute(attrs, "image_digest")),
			Attributes: map[string]string{
				"image_digest": firstAttribute(attrs, "image_digest"),
				"promoted_by":  firstAttribute(attrs, "promoted_by"),
				"promoted_at":  firstAttribute(attrs, "promoted_at"),
				"track":        track,
				"verdict":      firstAttribute(attrs, "verdict"),
			},
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
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)

	exceptionKey := firstAttribute(attrs, "cve_id", "exception_id")
	exceptionURN := projectionURN(tenantID, "aurelius_policy_exception", exceptionKey)
	if exceptionURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        exceptionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aurelius.policy_exception",
			Label:      firstAttribute(attrs, "cve_id", "exception_id"),
			Attributes: map[string]string{
				"approver":   firstAttribute(attrs, "approver"),
				"cve_id":     firstAttribute(attrs, "cve_id"),
				"expires_at": firstAttribute(attrs, "expires_at"),
				"reason":     firstAttribute(attrs, "reason"),
				"scope":      firstAttribute(attrs, "scope"),
				"status":     firstAttribute(attrs, "status"),
			},
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
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "gcp.artifact_registry_image",
		Label:      firstAttribute(attrs, "image_uri", "image", "image_digest"),
		Attributes: map[string]string{
			"digest":     firstAttribute(attrs, "image_digest"),
			"image_uri":  firstAttribute(attrs, "image_uri"),
			"registry":   firstAttribute(attrs, "registry"),
			"repository": firstAttribute(attrs, "repository"),
		},
	}
}
