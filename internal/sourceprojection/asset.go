package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func assetDataSensitivityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return assetClassificationProjections(event, false)
}

func assetCrownJewelProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return assetClassificationProjections(event, true)
}

func assetClassificationProjections(event *cerebrov1.EventEnvelope, crownJewelEvent bool) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	resourceURN := firstNonEmpty(attributes["resource_urn"])
	provider := firstNonEmpty(attributes["source_provider"], attributes["resource_provider"], "asset")
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["resource_name"])
	if resourceURN == "" {
		resourceURN = projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	}
	classification := firstNonEmpty(attributes["data_classification"], attributes["data_sensitivity"], attributes["sensitivity"], "unknown")
	classificationURN := projectionURN(tenantID, "data_classification", classification)
	crownJewel := crownJewelEvent || projectionBool(firstNonEmpty(attributes["crown_jewel"], attributes["tier0"], attributes["business_critical"]))
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
			Label:      firstNonEmpty(attributes["resource_name"], resourceID, resourceURN),
			Attributes: map[string]string{
				"asset_criticality":   firstNonEmpty(attributes["asset_criticality"], attributes["business_criticality"], attributes["tier"]),
				"contains_pii":        strings.TrimSpace(attributes["contains_pii"]),
				"contains_phi":        strings.TrimSpace(attributes["contains_phi"]),
				"contains_secrets":    strings.TrimSpace(attributes["contains_secrets"]),
				"crown_jewel":         boolString(crownJewel),
				"data_classification": classification,
				"environment":         strings.TrimSpace(attributes["environment"]),
				"internet_exposed":    strings.TrimSpace(attributes["internet_exposed"]),
				"public":              strings.TrimSpace(attributes["public"]),
				"resource_id":         resourceID,
				"resource_type":       resourceType,
			},
		})
	}
	if classificationURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: classificationURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "data.classification", Label: classification, Attributes: map[string]string{"classification": classification}})
	}
	if resourceURN != "" && classificationURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, classificationURN, relationHasClassification, map[string]string{"event_id": event.GetId()}))
	}
	if crownJewel && resourceURN != "" {
		tagURN := projectionURN(tenantID, "asset_tag", "crown_jewel")
		addEntity(entities, &ports.ProjectedEntity{URN: tagURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "asset.tag", Label: "crown_jewel", Attributes: map[string]string{"tag": "crown_jewel"}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, tagURN, relationTaggedAs, map[string]string{"event_id": event.GetId()}))
	}
	if owner := firstNonEmpty(attributes["owner"], attributes["team"]); owner != "" && resourceURN != "" {
		ownerURN := projectionURN(tenantID, "owner", owner)
		addEntity(entities, &ports.ProjectedEntity{URN: ownerURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "owner", Label: owner, Attributes: map[string]string{"owner": owner}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
