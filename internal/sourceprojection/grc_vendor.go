package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	vendorID := firstAttribute(attrs, "vendor_id", "external_id")
	if vendorID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vendorURN := projectionURN(tenantID, "vendor", provider, vendorID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vendorURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor",
		Label:      firstAttribute(attrs, "name", "vendor_id"),
		Attributes: grcAttributes(attrs, map[string]string{"vendor_id": vendorID, "source_system": provider}),
	})
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, firstAttribute(attrs, "name"), "grc_vendor_name_alias", "0.90")
	addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, relationHasIdentifier, firstAttribute(attrs, "website_url", "website", "url", "domain"), "grc_vendor_website_host", "0.95")
	for _, ownerID := range []string{firstAttribute(attrs, "security_owner_user_id"), firstAttribute(attrs, "business_owner_user_id")} {
		if ownerID == "" {
			continue
		}
		ownerURN := grcUserURN(tenantID, provider, ownerID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), vendorURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	}
	addSecurityContactEmailLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, firstAttribute(attrs, "account_manager_email", "security_contact_email", "contact_email"), "account_manager")
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcDiscoveredVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	discoveryID := firstAttribute(attrs, "discovered_vendor_id", "vendor_id", "external_id")
	if discoveryID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	discoveryURN := projectionURN(tenantID, "vendor_discovery", provider, discoveryID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        discoveryURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor.discovery",
		Label:      firstAttribute(attrs, "name", "normalized_name", "discovered_vendor_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"discovered_vendor_id": discoveryID,
			"source_system":        provider,
			"status":               discoveredVendorStatus(attrs),
		}),
	})
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, firstAttribute(attrs, "name"), "grc_discovered_vendor_name", "0.90")
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, firstAttribute(attrs, "normalized_name"), "grc_discovered_vendor_normalized_name", "0.95")
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, "vendor_category", firstAttribute(attrs, "category"))
	addGRCUserActionLink(entities, links, tenantID, event.GetSourceId(), event, provider, firstAttribute(attrs, "ignored_by_user_id"), discoveryURN, "ignored")
	addGRCUserActionLink(entities, links, tenantID, event.GetSourceId(), event, provider, firstAttribute(attrs, "rejected_by_user_id"), discoveryURN, "rejected")
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVendorRiskAttributeProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	attributeID := firstAttribute(attrs, "vendor_risk_attribute_id", "external_id")
	if attributeID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	attributeURN := projectionURN(tenantID, "vendor_risk_attribute", provider, attributeID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        attributeURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor.risk_attribute",
		Label:      firstAttribute(attrs, "name", "vendor_risk_attribute_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"enabled":                  firstAttribute(attrs, "enabled"),
			"risk_level":               firstAttribute(attrs, "risk_level"),
			"source_system":            provider,
			"vendor_risk_attribute_id": attributeID,
		}),
	})
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attributeURN, "vendor_category", firstAttribute(attrs, "vendor_categories"))
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attributeURN, "vendor_risk_level", firstAttribute(attrs, "risk_level"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func discoveredVendorStatus(attrs map[string]string) string {
	switch {
	case firstAttribute(attrs, "rejected_at", "rejected_reason", "rejected_by_user_id") != "":
		return "rejected"
	case firstAttribute(attrs, "ignored_at", "ignored_reason", "ignored_by_user_id") != "":
		return "ignored"
	default:
		return "discovered"
	}
}
