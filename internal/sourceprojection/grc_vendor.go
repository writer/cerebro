package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	vendorID := firstAttribute(ctx.attrs, "vendor_id", "external_id")
	if vendorID == "" {
		return nil, nil, nil
	}
	vendorURN := ctx.resourceURN("vendor", vendorID)
	ctx.addResourceEntity(
		vendorURN,
		"vendor",
		firstAttribute(ctx.attrs, "name", "vendor_id"),
		map[string]string{"vendor_id": vendorID, "source_system": ctx.provider},
	)
	addVendorAliasLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, vendorURN, firstAttribute(ctx.attrs, "name"), "grc_vendor_name_alias", "0.90")
	addInternetHostLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, vendorURN, relationHasIdentifier, firstAttribute(ctx.attrs, "website_url", "website", "url", "domain"), "grc_vendor_website_host", "0.95")
	for _, ownerID := range []string{firstAttribute(ctx.attrs, "security_owner_user_id"), firstAttribute(ctx.attrs, "business_owner_user_id")} {
		if ownerID == "" {
			continue
		}
		ownerURN := grcUserURN(ctx.tenantID, ctx.provider, ownerID)
		addEntity(ctx.entities, grcUserEntity(ctx.tenantID, ctx.sourceID, ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": ctx.provider}))
		ctx.addEventLink(vendorURN, ownerURN, relationOwnedBy)
	}
	addSecurityContactEmailLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, vendorURN, firstAttribute(ctx.attrs, "account_manager_email", "security_contact_email", "contact_email"), "account_manager")
	entities, links := ctx.done()
	return entities, links, nil
}

func grcDiscoveredVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	discoveryID := firstAttribute(ctx.attrs, "discovered_vendor_id", "vendor_id", "external_id")
	if discoveryID == "" {
		return nil, nil, nil
	}
	discoveryURN := ctx.resourceURN("vendor_discovery", discoveryID)
	ctx.addResourceEntity(
		discoveryURN,
		"vendor.discovery",
		firstAttribute(ctx.attrs, "name", "normalized_name", "discovered_vendor_id"),
		map[string]string{
			"discovered_vendor_id": discoveryID,
			"source_system":        ctx.provider,
			"status":               discoveredVendorStatus(ctx.attrs),
		},
	)
	addVendorAliasLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, discoveryURN, firstAttribute(ctx.attrs, "name"), "grc_discovered_vendor_name", "0.90")
	addVendorAliasLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, discoveryURN, firstAttribute(ctx.attrs, "normalized_name"), "grc_discovered_vendor_normalized_name", "0.95")
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, discoveryURN, "vendor_category", firstAttribute(ctx.attrs, "category"))
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "ignored_by_user_id"), discoveryURN, "ignored")
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "rejected_by_user_id"), discoveryURN, "rejected")
	entities, links := ctx.done()
	return entities, links, nil
}

func grcVendorRiskAttributeProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	attributeID := firstAttribute(ctx.attrs, "vendor_risk_attribute_id", "external_id")
	if attributeID == "" {
		return nil, nil, nil
	}
	attributeURN := ctx.resourceURN("vendor_risk_attribute", attributeID)
	ctx.addResourceEntity(
		attributeURN,
		"vendor.risk_attribute",
		firstAttribute(ctx.attrs, "name", "vendor_risk_attribute_id"),
		map[string]string{
			"enabled":                  firstAttribute(ctx.attrs, "enabled"),
			"risk_level":               firstAttribute(ctx.attrs, "risk_level"),
			"source_system":            ctx.provider,
			"vendor_risk_attribute_id": attributeID,
		},
	)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, attributeURN, "vendor_category", firstAttribute(ctx.attrs, "vendor_categories"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, attributeURN, "vendor_risk_level", firstAttribute(ctx.attrs, "risk_level"))
	entities, links := ctx.done()
	return entities, links, nil
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
