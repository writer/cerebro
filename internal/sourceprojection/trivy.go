package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func trivyImageURN(tenantID string, imageDigest string) string {
	return projectionURN(tenantID, "trivy_image", strings.TrimSpace(imageDigest))
}

func trivyPackageURN(tenantID string, imageDigest string, pkg string) string {
	return projectionURN(tenantID, "trivy_package", strings.TrimSpace(imageDigest), strings.TrimSpace(pkg))
}

func trivyVulnerabilityURN(tenantID string, imageDigest string, vulnerabilityID string, pkg string) string {
	return projectionURN(tenantID, "trivy_vulnerability", strings.TrimSpace(imageDigest), strings.TrimSpace(vulnerabilityID), strings.TrimSpace(pkg))
}

func trivyEntity(event *cerebrov1.EventEnvelope, urn string, entityType string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   event.GetTenantId(),
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: trivyAttributes(attrs),
	}
}

func trivyAttributes(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		addProjectedAttribute(out, key, value)
	}
	return out
}

func trivyImageScanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	imageDigest := strings.TrimSpace(attrs["image_digest"])
	if imageDigest == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, trivyEntity(event, trivyImageURN(tenantID, imageDigest), "trivy.image", firstNonEmpty(attrs["image_uri"], imageDigest), map[string]string{
		"image_digest":  imageDigest,
		"image_uri":     attrs["image_uri"],
		"artifact_name": attrs["artifact_name"],
		"artifact_type": attrs["artifact_type"],
		"scanner":       firstNonEmpty(attrs["scanner"], "trivy"),
	}))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func trivyImagePackageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	imageDigest := strings.TrimSpace(attrs["image_digest"])
	pkg := strings.TrimSpace(attrs["package"])
	if imageDigest == "" || pkg == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	packageURN := trivyPackageURN(tenantID, imageDigest, pkg)
	addEntity(entities, trivyEntity(event, packageURN, "trivy.package", pkg, map[string]string{
		"image_digest":      imageDigest,
		"package":           pkg,
		"installed_version": attrs["installed_version"],
		"ecosystem":         attrs["ecosystem"],
		"purl":              attrs["purl"],
		"normalized_id":     attrs["normalized_id"],
	}))
	imageURN := trivyImageURN(tenantID, imageDigest)
	addEntity(entities, trivyEntity(event, imageURN, "trivy.image", attrs["image_uri"], map[string]string{"image_digest": imageDigest}))
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "trivy_image_package",
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, packageURN, relationContains, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, imageURN, relationBelongsTo, linkAttrs))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func trivyImageVulnerabilityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	imageDigest := strings.TrimSpace(attrs["image_digest"])
	vulnerabilityID := strings.TrimSpace(attrs["vulnerability_id"])
	pkg := strings.TrimSpace(attrs["package"])
	if imageDigest == "" || vulnerabilityID == "" || pkg == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vulnerabilityURN := trivyVulnerabilityURN(tenantID, imageDigest, vulnerabilityID, pkg)
	addEntity(entities, trivyEntity(event, vulnerabilityURN, "trivy.vulnerability", vulnerabilityID, map[string]string{
		"image_digest":      imageDigest,
		"vulnerability_id":  vulnerabilityID,
		"package":           pkg,
		"installed_version": attrs["installed_version"],
		"fixed_version":     attrs["fixed_version"],
		"fix_available":     attrs["fix_available"],
		"severity":          attrs["severity"],
		"status":            attrs["status"],
		"primary_url":       attrs["primary_url"],
	}))
	packageURN := trivyPackageURN(tenantID, imageDigest, pkg)
	addEntity(entities, trivyEntity(event, packageURN, "trivy.package", pkg, map[string]string{"image_digest": imageDigest, "package": pkg}))
	imageURN := trivyImageURN(tenantID, imageDigest)
	addEntity(entities, trivyEntity(event, imageURN, "trivy.image", attrs["image_uri"], map[string]string{"image_digest": imageDigest}))

	if trivyVulnerabilityResolved(attrs["status"]) {
		// A resolved/suppressed vulnerability is not a current affecting link;
		// supersession reconciliation in ProjectRetractions removes any stale
		// affected_by edges so the graph reflects current state.
		projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
		return projectedEntities, projectedLinks, nil
	}

	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "trivy_image_vulnerability",
		"severity":   strings.TrimSpace(attrs["severity"]),
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, vulnerabilityURN, relationAffectedBy, linkAttrs))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func trivyFixProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	imageDigest := strings.TrimSpace(attrs["image_digest"])
	vulnerabilityID := strings.TrimSpace(attrs["vulnerability_id"])
	pkg := strings.TrimSpace(attrs["package"])
	fixedVersion := strings.TrimSpace(attrs["fixed_version"])
	if imageDigest == "" || vulnerabilityID == "" || pkg == "" || fixedVersion == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	fixURN := projectionURN(tenantID, "trivy_fix", imageDigest, vulnerabilityID, pkg, fixedVersion)
	addEntity(entities, trivyEntity(event, fixURN, "trivy.fix", vulnerabilityID+" -> "+fixedVersion, map[string]string{
		"image_digest":     imageDigest,
		"vulnerability_id": vulnerabilityID,
		"package":          pkg,
		"fixed_version":    fixedVersion,
	}))
	vulnerabilityURN := trivyVulnerabilityURN(tenantID, imageDigest, vulnerabilityID, pkg)
	addEntity(entities, trivyEntity(event, vulnerabilityURN, "trivy.vulnerability", vulnerabilityID, map[string]string{
		"image_digest":     imageDigest,
		"vulnerability_id": vulnerabilityID,
		"package":          pkg,
	}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fixURN, vulnerabilityURN, relationResolvesTo, map[string]string{
		"event_id":      event.GetId(),
		"at":            eventObservedAt(event),
		"match_type":    "trivy_fix_vulnerability",
		"fixed_version": fixedVersion,
	}))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// trivyVulnerabilityRetractions removes obsolete affected_by links when a later
// scan reports the same vulnerability identity as resolved or VEX-suppressed, so
// fixed records no longer appear as active affecting edges on the image/package.
func trivyVulnerabilityRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	if event.GetKind() != "trivy.image_vulnerability" {
		return nil, nil
	}
	attrs := event.GetAttributes()
	if !trivyVulnerabilityResolved(attrs["status"]) {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	imageDigest := strings.TrimSpace(attrs["image_digest"])
	vulnerabilityID := strings.TrimSpace(attrs["vulnerability_id"])
	pkg := strings.TrimSpace(attrs["package"])
	if imageDigest == "" || vulnerabilityID == "" || pkg == "" {
		return nil, nil
	}
	vulnerabilityURN := trivyVulnerabilityURN(tenantID, imageDigest, vulnerabilityID, pkg)
	packageURN := trivyPackageURN(tenantID, imageDigest, pkg)
	imageURN := trivyImageURN(tenantID, imageDigest)
	links := map[string]*ports.ProjectedLink{}
	retractionAttrs := map[string]string{
		"event_id":   event.GetId(),
		"retraction": "trivy_vulnerability_resolved",
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, retractionAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), imageURN, vulnerabilityURN, relationAffectedBy, retractionAttrs))
	_, projectedLinks := entitiesAndLinks(nil, links)
	return projectedLinks, nil
}

// trivyVulnerabilityResolved reports whether a Trivy vulnerability status marks
// the finding as no longer actively affecting the image (VEX not_affected,
// resolved, or fixed-and-cleared states).
func trivyVulnerabilityResolved(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "not_affected", "notaffected", "resolved", "fixed_applied":
		return true
	default:
		return false
	}
}
