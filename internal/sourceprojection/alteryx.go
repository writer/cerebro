package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func alteryxUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "alteryx"})
}

func alteryxUserGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "alteryx"})
}

func alteryxWorkflowsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return alteryxGenericAssetProjections(event)
}

func alteryxCollectionsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return alteryxGenericAssetProjections(event)
}

func alteryxAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "alteryx"})
}

func alteryxGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	resourceID := firstNonEmpty(attrs["resource_id"], attrs["id"])
	resourceType := firstNonEmpty(attrs["resource_type"], "asset")
	resourceName := firstNonEmpty(attrs["resource_name"], attrs["name"], resourceID)
	resourceURN := firstNonEmpty(attrs["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: resourceName, Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "resource_name": resourceName, "owner_id": attrs["owner_id"]}})
		if evidenceID := strings.TrimSpace(attrs["evidence_id"]); evidenceID != "" {
			evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
			addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attrs["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attrs["evidence_cas_digest"])}})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		}
	}
	return identityProjectionResult(entities, links)
}
