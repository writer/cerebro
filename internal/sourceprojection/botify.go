package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func botifyFilterProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyExportProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyOutOfConfigProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifySitemapOnlyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyReportProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyAnalysesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyUrlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyOrphanUrlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyDatamodelProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyDomainProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyPercentileProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return botifyGenericAssetProjections(event)
}

func botifyGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: firstNonEmpty(attributes["resource_name"], resourceID), Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
