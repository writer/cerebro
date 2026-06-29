package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func billbeeWebhookProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeCloudstorageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeCustomFieldProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeCustomerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeCustomerAddressesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeLayoutProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeOrderProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeProductProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeShipmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeStockProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeAddressesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeImageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return billbeeGenericAssetProjections(event)
}

func billbeeGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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
