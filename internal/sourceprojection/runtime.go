package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func runtimeEvidenceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	evidenceID := firstNonEmpty(attributes["evidence_id"], event.GetId())
	evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
	resourceURN := firstNonEmpty(attributes["resource_urn"], attributes["workload_urn"])
	if resourceURN == "" {
		resourceURN = projectionURN(tenantID, "runtime_"+normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource")), firstNonEmpty(attributes["resource_id"], attributes["resource_name"], evidenceID))
	}
	if evidenceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      firstNonEmpty(attributes["evidence_type"], attributes["detector_id"], evidenceID),
			Attributes: map[string]string{
				"confidence":    strings.TrimSpace(attributes["confidence"]),
				"detector_id":   strings.TrimSpace(attributes["detector_id"]),
				"evidence_id":   evidenceID,
				"evidence_type": strings.TrimSpace(attributes["evidence_type"]),
				"observed_at":   strings.TrimSpace(attributes["observed_at"]),
				"process_name":  strings.TrimSpace(attributes["process_name"]),
				"verdict":       strings.TrimSpace(attributes["verdict"]),
			},
		})
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: firstNonEmpty(attributes["resource_entity_type"], "runtime."+strings.ReplaceAll(normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource")), "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["resource_id"], resourceURN),
			Attributes: map[string]string{"resource_id": strings.TrimSpace(attributes["resource_id"]), "resource_type": strings.TrimSpace(attributes["resource_type"])},
		})
	}
	if resourceURN != "" && evidenceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, resourceURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	if findingID := strings.TrimSpace(attributes["finding_id"]); findingID != "" && evidenceURN != "" {
		findingURN := projectionURN(tenantID, "finding", findingID)
		addEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "finding", Label: findingID})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
