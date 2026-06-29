package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func haveibeenpwnedBreachesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return haveibeenpwnedGenericFindingProjections(event)
}

func haveibeenpwnedAffectedAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "haveibeenpwned"})
}

func haveibeenpwnedAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "haveibeenpwned"})
}

func haveibeenpwnedGenericFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	findingID := firstNonEmpty(attributes["finding_id"], event.GetId())
	findingURN := projectionURN(tenantID, "finding", findingID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "finding", Label: firstNonEmpty(attributes["title"], findingID), Attributes: map[string]string{"finding_id": findingID, "severity": strings.TrimSpace(attributes["severity"]), "status": strings.TrimSpace(attributes["status"]), "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if resourceURN := strings.TrimSpace(attributes["resource_urn"]); resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, resourceURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
