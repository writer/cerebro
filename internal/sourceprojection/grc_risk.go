package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcRiskScenarioProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	riskID := firstAttribute(attrs, "risk_id", "external_id")
	if riskID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	riskURN := projectionURN(tenantID, "claim", provider, "risk_scenario", riskID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        riskURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "claim",
		Label:      firstAttribute(attrs, "description", "risk_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"claim_type":    "risk_scenario",
			"predicate":     firstAttribute(attrs, "description"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "review_status"),
		}),
	})
	if owner := firstAttribute(attrs, "owner"); owner != "" {
		ownerURN := projectionURN(tenantID, "contact", provider, "owner", owner)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ownerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "contact",
			Label:      owner,
			Attributes: map[string]string{"source_system": provider, "owner": owner},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), riskURN, ownerURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
		addGRCRiskOwnerEmailLink(entities, links, tenantID, event.GetSourceId(), event, ownerURN, owner)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGRCRiskOwnerEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, contactURN string, owner string) {
	addSecurityContactEmailLink(entities, links, tenantID, sourceID, event, contactURN, owner, "owner")
}
