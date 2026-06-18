package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func sdkIntegrationPostureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	integration := strings.TrimSpace(attrs["integration"])
	resourceURN := strings.TrimSpace(attrs["resource_urn"])
	control := strings.TrimSpace(attrs["control"])
	if integration == "" || resourceURN == "" || control == "" {
		return nil, nil, nil
	}
	if strings.Contains(integration, ":") || strings.Contains(control, ":") {
		return nil, nil, nil
	}

	integrationURN := projectionURN(tenantID, "sdk_integration", integration)
	postureURN := projectionURN(tenantID, "sdk_integration_posture", integration, control, sdkPostureResourceKey(tenantID, resourceURN))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: firstNonEmpty(attrs["resource_type"], "resource"),
		Label:      firstNonEmpty(attrs["resource_label"], resourceURN),
		Attributes: compactAttributes(map[string]string{
			"resource_urn": resourceURN,
		}),
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        integrationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sdk.integration",
		Label:      integration,
		Attributes: map[string]string{"integration": integration},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        postureURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sdk.integration_posture",
		Label:      integration + " " + control,
		Attributes: compactAttributes(map[string]string{
			"integration":    integration,
			"control":        control,
			"posture_status": attrs["posture_status"],
			"risk_reason":    attrs["risk_reason"],
			"resource_urn":   resourceURN,
		}),
	})

	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, postureURN, relationHasEvidence, map[string]string{
		"event_id":       event.GetId(),
		"posture_status": attrs["posture_status"],
	}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), postureURN, resourceURN, relationObservedOn, map[string]string{
		"event_id": event.GetId(),
		"at":       eventObservedAt(event),
	}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), postureURN, integrationURN, relationBelongsTo, map[string]string{
		"event_id": event.GetId(),
	}))

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func sdkPostureResourceKey(tenantID string, resourceURN string) string {
	trimmed := strings.TrimPrefix(resourceURN, "urn:cerebro:"+tenantID+":")
	return strings.ReplaceAll(trimmed, ":", "/")
}
