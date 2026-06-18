package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// kolideDeviceProjections materializes the Kolide endpoint graph slice (device,
// owner, and identifier links) and enriches the device node with current host
// posture attributes (failing compliance check count, enrollment/registration
// state, and last resolution time) so durable host posture findings can anchor
// on the device's current state rather than on raw osquery events.
func kolideDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := endpointDeviceProjections(event, kolideEndpointProfile)
	if err != nil {
		return nil, nil, err
	}
	enrichKolideDevicePosture(entities, event)
	return entities, links, nil
}

func kolideIssueProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	baseEntities, baseLinks, err := kolideCheckProjections(event)
	if err != nil {
		return nil, nil, err
	}
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, entity := range baseEntities {
		addEntity(entities, entity)
	}
	for _, link := range baseLinks {
		addLink(links, link)
	}

	issueID := strings.TrimSpace(attrs["issue_id"])
	issueURN := projectionURN(tenant, "kolide_issue", issueID)
	if issueURN == "" {
		projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
		return projectedEntities, projectedLinks, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        issueURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "kolide.issue",
		Label:      firstAttribute(attrs, "title", "issue_value", "issue_id"),
		Attributes: map[string]string{
			"issue_id":           issueID,
			"issue_key":          strings.TrimSpace(attrs["issue_key"]),
			"issue_value":        strings.TrimSpace(attrs["issue_value"]),
			"title":              strings.TrimSpace(attrs["title"]),
			"check_id":           strings.TrimSpace(attrs["check_id"]),
			"device_id":          strings.TrimSpace(attrs["device_id"]),
			"resolved_at":        strings.TrimSpace(attrs["resolved_at"]),
			"detected_at":        strings.TrimSpace(attrs["detected_at"]),
			"last_rechecked_at":  strings.TrimSpace(attrs["last_rechecked_at"]),
			"blocks_device_at":   strings.TrimSpace(attrs["blocks_device_at"]),
			"exempted":           strings.TrimSpace(attrs["exempted"]),
			"check_result_value": strings.TrimSpace(attrs["check_result_value"]),
			"source_product":     "kolide",
			"event_id":           event.GetId(),
			"at":                 eventObservedAt(event),
		},
	})

	endpointURN := projectionURN(tenant, kolideEndpointProfile.EndpointKind, firstAttribute(attrs, kolideEndpointProfile.EndpointIDKeys...))
	checkURN := projectionURN(tenant, "kolide_check", firstAttribute(attrs, "check_id", "slug", "name"))
	if endpointURN != "" {
		addLink(links, projectedLink(tenant, event.GetSourceId(), endpointURN, issueURN, relationHasEvidence, map[string]string{
			"event_id": event.GetId(),
			"at":       eventObservedAt(event),
		}))
		addLink(links, projectedLink(tenant, event.GetSourceId(), issueURN, endpointURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	}
	if checkURN != "" {
		addLink(links, projectedLink(tenant, event.GetSourceId(), checkURN, issueURN, relationHasEvidence, map[string]string{
			"event_id": event.GetId(),
			"at":       eventObservedAt(event),
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func enrichKolideDevicePosture(entities []*ports.ProjectedEntity, event *cerebrov1.EventEnvelope) {
	tenant, err := tenantID(event)
	if err != nil {
		return
	}
	attrs := event.GetAttributes()
	deviceURN := projectionURN(tenant, kolideEndpointProfile.EndpointKind, firstAttribute(attrs, kolideEndpointProfile.EndpointIDKeys...))
	if deviceURN == "" {
		return
	}
	for _, entity := range entities {
		if entity == nil || entity.URN != deviceURN {
			continue
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		addEndpointAttribute(entity.Attributes, "failure_count", attrs["failure_count"])
		addEndpointAttribute(entity.Attributes, "registered", attrs["registered"])
		addEndpointAttribute(entity.Attributes, "mdm_enabled", attrs["mdm_enabled"])
		addEndpointAttribute(entity.Attributes, "resolved_at", attrs["resolved_at"])
	}
}
