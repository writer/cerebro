package sourceprojection

import (
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
