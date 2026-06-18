package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// kandjiDeviceProjections materializes the Kandji endpoint graph slice (device,
// owner, identifier, and blueprint links) and enriches the device node with
// current posture attributes (MDM enrollment, FileVault disk encryption, and
// missing-device state) so durable endpoint posture findings can anchor on the
// device's current state rather than on raw events.
func kandjiDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := endpointDeviceProjections(event, kandjiEndpointProfile)
	if err != nil {
		return nil, nil, err
	}
	enrichKandjiDevicePosture(entities, event)
	return entities, links, nil
}

func enrichKandjiDevicePosture(entities []*ports.ProjectedEntity, event *cerebrov1.EventEnvelope) {
	tenant, err := tenantID(event)
	if err != nil {
		return
	}
	attrs := event.GetAttributes()
	deviceURN := projectionURN(tenant, kandjiEndpointProfile.EndpointKind, firstAttribute(attrs, kandjiEndpointProfile.EndpointIDKeys...))
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
		addEndpointAttribute(entity.Attributes, "mdm_enabled", attrs["mdm_enabled"])
		addEndpointAttribute(entity.Attributes, "filevault_enabled", attrs["filevault_enabled"])
		addEndpointAttribute(entity.Attributes, "is_missing", attrs["is_missing"])
	}
}
