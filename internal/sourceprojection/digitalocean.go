package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func digitaloceanDropletsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	dropletURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenant, "digitalocean_droplets", attributes["resource_id"]))
	if dropletURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        dropletURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime.compute.droplet",
		Label:      firstNonEmpty(attributes["resource_name"], attributes["resource_id"]),
		Attributes: map[string]string{"resource_id": attributes["resource_id"], "resource_type": "droplet", "region": attributes["region"]},
	})
	if vpc := strings.TrimSpace(attributes["vpc_uuid"]); vpc != "" {
		if vpcURN := projectionURN(tenant, "digitalocean_vpcs", vpc); vpcURN != "" {
			addLink(links, projectedLink(tenant, event.GetSourceId(), dropletURN, vpcURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	return identityProjectionResult(entities, links)
}

func digitaloceanVPCsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	vpcURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenant, "digitalocean_vpcs", attributes["resource_id"]))
	if vpcURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vpcURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime.network.vpc",
		Label:      firstNonEmpty(attributes["resource_name"], attributes["resource_id"]),
		Attributes: map[string]string{"resource_id": attributes["resource_id"], "resource_type": "vpc", "region": attributes["region"]},
	})
	return identityProjectionResult(entities, map[string]*ports.ProjectedLink{})
}

func digitaloceanFirewallsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenant, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	firewallURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenant, "digitalocean_firewalls", attributes["resource_id"]))
	if firewallURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	public := strings.EqualFold(strings.TrimSpace(attributes["public_ingress"]), "true")
	addEntity(entities, &ports.ProjectedEntity{
		URN:        firewallURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime.network.firewall",
		Label:      firstNonEmpty(attributes["resource_name"], attributes["resource_id"]),
		Attributes: map[string]string{"resource_id": attributes["resource_id"], "resource_type": "firewall", "public_ingress": attributes["public_ingress"]},
	})
	for _, raw := range strings.Split(attributes["droplet_ids"], ",") {
		dropletID := strings.TrimSpace(raw)
		if dropletID == "" {
			continue
		}
		dropletURN := projectionURN(tenant, "digitalocean_droplets", dropletID)
		if dropletURN == "" {
			continue
		}
		addLink(links, projectedLink(tenant, event.GetSourceId(), firewallURN, dropletURN, relationAttachedTo, map[string]string{"event_id": event.GetId()}))
		if public {
			addLink(links, projectedLink(tenant, event.GetSourceId(), firewallURN, dropletURN, relationCanReach, map[string]string{"event_id": event.GetId(), "exposure": "public"}))
		}
	}
	return identityProjectionResult(entities, links)
}
