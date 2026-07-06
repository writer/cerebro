package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestDigitaloceanDropletProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "tenant", SourceId: "digitalocean", Kind: "digitalocean.droplets",
		Attributes: map[string]string{"resource_id": "3164444", "resource_type": "droplet", "resource_name": "web-01", "vpc_uuid": "vpc-1111", "region": "nyc3"},
	}
	entities, links, err := digitaloceanDropletsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected droplet entity")
	}
	dropletURN := projectionURN("tenant", "digitalocean_droplets", "3164444")
	vpcURN := projectionURN("tenant", "digitalocean_vpcs", "vpc-1111")
	if !projectedLinksContain(links, dropletURN, relationBelongsTo, vpcURN) {
		t.Fatalf("expected droplet %q belongs_to vpc %q, got %+v", dropletURN, vpcURN, links)
	}
}

func TestDigitaloceanVPCProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "tenant", SourceId: "digitalocean", Kind: "digitalocean.vpcs",
		Attributes: map[string]string{"resource_id": "vpc-1111", "resource_type": "vpc", "resource_name": "default-nyc3", "region": "nyc3"},
	}
	entities, _, err := digitaloceanVPCsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected vpc entity")
	}
}

func TestDigitaloceanFirewallProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "tenant", SourceId: "digitalocean", Kind: "digitalocean.firewalls",
		Attributes: map[string]string{"resource_id": "fw-2222", "resource_type": "firewall", "resource_name": "web-fw", "droplet_ids": "3164444,3164445", "public_ingress": "true"},
	}
	entities, links, err := digitaloceanFirewallsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected firewall entity")
	}
	firewallURN := projectionURN("tenant", "digitalocean_firewalls", "fw-2222")
	dropletURN := projectionURN("tenant", "digitalocean_droplets", "3164444")
	if !projectedLinksContain(links, firewallURN, relationCanReach, dropletURN) {
		t.Fatalf("expected firewall %q can_reach droplet %q, got %+v", firewallURN, dropletURN, links)
	}
	if !projectedLinksContain(links, firewallURN, relationAttachedTo, dropletURN) {
		t.Fatalf("expected firewall %q attached_to droplet %q", firewallURN, dropletURN)
	}
}
