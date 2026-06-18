package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAzureSubnetLinksNetworkAssociations(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	subnetID := "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/web"
	routeTableID := "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/routeTables/route-table-prod"
	securityGroupID := "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg"
	natGatewayID := "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/natGateways/nat-prod"
	event := &cerebrov1.EventEnvelope{
		Id:       "azure-subnet-web",
		TenantId: "writer",
		SourceId: "azure",
		Kind:     "azure.subnet",
		Attributes: map[string]string{
			"address_prefix":            "10.0.1.0/24",
			"domain":                    "tenant-1",
			"family":                    "subnet",
			"nat_gateway_id":            natGatewayID,
			"network_security_group_id": securityGroupID,
			"resource_group":            "rg-prod",
			"resource_id":               subnetID,
			"resource_name":             "web",
			"resource_provider":         "azure",
			"resource_type":             "Microsoft.Network/virtualNetworks/subnets",
			"route_table_id":            routeTableID,
			"subscription_id":           "sub-1",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	subnetURN := "urn:cerebro:writer:azure_subnet:" + subnetID
	vnetURN := "urn:cerebro:writer:azure_virtual_network:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod"
	routeTableURN := "urn:cerebro:writer:azure_route_table:" + routeTableID
	securityGroupURN := "urn:cerebro:writer:azure_network_security_group:" + securityGroupID
	natGatewayURN := "urn:cerebro:writer:azure_nat_gateway:" + natGatewayID
	accountURN := "urn:cerebro:writer:cloud_account:sub-1"
	assertProjectedLink(t, state, subnetURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, subnetURN, relationBelongsTo, "urn:cerebro:writer:azure_resource_group:sub-1:rg-prod")
	assertProjectedLink(t, state, vnetURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, subnetURN, relationBelongsTo, vnetURN)
	assertProjectedLink(t, state, routeTableURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, subnetURN, relationAssociatedWith, routeTableURN)
	assertProjectedLink(t, state, securityGroupURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, subnetURN, relationAssociatedWith, securityGroupURN)
	assertProjectedLink(t, state, natGatewayURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, subnetURN, relationAssociatedWith, natGatewayURN)
}
