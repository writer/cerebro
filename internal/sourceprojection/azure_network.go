package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func azureSubnetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := azureCloudResourceProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntitiesMap(entities)
	linkMap := projectedLinksMap(links)
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := cloudResourceProjectionID(attributes)
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "azure_subnet", resourceID))
	if resourceURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	accountID := cloudResourceAccountID("azure", attributes, resourceID, resourceURN)

	if vnetID := azureParentVirtualNetworkID(resourceID); vnetID != "" {
		vnetURN := addAzureNetworkNode(entityMap, linkMap, tenantID, event.GetSourceId(), "azure_virtual_network", "azure.virtual.network", vnetID, "Microsoft.Network/virtualNetworks", accountID, event)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), resourceURN, vnetURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "azure_subnet_virtual_network"}))
	}
	for _, routeTableID := range splitCloudAttributeList(attributes["route_table_id"]) {
		tableURN := addAzureNetworkNode(entityMap, linkMap, tenantID, event.GetSourceId(), "azure_route_table", "azure.route.table", routeTableID, "Microsoft.Network/routeTables", accountID, event)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), resourceURN, tableURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "azure_subnet_route_table"}))
	}
	for _, securityGroupID := range splitCloudAttributeList(attributes["network_security_group_id"]) {
		securityGroupURN := addAzureNetworkNode(entityMap, linkMap, tenantID, event.GetSourceId(), "azure_network_security_group", "azure.network.security.group", securityGroupID, "Microsoft.Network/networkSecurityGroups", accountID, event)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), resourceURN, securityGroupURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "azure_subnet_network_security_group"}))
	}
	for _, natGatewayID := range splitCloudAttributeList(attributes["nat_gateway_id"]) {
		gatewayURN := addAzureNetworkNode(entityMap, linkMap, tenantID, event.GetSourceId(), "azure_nat_gateway", "azure.nat.gateway", natGatewayID, "Microsoft.Network/natGateways", accountID, event)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), resourceURN, gatewayURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "azure_subnet_nat_gateway"}))
	}

	return identityProjectionResult(entityMap, linkMap)
}

func addAzureNetworkNode(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, urnKind string, entityType string, resourceID string, resourceType string, accountID string, event *cerebrov1.EventEnvelope) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return ""
	}
	resourceURN := projectionURN(tenantID, urnKind, resourceID)
	if resourceURN == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      azureResourceNameFromScope(resourceID),
		Attributes: compactAttributes(map[string]string{
			"resource_id":       resourceID,
			"resource_name":     azureResourceNameFromScope(resourceID),
			"resource_provider": "azure",
			"resource_type":     resourceType,
			"subscription_id":   accountID,
		}),
	})
	addCloudAccountLink(entities, links, tenantID, sourceID, event, resourceURN, accountID, "azure")
	return resourceURN
}

func azureParentVirtualNetworkID(resourceID string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(resourceID), "/"), "/")
	for index := 0; index+3 < len(parts); index++ {
		if strings.EqualFold(parts[index], "providers") &&
			strings.EqualFold(parts[index+1], "Microsoft.Network") &&
			strings.EqualFold(parts[index+2], "virtualNetworks") &&
			strings.TrimSpace(parts[index+3]) != "" {
			return "/" + strings.Join(parts[:index+4], "/")
		}
	}
	return ""
}

func azureResourceNameFromScope(resourceID string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(resourceID), "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}
