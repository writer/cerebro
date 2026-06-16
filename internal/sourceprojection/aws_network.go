package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type awsNetworkSubstrateProjection struct {
	entities    map[string]*ports.ProjectedEntity
	links       map[string]*ports.ProjectedLink
	tenantID    string
	sourceID    string
	resourceURN string
	event       *cerebrov1.EventEnvelope
	attributes  map[string]string
}

type awsNetworkSubstrateContext func(*awsNetworkSubstrateProjection)

type awsNetworkSubstrateExtra func(*awsNetworkSubstrateProjection)

func awsGlobalAcceleratorAcceleratorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsCloudResourceProjections(event)
}

func awsVPCProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsCloudResourceProjections(event)
}

func awsSubnetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateVPCOnlyProjections(event)
}

func awsSecurityGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateVPCOnlyProjections(event)
}

func awsRouteTableProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjectionsWithContext(event, addAWSNetworkVPCContextLink, func(projection *awsNetworkSubstrateProjection) {
		for _, subnetID := range splitCloudAttributeList(projection.attributes["subnet_ids"]) {
			subnetURN := projection.addAWSNetworkNode("aws_subnet", "aws.subnet", subnetID)
			projection.addLink(subnetURN, relationAssociatedWith, "aws_route_table_subnet")
		}
		for _, gatewayID := range splitCloudAttributeList(projection.attributes["internet_gateway_ids"]) {
			gatewayURN := projection.addAWSNetworkNode("aws_internet_gateway", "aws.internet.gateway", gatewayID)
			projection.addLink(gatewayURN, relationDependsOn, "aws_route_table_internet_gateway")
		}
		for _, gatewayID := range splitCloudAttributeList(projection.attributes["nat_gateway_ids"]) {
			gatewayURN := projection.addAWSNetworkNode("aws_nat_gateway", "aws.nat.gateway", gatewayID)
			projection.addLink(gatewayURN, relationDependsOn, "aws_route_table_nat_gateway")
		}
		for _, endpointID := range splitCloudAttributeList(projection.attributes["vpc_endpoint_ids"]) {
			endpointURN := projection.addAWSNetworkNode("aws_vpc_endpoint", "aws.vpc.endpoint", endpointID)
			projection.addLink(endpointURN, relationDependsOn, "aws_route_table_vpc_endpoint")
		}
	})
}

func awsNetworkACLProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjectionsWithContext(event, addAWSNetworkVPCContextLink, func(projection *awsNetworkSubstrateProjection) {
		for _, subnetID := range splitCloudAttributeList(projection.attributes["subnet_ids"]) {
			subnetURN := projection.addAWSNetworkNode("aws_subnet", "aws.subnet", subnetID)
			projection.addLink(subnetURN, relationAssociatedWith, "aws_network_acl_subnet")
		}
	})
}

func awsInternetGatewayProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjections(event, nil)
}

func awsNATGatewayProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjections(event, nil)
}

func awsVPCFlowLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjectionsWithContext(event, nil, func(projection *awsNetworkSubstrateProjection) {
		vpcURN := projection.addAWSNetworkNode("aws_vpc", "aws.vpc", projection.attributes["vpc_id"])
		if vpcURN != "" {
			projection.addLink(vpcURN, relationAssociatedWith, "aws_vpc_flow_log_resource")
		}
	})
}

func awsVPCEndpointProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjections(event, func(projection *awsNetworkSubstrateProjection) {
		for _, routeTableID := range splitCloudAttributeList(projection.attributes["route_table_ids"]) {
			tableURN := projection.addAWSNetworkNode("aws_route_table", "aws.route.table", routeTableID)
			projection.addLink(tableURN, relationAssociatedWith, "aws_vpc_endpoint_route_table")
		}
	})
}

func awsNetworkSubstrateProjections(event *cerebrov1.EventEnvelope, extra awsNetworkSubstrateExtra) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsNetworkSubstrateProjectionsWithContext(event, addAWSNetworkFullContextLinks, extra)
}

func awsNetworkSubstrateProjectionsWithContext(event *cerebrov1.EventEnvelope, contextLinks awsNetworkSubstrateContext, extra awsNetworkSubstrateExtra) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	resourceType := cloudResourceProjectionType(event, "aws", attributes)
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "aws_"+resourceType, cloudResourceProjectionID(attributes)))
	if resourceURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	projection := &awsNetworkSubstrateProjection{
		entities:    entityMap,
		links:       linkMap,
		tenantID:    tenantID,
		sourceID:    event.GetSourceId(),
		resourceURN: resourceURN,
		event:       event,
		attributes:  attributes,
	}
	if contextLinks != nil {
		contextLinks(projection)
	}
	if extra != nil {
		extra(projection)
	}
	return identityProjectionResult(entityMap, linkMap)
}

func addAWSNetworkFullContextLinks(projection *awsNetworkSubstrateProjection) {
	addAWSNetworkContextLinks(projection.entities, projection.links, projection.tenantID, projection.sourceID, projection.event, projection.resourceURN, projection.attributes)
}

func addAWSNetworkVPCContextLink(projection *awsNetworkSubstrateProjection) {
	vpcURN := projection.addAWSNetworkNode("aws_vpc", "aws.vpc", firstNonEmpty(projection.attributes["vpc_id"], projection.attributes["vpc"]))
	if vpcURN != "" {
		projection.addLink(vpcURN, relationBelongsTo, "aws_compute_vpc")
		addCloudAccountLink(projection.entities, projection.links, projection.tenantID, projection.sourceID, projection.event, vpcURN, projection.accountID(), "aws")
	}
}

func (projection *awsNetworkSubstrateProjection) accountID() string {
	return strings.TrimSpace(projection.attributes["domain"])
}

func (projection *awsNetworkSubstrateProjection) addAWSNetworkNode(urnKind string, entityType string, id string) string {
	return addAWSNetworkNode(projection.entities, projection.tenantID, projection.sourceID, urnKind, entityType, id, projection.accountID())
}

func (projection *awsNetworkSubstrateProjection) addLink(toURN string, relation string, matchType string) {
	addLink(projection.links, projectedLink(projection.tenantID, projection.sourceID, projection.resourceURN, toURN, relation, map[string]string{"event_id": projection.event.GetId(), "match_type": matchType}))
}

func awsNetworkSubstrateVPCOnlyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	resourceType := cloudResourceProjectionType(event, "aws", attributes)
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "aws_"+resourceType, cloudResourceProjectionID(attributes)))
	vpcURN := addAWSNetworkNode(entityMap, tenantID, event.GetSourceId(), "aws_vpc", "aws.vpc", firstNonEmpty(attributes["vpc_id"], attributes["vpc"]), attributes["domain"])
	if resourceURN != "" && vpcURN != "" && resourceURN != vpcURN {
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), resourceURN, vpcURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_network_substrate_vpc"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsGlobalAcceleratorListenerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	listenerURN := projectionURN(tenantID, "aws_globalaccelerator_listener", firstNonEmpty(attributes["listener_arn"], attributes["resource_id"]))
	acceleratorURN := projectionURN(tenantID, "aws_globalaccelerator_accelerator", attributes["accelerator_arn"])
	if acceleratorURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), acceleratorURN, "aws.globalaccelerator.accelerator", firstNonEmpty(attributes["accelerator_name"], attributes["accelerator_arn"]), map[string]string{
			"accelerator_arn": strings.TrimSpace(attributes["accelerator_arn"]),
			"domain":          strings.TrimSpace(attributes["domain"]),
			"region":          "global",
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), listenerURN, acceleratorURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "global_accelerator_listener_accelerator"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsGlobalAcceleratorEndpointGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	groupURN := projectionURN(tenantID, "aws_globalaccelerator_endpoint_group", firstNonEmpty(attributes["endpoint_group_arn"], attributes["resource_id"]))
	listenerURN := projectionURN(tenantID, "aws_globalaccelerator_listener", attributes["listener_arn"])
	if listenerURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), listenerURN, "aws.globalaccelerator.listener", firstNonEmpty(attributes["listener_arn"], "global accelerator listener"), map[string]string{
			"accelerator_arn": strings.TrimSpace(attributes["accelerator_arn"]),
			"domain":          strings.TrimSpace(attributes["domain"]),
			"listener_arn":    strings.TrimSpace(attributes["listener_arn"]),
			"region":          "global",
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), groupURN, listenerURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "global_accelerator_endpoint_group_listener"}))
	}
	for _, endpointID := range splitCloudAttributeList(attributes["endpoint_ids"]) {
		endpointURN := projectionURN(tenantID, "aws_globalaccelerator_endpoint", endpointID)
		if endpointURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), endpointURN, "aws.globalaccelerator.endpoint", endpointID, map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"endpoint_id": endpointID,
			"region":      strings.TrimSpace(firstNonEmpty(attributes["endpoint_group_region"], attributes["region"])),
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), groupURN, endpointURN, relationTargeted, map[string]string{"event_id": event.GetId(), "match_type": "global_accelerator_endpoint_group_endpoint"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsVPCLatticeServiceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsCloudResourceProjections(event)
}

func awsVPCLatticeListenerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	listenerURN := projectionURN(tenantID, "aws_vpclattice_listener", firstNonEmpty(attributes["listener_arn"], attributes["resource_id"], attributes["listener_id"]))
	serviceURN := projectionURN(tenantID, "aws_vpclattice_service", firstNonEmpty(attributes["service_arn"], attributes["service_id"]))
	if serviceURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), serviceURN, "aws.vpclattice.service", firstNonEmpty(attributes["service_name"], attributes["service_id"], attributes["service_arn"]), map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"region":      strings.TrimSpace(attributes["region"]),
			"service_arn": strings.TrimSpace(attributes["service_arn"]),
			"service_id":  strings.TrimSpace(attributes["service_id"]),
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), listenerURN, serviceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_listener_service"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsVPCLatticeTargetGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
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
	targetGroupURN := projectionURN(tenantID, "aws_vpclattice_target_group", firstNonEmpty(attributes["target_group_arn"], attributes["resource_id"], attributes["target_group_id"]))
	for _, serviceARN := range splitCloudAttributeList(attributes["service_arns"]) {
		serviceURN := projectionURN(tenantID, "aws_vpclattice_service", serviceARN)
		if serviceURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), serviceURN, "aws.vpclattice.service", serviceARN, map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"region":      strings.TrimSpace(attributes["region"]),
			"service_arn": serviceARN,
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), targetGroupURN, serviceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_target_group_service"}))
	}
	addAWSNetworkContextLinks(entityMap, linkMap, tenantID, event.GetSourceId(), event, targetGroupURN, attributes)
	return identityProjectionResult(entityMap, linkMap)
}

func addAWSNetworkServiceEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, entityType string, label string, attributes map[string]string) {
	if strings.TrimSpace(urn) == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: compactAttributes(attributes),
	})
}
