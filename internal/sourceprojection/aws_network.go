package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsGlobalAcceleratorAcceleratorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsCloudResourceProjections(event)
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
	listenerURN := projectionURN(tenantID, "aws_global_accelerator_listener", firstNonEmpty(attributes["listener_arn"], attributes["resource_id"]))
	acceleratorURN := projectionURN(tenantID, "aws_global_accelerator_accelerator", attributes["accelerator_arn"])
	if acceleratorURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), acceleratorURN, "aws.global_accelerator.accelerator", firstNonEmpty(attributes["accelerator_name"], attributes["accelerator_arn"]), map[string]string{
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
	groupURN := projectionURN(tenantID, "aws_global_accelerator_endpoint_group", firstNonEmpty(attributes["endpoint_group_arn"], attributes["resource_id"]))
	listenerURN := projectionURN(tenantID, "aws_global_accelerator_listener", attributes["listener_arn"])
	if listenerURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), listenerURN, "aws.global_accelerator.listener", firstNonEmpty(attributes["listener_arn"], "global accelerator listener"), map[string]string{
			"accelerator_arn": strings.TrimSpace(attributes["accelerator_arn"]),
			"domain":          strings.TrimSpace(attributes["domain"]),
			"listener_arn":    strings.TrimSpace(attributes["listener_arn"]),
			"region":          "global",
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), groupURN, listenerURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "global_accelerator_endpoint_group_listener"}))
	}
	for _, endpointID := range splitCloudAttributeList(attributes["endpoint_ids"]) {
		endpointURN := projectionURN(tenantID, "aws_global_accelerator_endpoint", endpointID)
		if endpointURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), endpointURN, "aws.global_accelerator.endpoint", endpointID, map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"endpoint_id": endpointID,
			"region":      strings.TrimSpace(attributes["endpoint_group_region"]),
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
	listenerURN := projectionURN(tenantID, "aws_vpc_lattice_listener", firstNonEmpty(attributes["listener_arn"], attributes["resource_id"], attributes["listener_id"]))
	serviceURN := projectionURN(tenantID, "aws_vpc_lattice_service", firstNonEmpty(attributes["service_arn"], attributes["service_id"]))
	if serviceURN != "" {
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), serviceURN, "aws.vpc_lattice.service", firstNonEmpty(attributes["service_name"], attributes["service_id"], attributes["service_arn"]), map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"region":      strings.TrimSpace(attributes["region"]),
			"service_arn": strings.TrimSpace(attributes["service_arn"]),
			"service_id":  strings.TrimSpace(attributes["service_id"]),
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), listenerURN, serviceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_listener_service"}))
	}
	for _, targetGroupID := range splitCloudAttributeList(attributes["target_group_ids"]) {
		targetGroupURN := projectionURN(tenantID, "aws_vpc_lattice_target_group", targetGroupID)
		if targetGroupURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), targetGroupURN, "aws.vpc_lattice.target_group", targetGroupID, map[string]string{
			"domain":           strings.TrimSpace(attributes["domain"]),
			"region":           strings.TrimSpace(attributes["region"]),
			"target_group_arn": targetGroupID,
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), listenerURN, targetGroupURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_listener_target_group"}))
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
	targetGroupURN := projectionURN(tenantID, "aws_vpc_lattice_target_group", firstNonEmpty(attributes["target_group_arn"], attributes["resource_id"], attributes["target_group_id"]))
	for _, serviceARN := range splitCloudAttributeList(attributes["service_arns"]) {
		serviceURN := projectionURN(tenantID, "aws_vpc_lattice_service", serviceARN)
		if serviceURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), serviceURN, "aws.vpc_lattice.service", serviceARN, map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"region":      strings.TrimSpace(attributes["region"]),
			"service_arn": serviceARN,
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), targetGroupURN, serviceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_target_group_service"}))
	}
	addAWSNetworkContextLinks(entityMap, linkMap, tenantID, event.GetSourceId(), event, targetGroupURN, attributes)
	for _, targetID := range splitCloudAttributeList(attributes["target_ids"]) {
		targetURN := projectionURN(tenantID, "aws_vpc_lattice_target", firstNonEmpty(attributes["target_group_id"], attributes["target_group_arn"])+":"+targetID)
		if targetURN == "" {
			continue
		}
		addAWSNetworkServiceEntity(entityMap, tenantID, event.GetSourceId(), targetURN, "aws.vpc_lattice.target", targetID, map[string]string{
			"domain":      strings.TrimSpace(attributes["domain"]),
			"region":      strings.TrimSpace(attributes["region"]),
			"target_id":   targetID,
			"target_type": strings.TrimSpace(attributes["target_type"]),
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), targetGroupURN, targetURN, relationTargeted, map[string]string{"event_id": event.GetId(), "match_type": "vpc_lattice_target_group_target"}))
	}
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
