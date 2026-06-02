package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsEC2InstanceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsComputeProjections(event, "aws_ec2_instance", "aws.ec2.instance")
}

func awsLambdaFunctionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsComputeProjections(event, "aws_lambda_function", "aws.lambda.function")
}

func awsECSServiceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_ecs_service", "aws.ecs.service")
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
	serviceURN := projectionURN(tenantID, "aws_ecs_service", firstNonEmpty(attributes["service_arn"], attributes["resource_id"], attributes["service_name"]))
	clusterURN := projectionURN(tenantID, "aws_ecs_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["cluster_name"]))
	taskDefinitionURN := projectionURN(tenantID, "aws_ecs_task_definition", attributes["task_definition_arn"])
	if clusterURN != "" {
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        clusterURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.ecs.cluster",
			Label:      firstNonEmpty(attributes["cluster_name"], attributes["cluster_arn"]),
			Attributes: map[string]string{
				"cluster_arn":  strings.TrimSpace(attributes["cluster_arn"]),
				"cluster_name": strings.TrimSpace(attributes["cluster_name"]),
				"domain":       strings.TrimSpace(attributes["domain"]),
			},
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), serviceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "ecs_service_cluster"}))
		addCloudAccountLink(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes["domain"], "aws")
	}
	if taskDefinitionURN != "" {
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        taskDefinitionURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.ecs.task_definition",
			Label:      firstNonEmpty(attributes["task_definition_arn"], attributes["resource_name"]),
			Attributes: map[string]string{
				"domain":              strings.TrimSpace(attributes["domain"]),
				"task_definition_arn": strings.TrimSpace(attributes["task_definition_arn"]),
			},
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), serviceURN, taskDefinitionURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "match_type": "ecs_service_task_definition"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsECSTaskDefinitionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_ecs_task_definition", "aws.ecs.task_definition")
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
	taskDefinitionURN := projectionURN(tenantID, "aws_ecs_task_definition", firstNonEmpty(attributes["task_definition_arn"], attributes["resource_id"], attributes["task_family"]))
	for _, role := range []struct {
		arn   string
		name  string
		usage string
	}{
		{arn: attributes["task_role_arn"], name: attributes["task_role_name"], usage: "task"},
		{arn: attributes["execution_role_arn"], name: attributes["execution_role_name"], usage: "execution"},
	} {
		addAWSComputeRoleLink(entityMap, linkMap, tenantID, event.GetSourceId(), event, taskDefinitionURN, role.arn, role.name, role.usage)
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsComputeProjections(event *cerebrov1.EventEnvelope, urnKind string, entityType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["arn"], attributes["function_arn"], attributes["service_arn"], attributes["task_definition_arn"], attributes["instance_id"], attributes["resource_name"])
	resourceURN := projectionURN(tenantID, urnKind, resourceID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if resourceURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(attributes["resource_name"], attributes["function_name"], attributes["service_name"], attributes["instance_id"], resourceID),
		Attributes: map[string]string{
			"domain":            strings.TrimSpace(attributes["domain"]),
			"region":            strings.TrimSpace(attributes["region"]),
			"resource_id":       resourceID,
			"resource_name":     strings.TrimSpace(attributes["resource_name"]),
			"resource_provider": strings.TrimSpace(attributes["resource_provider"]),
			"resource_type":     strings.TrimSpace(attributes["resource_type"]),
			"state":             strings.TrimSpace(firstNonEmpty(attributes["state"], attributes["status"])),
		},
	})
	addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, attributes["domain"], "aws")
	addAWSComputeRoleLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, attributes["role_arn"], attributes["role_name"], "primary")
	addAWSNetworkContextLinks(entities, links, tenantID, event.GetSourceId(), event, resourceURN, attributes)
	return identityProjectionResult(entities, links)
}

func addAWSComputeRoleLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, resourceURN string, roleARN string, roleName string, roleUsage string) {
	roleARN = strings.TrimSpace(roleARN)
	resourceURN = strings.TrimSpace(resourceURN)
	if resourceURN == "" || roleARN == "" {
		return
	}
	roleURN := identityPrincipalURN(tenantID, "aws", "role", roleARN, "")
	if roleURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        roleURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.role",
		Label:      firstNonEmpty(roleName, roleARN),
		Attributes: map[string]string{
			"role_arn":  roleARN,
			"role_name": strings.TrimSpace(roleName),
		},
	})
	addLink(links, projectedLink(tenantID, sourceID, resourceURN, roleURN, relationRunsAs, map[string]string{
		"event_id":   event.GetId(),
		"match_type": "aws_compute_role",
		"role_arn":   roleARN,
		"role_name":  strings.TrimSpace(roleName),
		"role_usage": strings.TrimSpace(roleUsage),
	}))
}

func addAWSNetworkContextLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, resourceURN string, attributes map[string]string) {
	accountID := strings.TrimSpace(attributes["domain"])
	vpcURN := addAWSNetworkNode(entities, tenantID, sourceID, "aws_vpc", "aws.vpc", firstNonEmpty(attributes["vpc_id"], attributes["vpc"]), accountID)
	subnetURNs := addAWSNetworkNodes(entities, tenantID, sourceID, "aws_subnet", "aws.subnet", firstNonEmpty(attributes["subnet_ids"], attributes["network_subnet_ids"], attributes["subnet_id"]), accountID)
	securityGroupURNs := addAWSNetworkNodes(entities, tenantID, sourceID, "aws_security_group", "aws.security_group", firstNonEmpty(attributes["security_group_ids"], attributes["network_security_group_ids"]), accountID)
	eniURNs := addAWSNetworkNodes(entities, tenantID, sourceID, "aws_network_interface", "aws.network.interface", attributes["network_interface_ids"], accountID)
	if vpcURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, resourceURN, vpcURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_compute_vpc"}))
		addCloudAccountLink(entities, links, tenantID, sourceID, event, vpcURN, accountID, "aws")
	}
	for _, subnetURN := range subnetURNs {
		addLink(links, projectedLink(tenantID, sourceID, resourceURN, subnetURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_compute_subnet"}))
		if vpcURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, subnetURN, vpcURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_subnet_vpc"}))
		}
	}
	for _, securityGroupURN := range securityGroupURNs {
		addLink(links, projectedLink(tenantID, sourceID, resourceURN, securityGroupURN, relationMemberOf, map[string]string{"event_id": event.GetId(), "match_type": "aws_compute_security_group"}))
	}
	for _, eniURN := range eniURNs {
		addLink(links, projectedLink(tenantID, sourceID, eniURN, resourceURN, relationAttachedTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_compute_network_interface"}))
		if vpcURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, eniURN, vpcURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "aws_eni_vpc"}))
		}
	}
}

func addAWSNetworkNodes(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urnKind string, entityType string, rawIDs string, accountID string) []string {
	var urns []string
	for _, id := range splitCloudAttributeList(rawIDs) {
		if urn := addAWSNetworkNode(entities, tenantID, sourceID, urnKind, entityType, id, accountID); urn != "" {
			urns = append(urns, urn)
		}
	}
	return urns
}

func addAWSNetworkNode(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urnKind string, entityType string, id string, accountID string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	urn := projectionURN(tenantID, urnKind, id)
	if urn == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      id,
		Attributes: map[string]string{
			"domain":      strings.TrimSpace(accountID),
			"resource_id": id,
		},
	})
	return urn
}

func projectedEntitiesMap(entities []*ports.ProjectedEntity) map[string]*ports.ProjectedEntity {
	out := make(map[string]*ports.ProjectedEntity, len(entities))
	for _, entity := range entities {
		if entity != nil {
			out[entity.URN] = entity
		}
	}
	return out
}

func projectedLinksMap(links []*ports.ProjectedLink) map[string]*ports.ProjectedLink {
	out := make(map[string]*ports.ProjectedLink, len(links))
	for _, link := range links {
		if link != nil {
			out[awsComputeProjectedLinkKey(link)] = link
		}
	}
	return out
}

func awsComputeProjectedLinkKey(link *ports.ProjectedLink) string {
	return strings.Join([]string{link.FromURN, link.Relation, link.ToURN}, "|")
}
