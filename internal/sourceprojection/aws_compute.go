package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsEC2InstanceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_ec2_instance", "aws.ec2.instance")
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
	instanceURN := ""
	if instanceID := firstNonEmpty(attributes["resource_id"], attributes["instance_id"]); instanceID != "" {
		instanceURN = projectionURN(tenantID, "aws_ec2_instance", instanceID)
	}
	addAWSEKSNodeContextLinks(entityMap, linkMap, tenantID, event.GetSourceId(), event, instanceURN, attributes)
	return identityProjectionResult(entityMap, linkMap)
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
	addAWSECSService(entityMap, tenantID, event.GetSourceId(), serviceURN, attributes)
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
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), serviceURN, taskDefinitionURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "match_type": "ecs_service_task_definition"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsECSTaskProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_ecs_task", "aws.ecs.task")
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
	taskURN := projectionURN(tenantID, "aws_ecs_task", firstNonEmpty(attributes["task_arn"], attributes["resource_id"], attributes["resource_name"]))
	clusterURN := projectionURN(tenantID, "aws_ecs_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["cluster_name"]))
	serviceURN := projectionURN(tenantID, "aws_ecs_service", attributes["service_arn"])
	taskDefinitionURN := projectionURN(tenantID, "aws_ecs_task_definition", attributes["task_definition_arn"])
	addAWSECSTask(entityMap, tenantID, event.GetSourceId(), taskURN, attributes)
	if clusterURN != "" {
		addAWSECSCluster(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), taskURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "ecs_task_cluster"}))
	}
	if serviceURN != "" {
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), taskURN, serviceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "ecs_task_service"}))
	}
	if taskDefinitionURN != "" {
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), taskURN, taskDefinitionURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "match_type": "ecs_task_task_definition"}))
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
	addAWSECSTaskDefinition(entityMap, tenantID, event.GetSourceId(), taskDefinitionURN, attributes)
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

func awsEKSClusterProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_eks_cluster", "aws.eks.cluster")
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
	clusterURN := projectionURN(tenantID, "aws_eks_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["resource_id"], attributes["cluster_name"]))
	addAWSEKSCluster(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes)
	nameURN := awsEKSClusterNameURN(tenantID, attributes)
	if nameURN != "" && clusterURN != "" && nameURN != clusterURN {
		addAWSEKSCluster(entityMap, linkMap, tenantID, event.GetSourceId(), event, nameURN, map[string]string{
			"cluster_arn":  attributes["cluster_arn"],
			"cluster_name": attributes["cluster_name"],
			"domain":       attributes["domain"],
			"region":       attributes["region"],
		})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), nameURN, clusterURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "eks_cluster_name"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsEKSNodegroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_eks_nodegroup", "aws.eks.nodegroup")
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
	nodegroupURN := projectionURN(tenantID, "aws_eks_nodegroup", firstNonEmpty(attributes["nodegroup_arn"], attributes["resource_id"], attributes["nodegroup_name"]))
	clusterURN := projectionURN(tenantID, "aws_eks_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["cluster_name"]))
	addAWSEKSNodegroup(entityMap, tenantID, event.GetSourceId(), nodegroupURN, attributes)
	nameURN := awsEKSNodegroupNameURN(tenantID, attributes)
	if nameURN != "" && nodegroupURN != "" && nameURN != nodegroupURN {
		addAWSEKSNodegroup(entityMap, tenantID, event.GetSourceId(), nameURN, attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), nameURN, nodegroupURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "eks_nodegroup_name"}))
	}
	if clusterURN != "" {
		addAWSEKSCluster(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), nodegroupURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_nodegroup_cluster"}))
		if nameURN != "" && nameURN != nodegroupURN {
			addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), nameURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_nodegroup_cluster_name"}))
		}
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsEKSFargateProfileProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsComputeProjections(event, "aws_eks_fargate_profile", "aws.eks.fargate_profile")
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
	profileURN := projectionURN(tenantID, "aws_eks_fargate_profile", firstNonEmpty(attributes["fargate_profile_arn"], attributes["resource_id"], attributes["fargate_profile_name"]))
	clusterURN := projectionURN(tenantID, "aws_eks_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["cluster_name"]))
	if clusterURN != "" {
		addAWSEKSCluster(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), profileURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_fargate_profile_cluster"}))
	}
	for _, namespace := range splitCloudAttributeList(attributes["selector_namespaces"]) {
		kubernetesAttributes := awsEKSKubernetesAttributes(attributes, namespace, "")
		namespaceURN := kubernetesNamespaceURN(tenantID, kubernetesAttributes)
		if namespaceURN == "" {
			continue
		}
		addKubernetesNamespace(entityMap, tenantID, event.GetSourceId(), kubernetesAttributes, namespaceURN)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), namespaceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "kubernetes_namespace_cluster"}))
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), profileURN, namespaceURN, relationSupports, map[string]string{"event_id": event.GetId(), "match_type": "eks_fargate_profile_selector"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsEKSPodIdentityAssociationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	associationURN := projectionURN(tenantID, "aws_eks_pod_identity_association", firstNonEmpty(attributes["association_arn"], attributes["association_id"], attributes["resource_id"]))
	clusterURN := projectionURN(tenantID, "aws_eks_cluster", firstNonEmpty(attributes["cluster_arn"], attributes["cluster_name"]))
	kubernetesAttributes := awsEKSKubernetesAttributes(attributes, attributes["namespace"], attributes["service_account"])
	namespaceURN := kubernetesNamespaceURN(tenantID, kubernetesAttributes)
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, kubernetesAttributes)
	if associationURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        associationURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.eks.pod_identity_association",
			Label:      firstNonEmpty(attributes["resource_name"], attributes["association_id"], attributes["association_arn"]),
			Attributes: map[string]string{
				"association_arn": strings.TrimSpace(attributes["association_arn"]),
				"association_id":  strings.TrimSpace(attributes["association_id"]),
				"cluster_name":    strings.TrimSpace(attributes["cluster_name"]),
				"domain":          strings.TrimSpace(attributes["domain"]),
				"namespace":       strings.TrimSpace(attributes["namespace"]),
				"service_account": strings.TrimSpace(attributes["service_account"]),
			},
		})
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, associationURN, attributes["domain"], "aws")
	}
	if clusterURN != "" {
		addAWSEKSCluster(entities, links, tenantID, event.GetSourceId(), event, clusterURN, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), associationURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_pod_identity_cluster"}))
	}
	if namespaceURN != "" {
		addKubernetesNamespace(entities, tenantID, event.GetSourceId(), kubernetesAttributes, namespaceURN)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), namespaceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "kubernetes_namespace_cluster"}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), associationURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_pod_identity_namespace"}))
	}
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        serviceAccountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.service_account",
			Label:      firstNonEmpty(kubernetesAttributes["service_account_name"], serviceAccountURN),
			Attributes: map[string]string{
				"cloud_account_id":     strings.TrimSpace(kubernetesAttributes["account_id"]),
				"cloud_provider":       "aws",
				"cluster_name":         strings.TrimSpace(kubernetesAttributes["cluster_name"]),
				"namespace":            strings.TrimSpace(kubernetesAttributes["namespace"]),
				"service_account_name": strings.TrimSpace(kubernetesAttributes["service_account_name"]),
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "kubernetes_service_account_namespace"}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), associationURN, serviceAccountURN, relationSupports, map[string]string{"event_id": event.GetId(), "match_type": "eks_pod_identity_service_account"}))
	}
	roleARN := firstNonEmpty(attributes["role_arn"], attributes["target_role_arn"])
	roleName := firstNonEmpty(attributes["role_name"], attributes["target_role_name"])
	addAWSComputeRoleLink(entities, links, tenantID, event.GetSourceId(), event, associationURN, roleARN, roleName, "pod_identity")
	roleURN := identityPrincipalURN(tenantID, "aws", "role", roleARN, "")
	if serviceAccountURN != "" && roleURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, roleURN, relationCanAssume, map[string]string{
			"association_arn": strings.TrimSpace(attributes["association_arn"]),
			"association_id":  strings.TrimSpace(attributes["association_id"]),
			"event_id":        event.GetId(),
			"match_type":      "eks_pod_identity_role",
			"role_arn":        strings.TrimSpace(roleARN),
			"role_name":       strings.TrimSpace(roleName),
		}))
	}
	return identityProjectionResult(entities, links)
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

func addAWSECSCluster(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, clusterURN string, attributes map[string]string) {
	if clusterURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        clusterURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ecs.cluster",
		Label:      firstNonEmpty(attributes["cluster_name"], attributes["cluster_arn"]),
		Attributes: map[string]string{
			"cluster_arn":  strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name": strings.TrimSpace(attributes["cluster_name"]),
			"domain":       strings.TrimSpace(attributes["domain"]),
			"region":       strings.TrimSpace(attributes["region"]),
		},
	})
	addCloudAccountLink(entities, links, tenantID, sourceID, event, clusterURN, attributes["domain"], "aws")
}

func addAWSECSService(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, serviceURN string, attributes map[string]string) {
	if serviceURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        serviceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ecs.service",
		Label:      firstNonEmpty(attributes["service_name"], attributes["resource_name"], attributes["service_arn"]),
		Attributes: map[string]string{
			"assign_public_ip":                   strings.TrimSpace(attributes["assign_public_ip"]),
			"capacity_providers":                 strings.TrimSpace(attributes["capacity_providers"]),
			"cluster_arn":                        strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name":                       strings.TrimSpace(attributes["cluster_name"]),
			"desired_count":                      strings.TrimSpace(attributes["desired_count"]),
			"domain":                             strings.TrimSpace(attributes["domain"]),
			"enable_execute_command":             strings.TrimSpace(attributes["enable_execute_command"]),
			"fargate_capacity_provider":          strings.TrimSpace(attributes["fargate_capacity_provider"]),
			"fargate_service":                    strings.TrimSpace(attributes["fargate_service"]),
			"launch_type":                        strings.TrimSpace(attributes["launch_type"]),
			"launch_type_effective":              strings.TrimSpace(attributes["launch_type_effective"]),
			"network_security_group_ids":         strings.TrimSpace(attributes["network_security_group_ids"]),
			"network_subnet_ids":                 strings.TrimSpace(attributes["network_subnet_ids"]),
			"pending_count":                      strings.TrimSpace(attributes["pending_count"]),
			"platform_family":                    strings.TrimSpace(attributes["platform_family"]),
			"platform_version":                   strings.TrimSpace(attributes["platform_version"]),
			"region":                             strings.TrimSpace(attributes["region"]),
			"resource_id":                        strings.TrimSpace(firstNonEmpty(attributes["service_arn"], attributes["resource_id"])),
			"resource_name":                      strings.TrimSpace(firstNonEmpty(attributes["service_name"], attributes["resource_name"])),
			"resource_provider":                  strings.TrimSpace(attributes["resource_provider"]),
			"resource_type":                      strings.TrimSpace(firstNonEmpty(attributes["resource_type"], "ecs_service")),
			"running_count":                      strings.TrimSpace(attributes["running_count"]),
			"scheduling_strategy":                strings.TrimSpace(attributes["scheduling_strategy"]),
			"service_arn":                        strings.TrimSpace(attributes["service_arn"]),
			"service_name":                       strings.TrimSpace(attributes["service_name"]),
			"status":                             strings.TrimSpace(attributes["status"]),
			"task_definition_arn":                strings.TrimSpace(attributes["task_definition_arn"]),
			"task_definition_family":             strings.TrimSpace(attributes["task_definition_family"]),
			"task_definition_revision":           strings.TrimSpace(attributes["task_definition_revision"]),
			"deployment_controller_type":         strings.TrimSpace(attributes["deployment_controller_type"]),
			"deployment_maximum_percent":         strings.TrimSpace(attributes["deployment_maximum_percent"]),
			"deployment_minimum_healthy_percent": strings.TrimSpace(attributes["deployment_minimum_healthy_percent"]),
			"deployment_strategy":                strings.TrimSpace(attributes["deployment_strategy"]),
			"load_balancer_target_group_arns":    strings.TrimSpace(attributes["load_balancer_target_group_arns"]),
			"service_registry_arns":              strings.TrimSpace(attributes["service_registry_arns"]),
		},
	})
}

func addAWSECSTask(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, taskURN string, attributes map[string]string) {
	if taskURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        taskURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ecs.task",
		Label:      firstNonEmpty(attributes["resource_name"], attributes["task_arn"]),
		Attributes: map[string]string{
			"capacity_provider_name":     strings.TrimSpace(attributes["capacity_provider_name"]),
			"cpu":                        strings.TrimSpace(attributes["cpu"]),
			"domain":                     strings.TrimSpace(attributes["domain"]),
			"enable_execute_command":     strings.TrimSpace(attributes["enable_execute_command"]),
			"ephemeral_storage_size_gib": strings.TrimSpace(attributes["ephemeral_storage_size_gib"]),
			"fargate_task":               strings.TrimSpace(attributes["fargate_task"]),
			"launch_type":                strings.TrimSpace(attributes["launch_type"]),
			"memory":                     strings.TrimSpace(attributes["memory"]),
			"platform_family":            strings.TrimSpace(attributes["platform_family"]),
			"platform_version":           strings.TrimSpace(attributes["platform_version"]),
			"private_ips":                strings.TrimSpace(attributes["private_ips"]),
			"resource_id":                strings.TrimSpace(firstNonEmpty(attributes["task_arn"], attributes["resource_id"])),
			"resource_name":              strings.TrimSpace(attributes["resource_name"]),
			"resource_provider":          strings.TrimSpace(attributes["resource_provider"]),
			"resource_type":              strings.TrimSpace(firstNonEmpty(attributes["resource_type"], "ecs_task")),
			"security_group_ids":         strings.TrimSpace(attributes["security_group_ids"]),
			"service_arn":                strings.TrimSpace(attributes["service_arn"]),
			"service_name":               strings.TrimSpace(attributes["service_name"]),
			"subnet_ids":                 strings.TrimSpace(attributes["subnet_ids"]),
			"task_arn":                   strings.TrimSpace(attributes["task_arn"]),
			"task_definition_arn":        strings.TrimSpace(attributes["task_definition_arn"]),
			"vpc_id":                     strings.TrimSpace(attributes["vpc_id"]),
		},
	})
}

func addAWSECSTaskDefinition(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, taskDefinitionURN string, attributes map[string]string) {
	if taskDefinitionURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        taskDefinitionURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ecs.task_definition",
		Label:      firstNonEmpty(attributes["task_family"], attributes["resource_name"], attributes["task_definition_arn"]),
		Attributes: map[string]string{
			"awsvpc_required":                 strings.TrimSpace(attributes["awsvpc_required"]),
			"container_count":                 strings.TrimSpace(attributes["container_count"]),
			"container_images":                strings.TrimSpace(attributes["container_images"]),
			"container_names":                 strings.TrimSpace(attributes["container_names"]),
			"cpu":                             strings.TrimSpace(attributes["cpu"]),
			"domain":                          strings.TrimSpace(attributes["domain"]),
			"ephemeral_storage_size_gib":      strings.TrimSpace(attributes["ephemeral_storage_size_gib"]),
			"fargate_compatible":              strings.TrimSpace(attributes["fargate_compatible"]),
			"memory":                          strings.TrimSpace(attributes["memory"]),
			"network_mode":                    strings.TrimSpace(attributes["network_mode"]),
			"region":                          strings.TrimSpace(attributes["region"]),
			"requires_compatibilities":        strings.TrimSpace(attributes["requires_compatibilities"]),
			"resource_id":                     strings.TrimSpace(firstNonEmpty(attributes["task_definition_arn"], attributes["resource_id"])),
			"resource_name":                   strings.TrimSpace(attributes["resource_name"]),
			"resource_provider":               strings.TrimSpace(attributes["resource_provider"]),
			"resource_type":                   strings.TrimSpace(firstNonEmpty(attributes["resource_type"], "ecs_task_definition")),
			"revision":                        strings.TrimSpace(attributes["revision"]),
			"runtime_cpu_architecture":        strings.TrimSpace(attributes["runtime_cpu_architecture"]),
			"runtime_operating_system_family": strings.TrimSpace(attributes["runtime_operating_system_family"]),
			"status":                          strings.TrimSpace(attributes["status"]),
			"task_definition_arn":             strings.TrimSpace(attributes["task_definition_arn"]),
			"task_family":                     strings.TrimSpace(attributes["task_family"]),
		},
	})
}

func addAWSEKSCluster(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, clusterURN string, attributes map[string]string) {
	if clusterURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        clusterURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.eks.cluster",
		Label:      firstNonEmpty(attributes["cluster_name"], attributes["cluster_arn"]),
		Attributes: map[string]string{
			"cluster_arn":             strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name":            strings.TrimSpace(attributes["cluster_name"]),
			"domain":                  strings.TrimSpace(attributes["domain"]),
			"endpoint":                strings.TrimSpace(attributes["endpoint"]),
			"endpoint_private_access": strings.TrimSpace(attributes["endpoint_private_access"]),
			"endpoint_public_access":  strings.TrimSpace(attributes["endpoint_public_access"]),
			"platform_version":        strings.TrimSpace(attributes["platform_version"]),
			"public_access_cidrs":     strings.TrimSpace(attributes["public_access_cidrs"]),
			"region":                  strings.TrimSpace(attributes["region"]),
			"state":                   strings.TrimSpace(firstNonEmpty(attributes["state"], attributes["status"])),
			"version":                 strings.TrimSpace(attributes["version"]),
		},
	})
	addCloudAccountLink(entities, links, tenantID, sourceID, event, clusterURN, attributes["domain"], "aws")
	addAWSNetworkContextLinks(entities, links, tenantID, sourceID, event, clusterURN, attributes)
	addEKSClusterPublicReachability(entities, links, tenantID, sourceID, event, clusterURN, attributes)
}

func addAWSEKSNodegroup(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, nodegroupURN string, attributes map[string]string) {
	if nodegroupURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        nodegroupURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.eks.nodegroup",
		Label:      firstNonEmpty(attributes["nodegroup_name"], attributes["eks_nodegroup_name"], attributes["resource_name"], attributes["nodegroup_arn"]),
		Attributes: map[string]string{
			"ami_type":                              strings.TrimSpace(attributes["ami_type"]),
			"autoscaling_groups":                    strings.TrimSpace(attributes["autoscaling_groups"]),
			"capacity_type":                         strings.TrimSpace(attributes["capacity_type"]),
			"cluster_arn":                           strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name":                          strings.TrimSpace(firstNonEmpty(attributes["cluster_name"], attributes["eks_cluster_name"])),
			"desired_size":                          strings.TrimSpace(attributes["desired_size"]),
			"disk_size_gib":                         strings.TrimSpace(attributes["disk_size_gib"]),
			"domain":                                strings.TrimSpace(attributes["domain"]),
			"health_issue_codes":                    strings.TrimSpace(attributes["health_issue_codes"]),
			"instance_types":                        strings.TrimSpace(attributes["instance_types"]),
			"label_keys":                            strings.TrimSpace(attributes["label_keys"]),
			"labels":                                strings.TrimSpace(attributes["labels"]),
			"launch_template_id":                    strings.TrimSpace(attributes["launch_template_id"]),
			"launch_template_name":                  strings.TrimSpace(attributes["launch_template_name"]),
			"launch_template_version":               strings.TrimSpace(attributes["launch_template_version"]),
			"max_size":                              strings.TrimSpace(attributes["max_size"]),
			"min_size":                              strings.TrimSpace(attributes["min_size"]),
			"node_repair_enabled":                   strings.TrimSpace(attributes["node_repair_enabled"]),
			"node_role_arn":                         strings.TrimSpace(firstNonEmpty(attributes["node_role_arn"], attributes["role_arn"])),
			"nodegroup_arn":                         strings.TrimSpace(attributes["nodegroup_arn"]),
			"nodegroup_name":                        strings.TrimSpace(firstNonEmpty(attributes["nodegroup_name"], attributes["eks_nodegroup_name"])),
			"region":                                strings.TrimSpace(attributes["region"]),
			"release_version":                       strings.TrimSpace(attributes["release_version"]),
			"remote_access_ec2_ssh_key":             strings.TrimSpace(attributes["remote_access_ec2_ssh_key"]),
			"resource_id":                           strings.TrimSpace(firstNonEmpty(attributes["nodegroup_arn"], attributes["resource_id"], attributes["nodegroup_name"], attributes["eks_nodegroup_name"])),
			"resource_name":                         strings.TrimSpace(firstNonEmpty(attributes["resource_name"], attributes["nodegroup_name"], attributes["eks_nodegroup_name"])),
			"resource_provider":                     strings.TrimSpace(attributes["resource_provider"]),
			"resource_type":                         strings.TrimSpace(firstNonEmpty(attributes["resource_type"], "eks_nodegroup")),
			"state":                                 strings.TrimSpace(firstNonEmpty(attributes["state"], attributes["status"])),
			"subnet_ids":                            strings.TrimSpace(attributes["subnet_ids"]),
			"taint_keys":                            strings.TrimSpace(attributes["taint_keys"]),
			"taints":                                strings.TrimSpace(attributes["taints"]),
			"update_strategy":                       strings.TrimSpace(attributes["update_strategy"]),
			"version":                               strings.TrimSpace(attributes["version"]),
			"warm_pool_enabled":                     strings.TrimSpace(attributes["warm_pool_enabled"]),
			"warm_pool_max_group_prepared_capacity": strings.TrimSpace(attributes["warm_pool_max_group_prepared_capacity"]),
			"warm_pool_min_size":                    strings.TrimSpace(attributes["warm_pool_min_size"]),
			"warm_pool_state":                       strings.TrimSpace(attributes["warm_pool_state"]),
		},
	})
}

func addAWSEKSNodeContextLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, instanceURN string, attributes map[string]string) {
	if instanceURN == "" || !strings.EqualFold(attributes["eks_node"], "true") {
		return
	}
	clusterName := firstNonEmpty(attributes["eks_cluster_name"], attributes["kubernetes_cluster"], attributes["cluster_name"])
	clusterURN := ""
	if clusterID := firstNonEmpty(attributes["eks_cluster_arn"], attributes["cluster_arn"], clusterName); clusterID != "" {
		clusterURN = projectionURN(tenantID, "aws_eks_cluster", clusterID)
	}
	if clusterURN != "" {
		addAWSEKSClusterReference(entities, tenantID, sourceID, clusterURN, map[string]string{
			"cluster_arn":  firstNonEmpty(attributes["eks_cluster_arn"], attributes["cluster_arn"]),
			"cluster_name": clusterName,
			"domain":       attributes["domain"],
			"region":       attributes["region"],
		})
		addLink(links, projectedLink(tenantID, sourceID, instanceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "ec2_instance_eks_cluster"}))
	}
	nodegroupURN := ""
	if nodegroupID := firstNonEmpty(attributes["eks_nodegroup_arn"], attributes["nodegroup_arn"]); nodegroupID != "" {
		nodegroupURN = projectionURN(tenantID, "aws_eks_nodegroup", nodegroupID)
	}
	nodegroupURN = firstNonEmpty(nodegroupURN, awsEKSNodegroupNameURN(tenantID, attributes))
	if nodegroupURN == "" {
		return
	}
	addAWSEKSNodegroupReference(entities, tenantID, sourceID, nodegroupURN, attributes)
	addLink(links, projectedLink(tenantID, sourceID, instanceURN, nodegroupURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "ec2_instance_eks_nodegroup"}))
	if clusterURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, nodegroupURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "eks_nodegroup_cluster"}))
	}
}

func addAWSEKSClusterReference(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, clusterURN string, attributes map[string]string) {
	if clusterURN == "" || entities[clusterURN] != nil {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        clusterURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.eks.cluster",
		Label:      firstNonEmpty(attributes["cluster_name"], attributes["cluster_arn"]),
		Attributes: map[string]string{
			"cluster_arn":  strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name": strings.TrimSpace(attributes["cluster_name"]),
			"domain":       strings.TrimSpace(attributes["domain"]),
			"region":       strings.TrimSpace(attributes["region"]),
		},
	})
}

func addAWSEKSNodegroupReference(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, nodegroupURN string, attributes map[string]string) {
	if nodegroupURN == "" || entities[nodegroupURN] != nil {
		return
	}
	nodegroupName := firstNonEmpty(attributes["eks_nodegroup_name"], attributes["nodegroup_name"])
	addEntity(entities, &ports.ProjectedEntity{
		URN:        nodegroupURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.eks.nodegroup",
		Label:      nodegroupName,
		Attributes: map[string]string{
			"cluster_name":   strings.TrimSpace(firstNonEmpty(attributes["eks_cluster_name"], attributes["cluster_name"], attributes["kubernetes_cluster"])),
			"domain":         strings.TrimSpace(attributes["domain"]),
			"nodegroup_name": strings.TrimSpace(nodegroupName),
			"region":         strings.TrimSpace(attributes["region"]),
			"resource_type":  "eks_nodegroup",
		},
	})
}

func awsEKSNodegroupNameURN(tenantID string, attributes map[string]string) string {
	nodegroupName := firstNonEmpty(attributes["eks_nodegroup_name"], attributes["nodegroup_name"])
	if nodegroupName == "" {
		return ""
	}
	clusterName := firstNonEmpty(attributes["eks_cluster_name"], attributes["kubernetes_cluster"], attributes["cluster_name"])
	if clusterName != "" {
		return projectionURN(tenantID, "aws_eks_nodegroup", clusterName, nodegroupName)
	}
	return projectionURN(tenantID, "aws_eks_nodegroup", nodegroupName)
}

func awsEKSClusterNameURN(tenantID string, attributes map[string]string) string {
	clusterName := firstNonEmpty(attributes["eks_cluster_name"], attributes["kubernetes_cluster"], attributes["cluster_name"])
	if clusterName == "" {
		return ""
	}
	return projectionURN(tenantID, "aws_eks_cluster", clusterName)
}

func addEKSClusterPublicReachability(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, clusterURN string, attributes map[string]string) {
	if clusterURN == "" || !eksClusterEndpointInternetExposed(attributes) {
		return
	}
	publicURN := identityPrincipalURN(tenantID, "aws", "public", "public_internet", "")
	if publicURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        publicURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.public_principal",
		Label:      "public internet",
		Attributes: map[string]string{"principal_type": "public"},
	})
	linkAttributes := map[string]string{
		"at":                  eventObservedAt(event),
		"direction":           "ingress",
		"event_id":            event.GetId(),
		"exposure_type":       "eks_public_endpoint",
		"public_access_cidrs": strings.TrimSpace(attributes["public_access_cidrs"]),
	}
	addLink(links, projectedLink(tenantID, sourceID, publicURN, clusterURN, relationCanReach, linkAttributes))
	reverseAttributes := cloneStringMap(linkAttributes)
	reverseAttributes["direction"] = "ingress_reverse"
	addLink(links, projectedLink(tenantID, sourceID, clusterURN, publicURN, relationCanReach, reverseAttributes))
}

func eksClusterEndpointInternetExposed(attributes map[string]string) bool {
	if !projectionBool(attributes["endpoint_public_access"]) {
		return false
	}
	for _, cidr := range splitCloudAttributeList(attributes["public_access_cidrs"]) {
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

func awsEKSKubernetesAttributes(attributes map[string]string, namespace string, serviceAccountName string) map[string]string {
	return map[string]string{
		"account_id":           strings.TrimSpace(attributes["domain"]),
		"cloud_account_id":     strings.TrimSpace(attributes["domain"]),
		"cloud_provider":       "aws",
		"cluster_name":         strings.TrimSpace(attributes["cluster_name"]),
		"namespace":            firstNonEmpty(namespace, "default"),
		"provider":             "aws",
		"service_account_name": strings.TrimSpace(serviceAccountName),
	}
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
