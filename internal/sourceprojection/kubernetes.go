package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func kubernetesServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, attributes)
	namespaceURN := kubernetesNamespaceURN(tenantID, attributes)
	clusterURN := kubernetesClusterURN(tenantID, attributes)
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        serviceAccountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.service_account",
			Label:      firstNonEmpty(attributes["service_account_name"], attributes["name"]),
			Attributes: map[string]string{
				"automount_token":      strings.TrimSpace(attributes["automount_token"]),
				"cluster_id":           strings.TrimSpace(attributes["cluster_id"]),
				"cluster_name":         strings.TrimSpace(attributes["cluster_name"]),
				"namespace":            strings.TrimSpace(attributes["namespace"]),
				"service_account_name": firstNonEmpty(attributes["service_account_name"], attributes["name"]),
			},
		})
	}
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), attributes, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if serviceAccountURN != "" && namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	addKubernetesClusterLinks(entities, links, tenantID, event.GetSourceId(), event, attributes, namespaceURN, clusterURN)
	return identityProjectionResult(entities, links)
}

func kubernetesWorkloadProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	workloadURN := kubernetesWorkloadURN(tenantID, attributes)
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, attributes)
	namespaceURN := kubernetesNamespaceURN(tenantID, attributes)
	clusterURN := kubernetesClusterURN(tenantID, attributes)
	if workloadURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        workloadURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.workload",
			Label:      firstNonEmpty(attributes["workload_name"], attributes["name"], attributes["workload_uid"]),
			Attributes: map[string]string{
				"cluster_id":    strings.TrimSpace(attributes["cluster_id"]),
				"image":         strings.TrimSpace(attributes["image"]),
				"image_digest":  strings.TrimSpace(attributes["image_digest"]),
				"namespace":     strings.TrimSpace(attributes["namespace"]),
				"workload_kind": strings.TrimSpace(attributes["workload_kind"]),
				"workload_name": firstNonEmpty(attributes["workload_name"], attributes["name"]),
				"workload_uid":  strings.TrimSpace(attributes["workload_uid"]),
			},
		})
	}
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: serviceAccountURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "kubernetes.service_account", Label: firstNonEmpty(attributes["service_account_name"], "default")})
	}
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), attributes, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if workloadURN != "" && serviceAccountURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, serviceAccountURN, relationRunsAs, map[string]string{"event_id": event.GetId()}))
	}
	if workloadURN != "" && namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	addKubernetesClusterLinks(entities, links, tenantID, event.GetSourceId(), event, attributes, namespaceURN, clusterURN)
	return identityProjectionResult(entities, links)
}

func kubernetesWorkloadIdentityBindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, attributes)
	namespaceURN := kubernetesNamespaceURN(tenantID, attributes)
	clusterURN := kubernetesClusterURN(tenantID, attributes)
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: serviceAccountURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "kubernetes.service_account", Label: firstNonEmpty(attributes["service_account_name"], "default")})
	}
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), attributes, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	provider := firstNonEmpty(attributes["cloud_provider"], "cloud")
	profile := identityProjectionProfile{Provider: provider}
	targetType := firstNonEmpty(attributes["target_type"], attributes["cloud_principal_type"], "role")
	targetID := firstNonEmpty(attributes["target_id"], attributes["cloud_principal_arn"], attributes["cloud_principal_email"], attributes["cloud_principal_id"])
	targetEmail := firstNonEmpty(attributes["target_email"], attributes["cloud_principal_email"])
	targetURN := cloudTargetURN(tenantID, provider, targetType, targetID, targetEmail)
	if targetURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(normalizeCloudType(identityPrincipalType(targetType)), "_", ".")),
			Label:      firstNonEmpty(attributes["target_name"], targetEmail, targetID),
			Attributes: map[string]string{"target_id": targetID, "target_type": targetType},
		})
	}
	if serviceAccountURN != "" && targetURN != "" {
		relation := cloudPrivilegeRelation(attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, targetURN, relation, map[string]string{
			"event_id":     event.GetId(),
			"path_type":    firstNonEmpty(attributes["path_type"], "workload_identity"),
			"relationship": strings.TrimSpace(attributes["relationship"]),
			"role_id":      strings.TrimSpace(attributes["role_id"]),
			"role_name":    strings.TrimSpace(attributes["role_name"]),
		}))
	}
	if serviceAccountURN != "" && namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	addKubernetesClusterLinks(entities, links, tenantID, event.GetSourceId(), event, attributes, namespaceURN, clusterURN)
	return identityProjectionResult(entities, links)
}

func addKubernetesCluster(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attributes map[string]string, clusterURN string) {
	if clusterURN == "" {
		return
	}
	clusterID := kubernetesClusterIdentity(attributes)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        clusterURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "kubernetes.cluster",
		Label:      clusterID,
		Attributes: map[string]string{
			"cloud_account_id": kubernetesCloudAccountID(attributes),
			"cloud_provider":   strings.TrimSpace(firstNonEmpty(attributes["cloud_provider"], attributes["provider"])),
			"cluster_id":       strings.TrimSpace(attributes["cluster_id"]),
			"cluster_name":     strings.TrimSpace(attributes["cluster_name"]),
		},
	})
}

func addKubernetesClusterLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, attributes map[string]string, namespaceURN string, clusterURN string) {
	if clusterURN == "" {
		return
	}
	if namespaceURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, namespaceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	addCloudAccountLink(entities, links, tenantID, sourceID, event, clusterURN, kubernetesCloudAccountID(attributes), firstNonEmpty(attributes["cloud_provider"], attributes["provider"]))
}

func addKubernetesNamespace(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attributes map[string]string, namespaceURN string) {
	if namespaceURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        namespaceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "kubernetes.namespace",
		Label:      firstNonEmpty(attributes["namespace"], "default"),
		Attributes: map[string]string{"cluster_id": strings.TrimSpace(attributes["cluster_id"]), "cluster_name": strings.TrimSpace(attributes["cluster_name"]), "namespace": firstNonEmpty(attributes["namespace"], "default")},
	})
}

func kubernetesClusterURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	if clusterID == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_cluster", clusterID)
}

func kubernetesServiceAccountURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	if clusterID == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_service_account", clusterID, firstNonEmpty(attributes["namespace"], "default"), firstNonEmpty(attributes["service_account_name"], attributes["name"], "default"))
}

func kubernetesNamespaceURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	if clusterID == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_namespace", clusterID, firstNonEmpty(attributes["namespace"], "default"))
}

func kubernetesWorkloadURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	if clusterID == "" {
		return ""
	}
	workloadID := strings.TrimSpace(attributes["workload_uid"])
	if workloadID == "" && strings.TrimSpace(attributes["workload_kind"]) != "" && strings.TrimSpace(attributes["workload_name"]) != "" {
		workloadID = strings.TrimSpace(attributes["workload_kind"]) + "/" + strings.TrimSpace(attributes["workload_name"])
	}
	workloadID = firstNonEmpty(workloadID, attributes["name"])
	if workloadID == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_workload", clusterID, firstNonEmpty(attributes["namespace"], "default"), workloadID)
}

func kubernetesClusterIdentity(attributes map[string]string) string {
	if clusterID := strings.TrimSpace(attributes["cluster_id"]); clusterID != "" {
		return clusterID
	}
	clusterName := strings.TrimSpace(attributes["cluster_name"])
	if clusterName == "" {
		return ""
	}
	accountID := kubernetesCloudAccountID(attributes)
	if accountID == "" {
		return ""
	}
	return accountID + ":" + clusterName
}

func kubernetesCloudAccountID(attributes map[string]string) string {
	provider := normalizeIdentifier(firstNonEmpty(attributes["cloud_provider"], attributes["provider"]))
	switch provider {
	case "aws":
		return firstNonEmpty(
			awsAccountID(attributes["cloud_account_external_id"]),
			awsAccountID(attributes["cloud_account_id"]),
			awsAccountID(attributes["account_id"]),
			awsAccountID(attributes["aws_account_id"]),
		)
	case "azure":
		return firstNonEmpty(
			attributes["subscription_id"],
			attributes["cloud_account_external_id"],
			azureSubscriptionIDFromScope(attributes["scope"]),
			azureSubscriptionIDFromScope(attributes["resource_id"]),
			azureSubscriptionIDFromScope(attributes["target_id"]),
		)
	case "gcp":
		return firstNonEmpty(
			attributes["gcp_project_id"],
			attributes["project_id"],
			attributes["cloud_account_external_id"],
		)
	default:
		return firstNonEmpty(
			attributes["subscription_id"],
			attributes["aws_account_id"],
			attributes["gcp_project_id"],
			attributes["project_id"],
		)
	}
}
