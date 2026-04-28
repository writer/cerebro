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
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if serviceAccountURN != "" && namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceAccountURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
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
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if workloadURN != "" && serviceAccountURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, serviceAccountURN, relationRunsAs, map[string]string{"event_id": event.GetId()}))
	}
	if workloadURN != "" && namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
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
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: serviceAccountURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "kubernetes.service_account", Label: firstNonEmpty(attributes["service_account_name"], "default")})
	}
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
	return identityProjectionResult(entities, links)
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
		Attributes: map[string]string{"cluster_id": strings.TrimSpace(attributes["cluster_id"]), "namespace": firstNonEmpty(attributes["namespace"], "default")},
	})
}

func kubernetesServiceAccountURN(tenantID string, attributes map[string]string) string {
	return projectionURN(tenantID, "kubernetes_service_account", firstNonEmpty(attributes["cluster_id"], attributes["cluster_name"]), firstNonEmpty(attributes["namespace"], "default"), firstNonEmpty(attributes["service_account_name"], attributes["name"], "default"))
}

func kubernetesNamespaceURN(tenantID string, attributes map[string]string) string {
	return projectionURN(tenantID, "kubernetes_namespace", firstNonEmpty(attributes["cluster_id"], attributes["cluster_name"]), firstNonEmpty(attributes["namespace"], "default"))
}

func kubernetesWorkloadURN(tenantID string, attributes map[string]string) string {
	return projectionURN(tenantID, "kubernetes_workload", firstNonEmpty(attributes["cluster_id"], attributes["cluster_name"]), firstNonEmpty(attributes["namespace"], "default"), firstNonEmpty(attributes["workload_uid"], attributes["workload_kind"]+"/"+attributes["workload_name"], attributes["name"]))
}
