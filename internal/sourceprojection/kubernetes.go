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
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), targetURN, targetEmail, event.GetOccurredAt())
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

func kubernetesRBACRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	roleURN := kubernetesRBACRoleURN(tenantID, attributes)
	namespaceURN := kubernetesExplicitNamespaceURN(tenantID, attributes)
	clusterURN := kubernetesClusterURN(tenantID, attributes)
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.rbac_role",
			Label:      firstNonEmpty(attributes["role_name"], attributes["resource_name"], attributes["name"]),
			Attributes: map[string]string{
				"cluster_id":   strings.TrimSpace(attributes["cluster_id"]),
				"cluster_name": strings.TrimSpace(attributes["cluster_name"]),
				"namespace":    strings.TrimSpace(attributes["namespace"]),
				"resources":    strings.TrimSpace(attributes["resources"]),
				"role_kind":    strings.TrimSpace(attributes["role_kind"]),
				"role_name":    firstNonEmpty(attributes["role_name"], attributes["resource_name"], attributes["name"]),
				"role_scope":   kubernetesRBACScope(attributes),
				"rules":        strings.TrimSpace(attributes["rules"]),
				"verbs":        strings.TrimSpace(attributes["verbs"]),
			},
		})
	}
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), attributes, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if roleURN != "" {
		if kubernetesRBACScope(attributes) == "namespace" && namespaceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if clusterURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	addKubernetesClusterLinks(entities, links, tenantID, event.GetSourceId(), event, attributes, namespaceURN, clusterURN)
	return identityProjectionResult(entities, links)
}

func kubernetesRBACBindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	bindingURN := kubernetesRBACBindingURN(tenantID, attributes)
	roleURN := kubernetesRBACBindingRoleURN(tenantID, attributes)
	namespaceURN := kubernetesExplicitNamespaceURN(tenantID, attributes)
	clusterURN := kubernetesClusterURN(tenantID, attributes)
	if bindingURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        bindingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.rbac_binding",
			Label:      firstNonEmpty(attributes["binding_name"], attributes["resource_name"], attributes["name"]),
			Attributes: map[string]string{
				"binding_kind":  strings.TrimSpace(attributes["binding_kind"]),
				"binding_name":  firstNonEmpty(attributes["binding_name"], attributes["resource_name"], attributes["name"]),
				"binding_scope": kubernetesRBACScope(attributes),
				"cluster_id":    strings.TrimSpace(attributes["cluster_id"]),
				"cluster_name":  strings.TrimSpace(attributes["cluster_name"]),
				"namespace":     strings.TrimSpace(attributes["namespace"]),
				"role_kind":     strings.TrimSpace(attributes["role_kind"]),
				"role_name":     strings.TrimSpace(attributes["role_name"]),
				"subject_refs":  strings.TrimSpace(attributes["subject_refs"]),
			},
		})
	}
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kubernetes.rbac_role",
			Label:      strings.TrimSpace(attributes["role_name"]),
			Attributes: map[string]string{
				"cluster_id":   strings.TrimSpace(attributes["cluster_id"]),
				"cluster_name": strings.TrimSpace(attributes["cluster_name"]),
				"namespace":    kubernetesRBACRoleNamespace(attributes),
				"role_kind":    strings.TrimSpace(attributes["role_kind"]),
				"role_name":    strings.TrimSpace(attributes["role_name"]),
			},
		})
	}
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), attributes, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), attributes, namespaceURN)
	if bindingURN != "" && roleURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), bindingURN, roleURN, relationAttachedTo, map[string]string{"event_id": event.GetId(), "match_type": "kubernetes_rbac_binding_role"}))
	}
	if bindingURN != "" {
		if kubernetesRBACScope(attributes) == "namespace" && namespaceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), bindingURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if clusterURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), bindingURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	for _, subject := range parseKubernetesRBACSubjectRefs(attributes["subject_refs"]) {
		subjectURN := kubernetesRBACSubjectURN(tenantID, attributes, subject)
		if subjectURN == "" {
			continue
		}
		addKubernetesRBACSubjectEntity(entities, tenantID, event.GetSourceId(), attributes, subject, subjectURN)
		if roleURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, roleURN, relationAssignedTo, map[string]string{
				"binding_kind": strings.TrimSpace(attributes["binding_kind"]),
				"binding_name": strings.TrimSpace(attributes["binding_name"]),
				"event_id":     event.GetId(),
				"match_type":   "kubernetes_rbac_binding_subject",
			}))
		}
		if normalizeIdentifier(subject.Kind) == "serviceaccount" || normalizeIdentifier(subject.Kind) == "service_account" {
			subjectNamespaceURN := kubernetesRBACSubjectNamespaceURN(tenantID, attributes, subject)
			if subjectNamespaceURN != "" {
				subjectNamespaceAttrs := cloneAttributes(attributes)
				subjectNamespaceAttrs["namespace"] = kubernetesRBACSubjectNamespace(attributes, subject)
				addKubernetesNamespace(entities, tenantID, event.GetSourceId(), subjectNamespaceAttrs, subjectNamespaceURN)
				addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, subjectNamespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
				if clusterURN != "" {
					addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectNamespaceURN, clusterURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
				}
			}
		}
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

func kubernetesExplicitNamespaceURN(tenantID string, attributes map[string]string) string {
	if strings.TrimSpace(attributes["namespace"]) == "" {
		return ""
	}
	return kubernetesNamespaceURN(tenantID, attributes)
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

func kubernetesRBACRoleURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	roleName := firstNonEmpty(attributes["role_name"], attributes["resource_name"], attributes["name"])
	roleKind := firstNonEmpty(attributes["role_kind"], "Role")
	if clusterID == "" || roleName == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_rbac_role", clusterID, roleKind, firstNonEmpty(kubernetesRBACRoleNamespace(attributes), "cluster"), roleName)
}

func kubernetesRBACBindingURN(tenantID string, attributes map[string]string) string {
	clusterID := kubernetesClusterIdentity(attributes)
	bindingName := firstNonEmpty(attributes["binding_name"], attributes["resource_name"], attributes["name"])
	bindingKind := firstNonEmpty(attributes["binding_kind"], "RoleBinding")
	if clusterID == "" || bindingName == "" {
		return ""
	}
	return projectionURN(tenantID, "kubernetes_rbac_binding", clusterID, bindingKind, firstNonEmpty(strings.TrimSpace(attributes["namespace"]), "cluster"), bindingName)
}

func kubernetesRBACBindingRoleURN(tenantID string, attributes map[string]string) string {
	roleName := strings.TrimSpace(attributes["role_name"])
	if roleName == "" {
		return ""
	}
	roleAttrs := cloneAttributes(attributes)
	roleAttrs["role_name"] = roleName
	roleAttrs["role_kind"] = firstNonEmpty(attributes["role_kind"], "Role")
	if !strings.EqualFold(roleAttrs["role_kind"], "ClusterRole") {
		roleAttrs["namespace"] = firstNonEmpty(attributes["namespace"], "default")
	} else {
		roleAttrs["namespace"] = ""
	}
	return kubernetesRBACRoleURN(tenantID, roleAttrs)
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

type kubernetesRBACSubjectRef struct {
	Kind      string
	Namespace string
	Name      string
}

func parseKubernetesRBACSubjectRefs(raw string) []kubernetesRBACSubjectRef {
	refs := []kubernetesRBACSubjectRef{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kind, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		namespace := ""
		name := strings.TrimSpace(value)
		if isKubernetesServiceAccountKind(kind) {
			if before, after, found := strings.Cut(name, "/"); found {
				namespace = strings.TrimSpace(before)
				name = strings.TrimSpace(after)
			}
		}
		if strings.TrimSpace(kind) == "" || name == "" {
			continue
		}
		refs = append(refs, kubernetesRBACSubjectRef{Kind: strings.TrimSpace(kind), Namespace: namespace, Name: name})
	}
	return refs
}

func isKubernetesServiceAccountKind(kind string) bool {
	normalized := normalizeIdentifier(kind)
	return normalized == "serviceaccount" || normalized == "service_account"
}

func kubernetesRBACSubjectNamespace(attributes map[string]string, subject kubernetesRBACSubjectRef) string {
	if !isKubernetesServiceAccountKind(subject.Kind) {
		return ""
	}
	return firstNonEmpty(subject.Namespace, attributes["namespace"], "default")
}

func kubernetesRBACSubjectNamespaceURN(tenantID string, attributes map[string]string, subject kubernetesRBACSubjectRef) string {
	namespace := kubernetesRBACSubjectNamespace(attributes, subject)
	if namespace == "" {
		return ""
	}
	subjectNamespaceAttrs := cloneAttributes(attributes)
	subjectNamespaceAttrs["namespace"] = namespace
	return kubernetesNamespaceURN(tenantID, subjectNamespaceAttrs)
}

func kubernetesRBACSubjectURN(tenantID string, attributes map[string]string, subject kubernetesRBACSubjectRef) string {
	clusterID := kubernetesClusterIdentity(attributes)
	if clusterID == "" || strings.TrimSpace(subject.Name) == "" {
		return ""
	}
	switch normalizeIdentifier(subject.Kind) {
	case "serviceaccount", "service_account":
		return projectionURN(tenantID, "kubernetes_service_account", clusterID, kubernetesRBACSubjectNamespace(attributes, subject), subject.Name)
	case "group":
		return projectionURN(tenantID, "kubernetes_group", clusterID, subject.Name)
	default:
		return projectionURN(tenantID, "kubernetes_user", clusterID, subject.Name)
	}
}

func addKubernetesRBACSubjectEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attributes map[string]string, subject kubernetesRBACSubjectRef, subjectURN string) {
	clusterID := kubernetesClusterIdentity(attributes)
	switch normalizeIdentifier(subject.Kind) {
	case "serviceaccount", "service_account":
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.service_account",
			Label:      subject.Name,
			Attributes: map[string]string{
				"cluster_id":           clusterID,
				"cluster_name":         strings.TrimSpace(attributes["cluster_name"]),
				"namespace":            kubernetesRBACSubjectNamespace(attributes, subject),
				"service_account_name": subject.Name,
			},
		})
	case "group":
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.group",
			Label:      subject.Name,
			Attributes: map[string]string{"cluster_id": clusterID, "cluster_name": strings.TrimSpace(attributes["cluster_name"]), "group_name": subject.Name},
		})
	default:
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.user",
			Label:      subject.Name,
			Attributes: map[string]string{"cluster_id": clusterID, "cluster_name": strings.TrimSpace(attributes["cluster_name"]), "user_name": subject.Name},
		})
	}
}

func kubernetesRBACRoleNamespace(attributes map[string]string) string {
	if strings.EqualFold(firstNonEmpty(attributes["role_kind"], "Role"), "ClusterRole") {
		return ""
	}
	return strings.TrimSpace(attributes["namespace"])
}

func kubernetesRBACScope(attributes map[string]string) string {
	if bindingKind := strings.TrimSpace(attributes["binding_kind"]); bindingKind != "" {
		if strings.EqualFold(bindingKind, "ClusterRoleBinding") || strings.TrimSpace(attributes["namespace"]) == "" {
			return "cluster"
		}
		return "namespace"
	}
	if strings.TrimSpace(attributes["namespace"]) == "" || strings.EqualFold(firstNonEmpty(attributes["role_kind"], "Role"), "ClusterRole") {
		return "cluster"
	}
	return "namespace"
}
