package sourceprojection

import (
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitytooling"
)

const relationDependsOn = "depends_on"

func backstageComponentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	name := firstNonEmpty(attrs["name"], nestedString(payload, "metadata.name"))
	if name == "" {
		return nil, nil, nil
	}
	kind := firstNonEmpty(attrs["kind"], nestedString(payload, "kind"), "Component")
	namespace := firstNonEmpty(attrs["namespace"], nestedString(payload, "metadata.namespace"), "default")
	entityRef := firstNonEmpty(attrs["entity_ref"], backstageEntityRef(kind, namespace, name))
	componentURN := projectionURN(tenantID, "service", strings.ToLower(entityRef))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        componentURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: backstageComponentEntityType(attrs["type"]),
		Label:      name,
		Attributes: compactAttributes(map[string]string{
			"backstage_entity_ref": entityRef,
			"backstage_kind":       kind,
			"name":                 name,
			"namespace":            namespace,
			"type":                 attrs["type"],
			"lifecycle":            attrs["lifecycle"],
			"description":          attrs["description"],
			"criticality":          attrs["criticality"],
			"data_class":           attrs["data_class"],
			"score_grade":          attrs["score_grade"],
			"source_product":       attrs["source_product"],
			"source_url":           attrs["source_url"],
		}),
	})
	addOwnerLink(entities, links, event, tenantID, componentURN, firstNonEmpty(attrs["owner"], nestedString(payload, "spec.owner")))
	addBackstageClassificationLinks(entities, links, event, tenantID, componentURN, attrs)
	addSystemLink(entities, links, event, tenantID, componentURN, firstNonEmpty(attrs["system"], nestedString(payload, "spec.system")))
	addRepoLink(entities, links, event, tenantID, componentURN, firstNonEmpty(
		attrs["repository"],
		backstageAnnotation(payload, "github.com/project-slug"),
		attrs["source_url"],
		backstageAnnotation(payload, "backstage.io/source-location"),
	))
	addBackstageKubernetesLinks(entities, links, event, tenantID, componentURN, attrs, payload)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addBackstageClassificationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, componentURN string, attrs map[string]string) {
	for _, classification := range splitCSV(attrs["data_class"]) {
		classificationURN := projectionURN(tenantID, "data_classification", classification)
		if classificationURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        classificationURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "data.classification",
			Label:      classification,
			Attributes: map[string]string{"classification": classification},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, classificationURN, relationHasClassification, map[string]string{"event_id": event.GetId(), "source_attribute": "data_class"}))
	}
	for _, criticality := range splitCSV(attrs["criticality"]) {
		tagValue := "criticality:" + normalizeIdentifier(criticality)
		tagURN := projectionURN(tenantID, "asset_tag", tagValue)
		if tagURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tagURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "asset.tag",
			Label:      tagValue,
			Attributes: map[string]string{"criticality": criticality, "tag": tagValue},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, tagURN, relationTaggedAs, map[string]string{"event_id": event.GetId(), "source_attribute": "criticality"}))
		if backstageCriticalityIsCrownJewel(criticality) {
			crownJewelURN := projectionURN(tenantID, "asset_tag", "crown_jewel")
			addEntity(entities, &ports.ProjectedEntity{
				URN:        crownJewelURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "asset.tag",
				Label:      "crown_jewel",
				Attributes: map[string]string{"tag": "crown_jewel"},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, crownJewelURN, relationTaggedAs, map[string]string{"event_id": event.GetId(), "source_attribute": "criticality"}))
		}
	}
}

func backstageCriticalityIsCrownJewel(value string) bool {
	switch normalizeIdentifier(value) {
	case "crown_jewel", "crown-jewel", "tier0", "tier_0", "tier-0", "critical":
		return true
	default:
		return false
	}
}

func securityToolingMapToolProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	toolID := firstNonEmpty(attrs["tool_id"], attrs["external_id"], attrs["name"])
	if toolID == "" {
		return nil, nil, nil
	}
	toolURN := projectionURN(tenantID, "security_tool", toolID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        toolURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "security.tool",
		Label:      firstNonEmpty(attrs["name"], toolID),
		Attributes: compactAttributes(map[string]string{
			"tool_id":          toolID,
			"name":             attrs["name"],
			"status":           attrs["status"],
			"primary_language": attrs["primary_language"],
			"url":              attrs["url"],
			"agent_role":       attrs["agent_role"],
			"surfaces":         attrs["surfaces"],
			"capabilities":     attrs["capabilities"],
			"consumed_by":      attrs["consumed_by"],
			"source_product":   attrs["source_product"],
		}),
	})
	addOwnerLink(entities, links, event, tenantID, toolURN, attrs["lifecycle_owner"])
	addRepoLink(entities, links, event, tenantID, toolURN, repositoryFromTool(attrs))
	for _, category := range splitCSV(attrs["categories"]) {
		categoryURN := projectionURN(tenantID, "security_category", category)
		addEntity(entities, &ports.ProjectedEntity{URN: categoryURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "security.category", Label: category, Attributes: map[string]string{"category": category}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), toolURN, categoryURN, relationHasClassification, map[string]string{"event_id": event.GetId()}))
	}
	for _, dependency := range splitCSV(attrs["depends_on"]) {
		dependencyURN := projectionURN(tenantID, "security_tool", dependency)
		addEntity(entities, &ports.ProjectedEntity{URN: dependencyURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "security.tool", Label: dependency, Attributes: map[string]string{"tool_id": dependency}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), toolURN, dependencyURN, relationDependsOn, map[string]string{"event_id": event.GetId()}))
	}
	for _, consumer := range splitCSV(attrs["consumed_by"]) {
		consumerURN := projectionURN(tenantID, "security_tool", consumer)
		addEntity(entities, &ports.ProjectedEntity{URN: consumerURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "security.tool", Label: consumer, Attributes: map[string]string{"tool_id": consumer}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), consumerURN, toolURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "relationship": "consumed_by"}))
	}
	for _, overlap := range splitCSV(attrs["overlaps_with"]) {
		overlapURN := projectionURN(tenantID, "security_tool", overlap)
		addEntity(entities, &ports.ProjectedEntity{URN: overlapURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "security.tool", Label: overlap, Attributes: map[string]string{"tool_id": overlap}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), toolURN, overlapURN, relationAffects, map[string]string{"event_id": event.GetId(), "relationship": "overlaps_with"}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func securityToolingMapControlMappingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	toolID := firstNonEmpty(attrs["tool_id"], attrs["tool_name"])
	controlID := attrs["control_id"]
	if toolID == "" || controlID == "" {
		return nil, nil, nil
	}
	toolURN := projectionURN(tenantID, "security_tool", toolID)
	controlURN := projectionURN(tenantID, "control", firstNonEmpty(attrs["framework"], "security"), controlID)
	coverageStatus := firstNonEmpty(attrs["coverage_status"], securitytooling.CoverageStatus(attrs["coverage"]))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: toolURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "security.tool", Label: toolID, Attributes: map[string]string{"tool_id": toolID}})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        controlURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "control",
		Label:      firstNonEmpty(attrs["control_name"], controlID),
		Attributes: compactAttributes(map[string]string{
			"control_id":      controlID,
			"control_name":    attrs["control_name"],
			"framework":       attrs["framework"],
			"coverage":        attrs["coverage"],
			"coverage_status": coverageStatus,
			"control_status":  attrs["control_status"],
		}),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), toolURN, controlURN, relationSupports, compactAttributes(map[string]string{
		"event_id":         event.GetId(),
		"coverage":         attrs["coverage"],
		"coverage_status":  coverageStatus,
		"evidence_surface": attrs["evidence_surface"],
	})))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addOwnerLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, fromURN string, owner string) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return
	}
	ownerURN := projectionURN(tenantID, "owner", normalizeBackstageRef(owner))
	addEntity(entities, &ports.ProjectedEntity{URN: ownerURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "owner", Label: ownerLabel(owner), Attributes: map[string]string{"owner": owner}})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	addOwnerIdentityLinks(entities, links, event, tenantID, ownerURN, owner)
}

func addSystemLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, fromURN string, system string) {
	system = strings.TrimSpace(system)
	if system == "" {
		return
	}
	systemURN := projectionURN(tenantID, "system", normalizeBackstageRef(system))
	addEntity(entities, &ports.ProjectedEntity{URN: systemURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "system", Label: ownerLabel(system), Attributes: map[string]string{"system": system}})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, systemURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
}

func addRepoLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, fromURN string, repository string) {
	repository = strings.TrimSpace(repository)
	if normalized := normalizeGitHubRepository(repository); normalized != "" {
		repository = normalized
	}
	if repository == "" {
		return
	}
	owner, _, hasOwner := strings.Cut(repository, "/")
	owner = strings.TrimSpace(owner)
	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	repoAttrs := map[string]string{"repository": repository}
	if hasOwner && owner != "" {
		repoAttrs["owner_login"] = owner
	}
	addEntity(entities, &ports.ProjectedEntity{URN: repoURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "github.code.repository", Label: repository, Attributes: repoAttrs})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "repository"}))
	if !hasOwner || owner == "" {
		return
	}
	orgURN := projectionURN(tenantID, "github_org", owner)
	addEntity(entities, &ports.ProjectedEntity{URN: orgURN, TenantID: tenantID, SourceID: "github", EntityType: "github.org", Label: owner, Attributes: map[string]string{"org": owner, "owner_login": owner}})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{
		"event_id":     event.GetId(),
		"match_type":   "repository_owner",
		"owner_login":  owner,
		"source_scope": "repository_name",
	}))
}

func addOwnerIdentityLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, ownerURN string, owner string) {
	for _, candidate := range ownerIdentifierCandidates(owner) {
		if extractEmailIdentifier(candidate) != "" || strings.HasPrefix(strings.ToLower(strings.TrimSpace(owner)), "user:") {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), ownerURN, candidate, event.GetOccurredAt())
			continue
		}
		addOwnerIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), ownerURN, candidate, event.GetOccurredAt())
	}
}

func addOwnerIdentifierLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, ownerURN string, value string, occurredAt *timestamppb.Timestamp) {
	identifierURN, identifierType, label := identifierURN(tenantID, value)
	if identifierURN == "" || strings.TrimSpace(ownerURN) == "" {
		return
	}
	attributes := identifierEvidenceAttributes(value, identifierType, label, eventID, occurredAt)
	attributes["match_type"] = "backstage_owner_identifier"
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identifierURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: identifierType,
		Label:      label,
		Attributes: map[string]string{"value": label},
	})
	addLink(links, projectedLink(tenantID, sourceID, ownerURN, identifierURN, relationHasIdentifier, attributes))
}

func ownerIdentifierCandidates(owner string) []string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil
	}
	candidates := []string{}
	if email := extractEmailIdentifier(owner); email != "" {
		candidates = append(candidates, email)
	} else {
		normalized := normalizeBackstageRef(owner)
		if normalized != "" {
			candidates = append(candidates, normalized)
		}
		label := ownerLabel(owner)
		if label != "" {
			candidates = append(candidates, label)
		}
	}
	out := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		key := normalizeIdentifier(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func addBackstageKubernetesLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, componentURN string, attrs map[string]string, payload map[string]any) {
	kubernetesID := firstNonEmpty(
		attrs["kubernetes_id"],
		attrs["kubernetes-id"],
		backstageAnnotation(payload, "backstage.io/kubernetes-id"),
		backstageAnnotation(payload, "cerebro.io/kubernetes-id"),
	)
	workloadName := firstNonEmpty(
		attrs["workload_name"],
		attrs["kubernetes_workload_name"],
		attrs["kubernetes_name"],
		kubernetesID,
	)
	clusterID := firstNonEmpty(
		attrs["cluster_id"],
		attrs["kubernetes_cluster_id"],
		backstageAnnotation(payload, "cerebro.io/kubernetes-cluster-id"),
		backstageAnnotation(payload, "backstage.io/kubernetes-cluster-id"),
	)
	clusterName := firstNonEmpty(
		attrs["cluster_name"],
		attrs["kubernetes_cluster_name"],
		backstageAnnotation(payload, "cerebro.io/kubernetes-cluster-name"),
		backstageAnnotation(payload, "backstage.io/kubernetes-cluster-name"),
	)
	cloudProvider := firstNonEmpty(
		attrs["cloud_provider"],
		attrs["provider"],
		backstageAnnotation(payload, "cerebro.io/cloud-provider"),
	)
	cloudAccountID := firstNonEmpty(
		attrs["cloud_account_id"],
		attrs["aws_account_id"],
		attrs["gcp_project_id"],
		attrs["project_id"],
		backstageAnnotation(payload, "cerebro.io/cloud-account-id"),
		backstageAnnotation(payload, "cerebro.io/aws-account-id"),
		backstageAnnotation(payload, "cerebro.io/gcp-project-id"),
	)
	if strings.TrimSpace(workloadName) == "" || (strings.TrimSpace(clusterID) == "" && (strings.TrimSpace(clusterName) == "" || strings.TrimSpace(cloudAccountID) == "")) {
		return
	}
	kubernetesAttrs := map[string]string{
		"account_id":           cloudAccountID,
		"aws_account_id":       cloudAccountID,
		"cloud_account_id":     cloudAccountID,
		"cloud_provider":       cloudProvider,
		"cluster_id":           clusterID,
		"cluster_name":         clusterName,
		"gcp_project_id":       cloudAccountID,
		"namespace":            firstNonEmpty(backstageAnnotation(payload, "backstage.io/kubernetes-namespace"), backstageAnnotation(payload, "cerebro.io/kubernetes-namespace"), attrs["kubernetes_namespace"], attrs["namespace"], "default"),
		"provider":             cloudProvider,
		"service_account_name": firstNonEmpty(attrs["service_account_name"], attrs["kubernetes_service_account"], backstageAnnotation(payload, "cerebro.io/kubernetes-service-account")),
		"workload_kind":        firstNonEmpty(attrs["workload_kind"], attrs["kubernetes_workload_kind"], backstageAnnotation(payload, "cerebro.io/kubernetes-workload-kind"), "Deployment"),
		"workload_name":        workloadName,
		"workload_uid":         attrs["workload_uid"],
	}
	workloadURN := kubernetesWorkloadURN(tenantID, kubernetesAttrs)
	if workloadURN == "" {
		return
	}
	namespaceURN := kubernetesNamespaceURN(tenantID, kubernetesAttrs)
	clusterURN := kubernetesClusterURN(tenantID, kubernetesAttrs)
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, kubernetesAttrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        workloadURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "kubernetes.workload",
		Label:      workloadName,
		Attributes: compactAttributes(kubernetesAttrs),
	})
	addKubernetesCluster(entities, tenantID, event.GetSourceId(), kubernetesAttrs, clusterURN)
	addKubernetesNamespace(entities, tenantID, event.GetSourceId(), kubernetesAttrs, namespaceURN)
	if serviceAccountURN != "" && strings.TrimSpace(kubernetesAttrs["service_account_name"]) != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: serviceAccountURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "kubernetes.service_account", Label: kubernetesAttrs["service_account_name"]})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, serviceAccountURN, relationRunsAs, map[string]string{"event_id": event.GetId(), "match_type": "backstage_kubernetes_service_account"}))
	}
	if namespaceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, namespaceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "backstage_kubernetes_namespace"}))
	}
	addKubernetesClusterLinks(entities, links, tenantID, event.GetSourceId(), event, kubernetesAttrs, namespaceURN, clusterURN)
	attrsOut := map[string]string{"event_id": event.GetId(), "match_type": "backstage_kubernetes_workload"}
	addProjectedAttribute(attrsOut, "kubernetes_id", kubernetesID)
	addProjectedAttribute(attrsOut, "workload_kind", kubernetesAttrs["workload_kind"])
	addProjectedAttribute(attrsOut, "workload_name", workloadName)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, workloadURN, relationRepresents, attrsOut))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), workloadURN, componentURN, relationRepresents, attrsOut))
}

func backstageComponentEntityType(componentType string) string {
	if strings.EqualFold(strings.TrimSpace(componentType), "service") {
		return "service"
	}
	return "backstage.component"
}

func backstageEntityRef(kind string, namespace string, name string) string {
	return strings.ToLower(firstNonEmpty(kind, "Component")) + "/" + strings.ToLower(firstNonEmpty(namespace, "default")) + "/" + strings.ToLower(strings.TrimSpace(name))
}

func backstageAnnotation(payload map[string]any, key string) string {
	annotations, ok := nestedValue(payload, "metadata.annotations").(map[string]any)
	if !ok {
		return ""
	}
	value, _ := annotations[key].(string)
	return strings.TrimSpace(value)
}

func repositoryFromTool(attrs map[string]string) string {
	if repository := strings.TrimSpace(attrs["repository"]); repository != "" {
		return repository
	}
	repo := strings.TrimSpace(attrs["repo"])
	org := strings.TrimSpace(attrs["org"])
	if repo == "" || strings.Contains(repo, "/") || org == "" {
		return repo
	}
	return org + "/" + repo
}

func nestedString(values map[string]any, path string) string {
	value, _ := nestedValue(values, path).(string)
	return strings.TrimSpace(value)
}

func nestedValue(values map[string]any, path string) any {
	var current any = values
	for _, part := range strings.Split(strings.TrimSpace(path), ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func compactAttributes(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		addProjectedAttribute(out, key, value)
	}
	return out
}

func splitCSV(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func normalizeBackstageRef(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "group:")
	value = strings.TrimPrefix(value, "user:")
	return value
}

func ownerLabel(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "group:")
	value = strings.TrimPrefix(value, "user:")
	if index := strings.LastIndex(value, "/"); index >= 0 && index < len(value)-1 {
		return value[index+1:]
	}
	return value
}
