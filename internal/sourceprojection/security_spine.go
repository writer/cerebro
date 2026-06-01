package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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
		}),
	})
	addOwnerLink(entities, links, event, tenantID, componentURN, firstNonEmpty(attrs["owner"], nestedString(payload, "spec.owner")))
	addSystemLink(entities, links, event, tenantID, componentURN, firstNonEmpty(attrs["system"], nestedString(payload, "spec.system")))
	addRepoLink(entities, links, event, tenantID, componentURN, firstNonEmpty(attrs["repository"], backstageAnnotation(payload, "github.com/project-slug")))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
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
			"control_id":   controlID,
			"control_name": attrs["control_name"],
			"framework":    attrs["framework"],
			"coverage":     attrs["coverage"],
		}),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), toolURN, controlURN, relationSupports, map[string]string{
		"event_id":         event.GetId(),
		"coverage":         attrs["coverage"],
		"evidence_surface": attrs["evidence_surface"],
	}))
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
	if extractEmailIdentifier(owner) != "" {
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), ownerURN, owner, event.GetOccurredAt())
	}
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
	if repository == "" {
		return
	}
	owner, _, hasOwner := strings.Cut(repository, "/")
	owner = strings.TrimSpace(owner)
	repoURN := projectionURN(tenantID, "github_repo", repository)
	repoAttrs := map[string]string{"repository": repository}
	if hasOwner && owner != "" {
		repoAttrs["owner_login"] = owner
	}
	addEntity(entities, &ports.ProjectedEntity{URN: repoURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "github.repo", Label: repository, Attributes: repoAttrs})
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
