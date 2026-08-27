package sourceprojection

import (
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitytooling"
)

// backstageComponentProjections and its exclusive helpers (the Backstage
// entity-ref/Kubernetes-link/classification machinery below) previously
// lived here. Backstage's Go projection writer was retired to Rust authority
// (internal/sourceprojection/backstage.go now fails closed for
// backstage.component), so the real implementation was removed to avoid
// redeclaring it. addOwnerLink and addRepoLink stay: securityToolingMapToolProjections
// below still uses them.

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
