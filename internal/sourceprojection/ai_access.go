package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type aiAccessProfile struct {
	Provider string
}

var langfuseAccessProfile = aiAccessProfile{Provider: "langfuse"}

// anthropic and langchain used to have their own profile-based wrappers here
// (anthropicAccessProfile, langChainAccessProfile). Both sources became fully
// Rust-authoritative and their Go projection writers were retired
// (internal/sourceprojection/anthropic.go, internal/sourceprojection/langchain.go
// now fail closed under those exact function names), so the wrappers were
// removed from this file to avoid redeclaring them. Test coverage for the
// generic helpers below via anthropic's richer fixture shapes now runs
// through the anthropicOracle* wrappers in openai_oracle_test.go, the same
// pattern already used to keep exercising this shared logic after OpenAI's
// own Go projection writer was retired.

func langfuseProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectProjections(event, langfuseAccessProfile)
}

func langfuseProjectMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectCollaboratorProjections(event, langfuseAccessProfile)
}

func langfuseCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiCredentialProjections(event, langfuseAccessProfile)
}

func langfuseUsageMetricProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUsageMetricProjections(event, langfuseAccessProfile)
}

func aiProjectProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, attrs)
	if projectURN != "" && orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), projectURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "project_organization")))
	}
	return identityProjectionResult(entities, links)
}

func aiCredentialProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	credentialID := firstNonEmpty(attrs["api_key_id"], attrs["external_key_id"], attrs["credential_id"], attrs["id"])
	if strings.TrimSpace(credentialID) == "" {
		return identityProjectionResult(entities, links)
	}
	credentialURN := projectionURN(tenantID, profile.Provider+"_credential", credentialID)
	if credentialURN == "" {
		return identityProjectionResult(entities, links)
	}
	credentialType := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(event.GetKind()), profile.Provider+"."), "project_")
	if credentialType == "" {
		credentialType = "credential"
	}
	scopeKind := aiCredentialScopeKind(attrs, event.GetKind())
	credentialAttrs := aiCredentialAttributes(attrs, credentialID, credentialType, true)
	addProjectedAttribute(credentialAttrs, "scope_kind", scopeKind)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        credentialURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + ".credential",
		Label:      firstNonEmpty(attrs["name"], credentialID),
		Attributes: credentialAttrs,
	})
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	if scopeURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, scopeURN, relationCanPerform, aiEventLinkAttributes(event, "credential_scope")))
	}
	ownerURN := aiCredentialOwnerURN(entities, links, tenantID, event, profile, attrs)
	if ownerURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), ownerURN, credentialURN, relationAssignedTo, aiEventLinkAttributes(event, "credential_owner")))
	}
	return identityProjectionResult(entities, links)
}

func aiProjectCollaboratorProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, attrs)
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	if projectURN != "" && orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), projectURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "project_organization")))
	}
	roleID := aiRoleID(attrs)
	if roleID == "" {
		return identityProjectionResult(entities, links)
	}
	roleName := firstNonEmpty(attrs["role_name"], attrs["role"], roleID)
	roleAttrs := aiScopedRoleAttributes(attrs, roleID)
	roleAttrs["name"] = roleName
	roleAttrs["role_name"] = roleName
	roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, "project")
	principalType := aiProjectCollaboratorPrincipalType(attrs)
	principalID := aiProjectCollaboratorPrincipalID(attrs, principalType)
	principalURN := aiEnsureProjectCollaboratorPrincipal(entities, links, tenantID, event, profile, principalType, principalID, roleName)
	if principalURN != "" && roleURN != "" {
		linkAttrs := aiEventLinkAttributes(event, "project_collaborator_role")
		addProjectedAttribute(linkAttrs, "principal_type", principalType)
		addProjectedAttribute(linkAttrs, "principal_id", principalID)
		addProjectedAttribute(linkAttrs, "role_id", roleID)
		addProjectedAttribute(linkAttrs, "role", roleName)
		addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(firstNonEmpty(roleName, roleID))))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, roleURN, aiRoleAssignmentRelation(firstNonEmpty(roleName, roleID)), linkAttrs))
	}
	aiLinkRoleToScope(links, tenantID, event, roleURN, projectURN, firstNonEmpty(roleName, roleID), "project_collaborator_role_scope")
	aiLinkPrincipalToScope(links, tenantID, event, principalURN, projectURN, firstNonEmpty(roleName, roleID), "project_collaborator_project_access")
	return identityProjectionResult(entities, links)
}

func aiUsageMetricProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	family := aiFamily(event, profile)
	metricID := aiUsageMetricID(family, attrs, event.GetId())
	if metricID == "" {
		return identityProjectionResult(entities, links)
	}
	metricType := aiUsageMetricType(family)
	metricURN := projectionURN(tenantID, profile.Provider+"_"+family, strings.Split(metricID, "|")...)
	metricAttrs := cloneAttributes(attrs)
	metricAttrs["event_kind"] = event.GetKind()
	metricAttrs["source_event_id"] = event.GetId()
	addProjectedAttribute(metricAttrs, "metric_id", metricID)
	addProjectedAttribute(metricAttrs, "metric_type", metricType)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        metricURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + "." + family,
		Label:      aiUsageMetricLabel(family, attrs, metricID),
		Attributes: metricAttrs,
	})
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	if orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, orgURN, relationBelongsTo, aiUsageMetricLinkAttributes(event, "usage_metric_organization", family, metricType)))
	}
	if projectID := strings.TrimSpace(attrs["project_id"]); projectID != "" {
		projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, attrs)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, projectURN, relationObservedOn, aiUsageMetricLinkAttributes(event, "usage_metric_project", family, metricType)))
	}
	if workspaceID := strings.TrimSpace(attrs["workspace_id"]); workspaceID != "" {
		workspaceURN := aiEnsureWorkspace(entities, tenantID, event.GetSourceId(), profile, attrs)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, workspaceURN, relationObservedOn, aiUsageMetricLinkAttributes(event, "usage_metric_workspace", family, metricType)))
	}
	if userID := strings.TrimSpace(attrs["user_id"]); userID != "" || strings.TrimSpace(attrs["email"]) != "" {
		userURN := aiEnsureUser(entities, links, tenantID, event, profile, userID, attrs["email"], attrs["name"], "")
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, userURN, relationObservedOn, aiUsageMetricLinkAttributes(event, "usage_metric_user", family, metricType)))
	}
	if apiKeyID := strings.TrimSpace(attrs["api_key_id"]); apiKeyID != "" {
		credentialURN := aiEnsureCredential(entities, tenantID, event.GetSourceId(), profile, apiKeyID, attrs)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, credentialURN, relationObservedOn, aiUsageMetricLinkAttributes(event, "usage_metric_credential", family, metricType)))
	}
	for _, modelID := range aiGovernanceControlModels(attrs) {
		modelURN := projectionURN(tenantID, profile.Provider+"_model", modelID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        modelURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".model",
			Label:      modelID,
			Attributes: map[string]string{"model_id": modelID},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), metricURN, modelURN, relationAssociatedWith, aiUsageMetricLinkAttributes(event, "usage_metric_model", family, metricType)))
	}
	return identityProjectionResult(entities, links)
}

func aiEnsureOrganization(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string) string {
	orgID := firstNonEmpty(attrs["organization_id"], attrs["organization_uuid"], attrs["org_id"], attrs[ports.EventAttributeSourceRuntimeID], profile.Provider)
	orgURN := projectionURN(tenantID, profile.Provider+"_org", orgID)
	if orgURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: profile.Provider + ".org",
			Label:      firstNonEmpty(attrs["name"], attrs["organization_name"], orgID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"organization_id":   strings.TrimSpace(attrs["organization_id"]),
				"organization_uuid": strings.TrimSpace(attrs["organization_uuid"]),
				"name":              strings.TrimSpace(attrs["name"]),
				"type":              strings.TrimSpace(attrs["type"]),
			}),
		})
	}
	return orgURN
}

func aiEnsureProject(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string) string {
	projectID := firstNonEmpty(attrs["project_id"], attrs["id"])
	projectURN := projectionURN(tenantID, profile.Provider+"_project", projectID)
	if projectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        projectURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: profile.Provider + ".project",
			Label:      firstNonEmpty(attrs["name"], projectID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"project_id":      projectID,
				"name":            strings.TrimSpace(attrs["name"]),
				"status":          strings.TrimSpace(attrs["status"]),
				"created_at":      strings.TrimSpace(attrs["created_at"]),
				"archived_at":     strings.TrimSpace(attrs["archived_at"]),
				"external_key_id": strings.TrimSpace(attrs["external_key_id"]),
			}),
		})
	}
	return projectURN
}

func aiEnsureWorkspace(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string) string {
	workspaceID := firstNonEmpty(attrs["workspace_id"], attrs["id"])
	workspaceURN := projectionURN(tenantID, profile.Provider+"_workspace", workspaceID)
	if workspaceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        workspaceURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: profile.Provider + ".workspace",
			Label:      firstNonEmpty(attrs["name"], workspaceID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"workspace_id":  workspaceID,
				"name":          strings.TrimSpace(attrs["name"]),
				"display_color": strings.TrimSpace(attrs["display_color"]),
				"created_at":    strings.TrimSpace(attrs["created_at"]),
				"archived_at":   strings.TrimSpace(attrs["archived_at"]),
			}),
		})
	}
	return workspaceURN
}

func aiEnsureScope(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, scopeKind string, attrs map[string]string) string {
	switch scopeKind {
	case "project":
		return aiEnsureProject(entities, tenantID, sourceID, profile, attrs)
	case "workspace":
		return aiEnsureWorkspace(entities, tenantID, sourceID, profile, attrs)
	default:
		return aiEnsureOrganization(entities, tenantID, sourceID, profile, attrs)
	}
}

func aiEnsureGroup(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string) string {
	groupID := firstNonEmpty(attrs["group_id"], attrs["id"])
	groupURN := identityPrincipalURN(tenantID, profile.Provider, "group", groupID, "")
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: profile.Provider + ".group",
			Label:      firstNonEmpty(attrs["group_name"], attrs["name"], groupID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"group_id":   groupID,
				"group_name": firstNonEmpty(attrs["group_name"], attrs["name"]),
				"created_at": strings.TrimSpace(attrs["created_at"]),
				"updated_at": strings.TrimSpace(attrs["updated_at"]),
			}),
		})
	}
	return groupURN
}

func aiEnsureUser(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, userID string, email string, name string, role string) string {
	userURN := identityPrincipalURN(tenantID, profile.Provider, "user", userID, email)
	if userURN == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        userURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + ".user",
		Label:      firstNonEmpty(name, email, userID),
		Attributes: aiPrincipalAttributes(event.GetAttributes(), map[string]string{
			"principal_type": "user",
			"user_id":        strings.TrimSpace(userID),
			"email":          strings.TrimSpace(email),
			"name":           strings.TrimSpace(name),
			"role":           strings.TrimSpace(role),
			"is_admin":       boolString(aiRoleIsAdmin(role)),
		}),
	})
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
	return userURN
}

func aiEnsureCredential(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, credentialID string, attrs map[string]string) string {
	credentialURN := projectionURN(tenantID, profile.Provider+"_credential", credentialID)
	if credentialURN == "" {
		return ""
	}
	baseAttrs := aiCredentialAttributes(attrs, credentialID, firstNonEmpty(attrs["credential_type"], "credential"), false)
	if credentialID == strings.TrimSpace(firstNonEmpty(attrs["actor_api_key_id"], attrs["actor_admin_api_key_id"])) {
		baseAttrs["actor_user_id"] = strings.TrimSpace(attrs["actor_user_id"])
		baseAttrs["actor_service_account_id"] = strings.TrimSpace(attrs["actor_service_account_id"])
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        credentialURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.Provider + ".credential",
		Label:      credentialID,
		Attributes: baseAttrs,
	})
	return credentialURN
}

func aiCredentialAttributes(attrs map[string]string, credentialID string, credentialType string, allowUserIDOwner bool) map[string]string {
	ownerUserID := firstNonEmpty(attrs["owner_user_id"], aiTypedOwnerID(attrs, "user"))
	if allowUserIDOwner {
		ownerUserID = firstNonEmpty(ownerUserID, attrs["user_id"])
	}
	ownerServiceAccountID := firstNonEmpty(attrs["owner_service_account_id"], aiTypedOwnerID(attrs, "service_account"))
	lastUsedAt := firstNonEmpty(attrs["last_used_at"], attrs["last_used_time"], attrs["last_used"], attrs["end_time"], attrs["start_time"])
	baseAttrs := map[string]string{
		"credential_id":            strings.TrimSpace(credentialID),
		"credential_type":          firstNonEmpty(credentialType, attrs["credential_type"], attrs["key_type"], "credential"),
		"principal_type":           "credential",
		"api_key_id":               strings.TrimSpace(credentialID),
		"external_key_id":          strings.TrimSpace(attrs["external_key_id"]),
		"name":                     strings.TrimSpace(attrs["name"]),
		"status":                   strings.TrimSpace(attrs["status"]),
		"provider":                 strings.TrimSpace(attrs["provider"]),
		"created_at":               strings.TrimSpace(attrs["created_at"]),
		"updated_at":               strings.TrimSpace(attrs["updated_at"]),
		"expires_at":               strings.TrimSpace(attrs["expires_at"]),
		"last_used_at":             strings.TrimSpace(lastUsedAt),
		"key_class":                strings.TrimSpace(attrs["key_class"]),
		"privileged":               strings.TrimSpace(attrs["privileged"]),
		"owner_id":                 strings.TrimSpace(attrs["owner_id"]),
		"owner_type":               strings.TrimSpace(attrs["owner_type"]),
		"owner_object":             strings.TrimSpace(attrs["owner_object"]),
		"owner_name":               strings.TrimSpace(attrs["owner_name"]),
		"owner_role":               strings.TrimSpace(attrs["owner_role"]),
		"owner_user_id":            strings.TrimSpace(ownerUserID),
		"owner_service_account_id": strings.TrimSpace(ownerServiceAccountID),
		"organization_id":          strings.TrimSpace(attrs["organization_id"]),
		"org_id":                   strings.TrimSpace(attrs["org_id"]),
		"project_id":               strings.TrimSpace(attrs["project_id"]),
		"workspace_id":             strings.TrimSpace(attrs["workspace_id"]),
	}
	if firstNonEmpty(ownerUserID, ownerServiceAccountID, attrs["owner_id"]) != "" {
		baseAttrs["has_owner"] = "true"
	} else if allowUserIDOwner {
		baseAttrs["has_owner"] = "false"
	}
	if aiCredentialUsageObserved(attrs) {
		baseAttrs["credential_use"] = "true"
	}
	return aiPrincipalAttributes(attrs, baseAttrs)
}

func aiCredentialUsageObserved(attrs map[string]string) bool {
	family := strings.ToLower(strings.TrimSpace(attrs["family"]))
	if strings.HasPrefix(family, "usage") || strings.Contains(family, "usage_") || strings.Contains(family, "cost") {
		return true
	}
	return firstNonEmpty(
		attrs["input_tokens"],
		attrs["output_tokens"],
		attrs["num_model_requests"],
		attrs["request_count"],
		attrs["cost_usd"],
		attrs["amount"],
		attrs["line_item"],
	) != "" && firstNonEmpty(attrs["start_time"], attrs["end_time"], attrs["model"]) != ""
}

func aiEnsureRole(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string, scopeKind string) string {
	roleID := aiRoleID(attrs)
	if roleID == "" {
		return ""
	}
	roleURN := projectionURN(tenantID, profile.Provider+"_role", scopeKind, roleID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        roleURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.Provider + ".role",
		Label:      firstNonEmpty(attrs["name"], attrs["role_name"], attrs["role"], roleID),
		Attributes: aiPrincipalAttributes(attrs, map[string]string{
			"role_id":         roleID,
			"name":            strings.TrimSpace(attrs["name"]),
			"description":     strings.TrimSpace(attrs["description"]),
			"permissions":     strings.TrimSpace(attrs["permissions"]),
			"resource_type":   strings.TrimSpace(attrs["resource_type"]),
			"predefined_role": strings.TrimSpace(attrs["predefined_role"]),
			"scope_kind":      strings.TrimSpace(scopeKind),
			"is_admin":        boolString(aiRoleIsAdmin(roleID)),
		}),
	})
	return roleURN
}

func aiCredentialOwnerURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, attrs map[string]string) string {
	if ownerServiceAccountID := firstNonEmpty(attrs["owner_service_account_id"], aiTypedOwnerID(attrs, "service_account")); ownerServiceAccountID != "" {
		ownerURN := identityPrincipalURN(tenantID, profile.Provider, "service_account", ownerServiceAccountID, "")
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ownerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".service_account",
			Label:      firstNonEmpty(attrs["owner_name"], ownerServiceAccountID),
			Attributes: map[string]string{"service_account_id": ownerServiceAccountID, "name": strings.TrimSpace(attrs["owner_name"]), "principal_type": "service_account", "role": strings.TrimSpace(attrs["owner_role"])},
		})
		return ownerURN
	}
	if ownerUserID := firstNonEmpty(attrs["owner_user_id"], attrs["user_id"], aiTypedOwnerID(attrs, "user")); ownerUserID != "" || strings.TrimSpace(attrs["email"]) != "" {
		return aiEnsureUser(entities, links, tenantID, event, profile, ownerUserID, attrs["email"], attrs["owner_name"], "")
	}
	return ""
}

func aiTypedOwnerID(attrs map[string]string, wantType string) string {
	ownerID := strings.TrimSpace(attrs["owner_id"])
	if ownerID == "" {
		return ""
	}
	ownerType := strings.ToLower(strings.TrimSpace(attrs["owner_type"]))
	ownerObject := strings.ToLower(strings.TrimSpace(attrs["owner_object"]))
	switch wantType {
	case "service_account":
		if ownerType == "service_account" || strings.Contains(ownerObject, "service_account") {
			return ownerID
		}
	case "user":
		if ownerType == "user" || strings.Contains(ownerObject, ".user") {
			return ownerID
		}
	}
	return ""
}

func aiCredentialScopeKind(attrs map[string]string, kind string) string {
	switch {
	case strings.TrimSpace(attrs["project_id"]) != "":
		return "project"
	case strings.TrimSpace(attrs["workspace_id"]) != "":
		return "workspace"
	case strings.Contains(kind, "project_"):
		return "project"
	default:
		return "organization"
	}
}

func aiLinkPrincipalToScope(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, principalURN string, scopeURN string, role string, matchType string) {
	if principalURN == "" || scopeURN == "" {
		return
	}
	linkAttrs := aiEventLinkAttributes(event, matchType)
	addProjectedAttribute(linkAttrs, "role", role)
	addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(role)))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, scopeURN, aiScopeAccessRelation([]string{role}), linkAttrs))
}

func aiLinkRoleToScope(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, roleURN string, scopeURN string, role string, matchType string) {
	if roleURN == "" || scopeURN == "" {
		return
	}
	linkAttrs := aiEventLinkAttributes(event, matchType)
	addProjectedAttribute(linkAttrs, "role", role)
	addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(role)))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, scopeURN, relationGrantsEntitlement, linkAttrs))
}

func aiScopeAccessRelation(roles []string) string {
	if aiRolesIncludeAdmin(roles) {
		return relationCanAdmin
	}
	return relationCanPerform
}

func aiRoleAssignmentRelation(role string) string {
	if aiRoleIsAdmin(role) {
		return relationCanAdmin
	}
	return relationAssignedTo
}

func aiRoleID(attrs map[string]string) string {
	return firstNonEmpty(attrs["role_id"], attrs["role"], attrs["name"], attrs["role_name"], attrs["predefined_role"])
}

func aiProjectCollaboratorPrincipalType(attrs map[string]string) string {
	raw := firstNonEmpty(attrs["principal_type"], attrs["collaborator_type"], attrs["type"])
	normalized := normalizeIdentifier(raw)
	switch {
	case strings.Contains(normalized, "organization") || normalized == "org" || strings.Contains(normalized, "everyone"):
		return "organization"
	case strings.TrimSpace(raw) != "":
		return identityPrincipalType(raw)
	case strings.TrimSpace(attrs["group_id"]) != "":
		return "group"
	case strings.TrimSpace(attrs["user_id"]) != "" || strings.TrimSpace(attrs["email"]) != "":
		return "user"
	case strings.TrimSpace(attrs["organization_uuid"]) != "" || strings.TrimSpace(attrs["organization_id"]) != "":
		return "organization"
	default:
		return identityPrincipalType(raw)
	}
}

func aiProjectCollaboratorPrincipalID(attrs map[string]string, principalType string) string {
	switch principalType {
	case "group":
		return firstNonEmpty(attrs["group_id"], attrs["principal_id"])
	case "organization":
		return firstNonEmpty(attrs["organization_uuid"], attrs["organization_id"], attrs["principal_id"])
	case "service_account":
		return firstNonEmpty(attrs["service_account_id"], attrs["principal_id"])
	default:
		return firstNonEmpty(attrs["user_id"], attrs["principal_id"])
	}
}

func aiEnsureProjectCollaboratorPrincipal(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, principalType string, principalID string, role string) string {
	attrs := event.GetAttributes()
	switch principalType {
	case "group":
		groupAttrs := cloneAttributes(attrs)
		groupAttrs["group_id"] = firstNonEmpty(attrs["group_id"], principalID)
		groupAttrs["group_name"] = firstNonEmpty(attrs["group_name"], attrs["name"], principalID)
		return aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, groupAttrs)
	case "organization":
		orgAttrs := cloneAttributes(attrs)
		if strings.TrimSpace(orgAttrs["organization_uuid"]) == "" && strings.TrimSpace(orgAttrs["organization_id"]) == "" {
			orgAttrs["organization_uuid"] = principalID
		}
		return aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, orgAttrs)
	case "service_account":
		serviceAccountID := firstNonEmpty(attrs["service_account_id"], principalID)
		serviceAccountURN := identityPrincipalURN(tenantID, profile.Provider, "service_account", serviceAccountID, "")
		if serviceAccountURN != "" {
			addEntity(entities, &ports.ProjectedEntity{
				URN:        serviceAccountURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: profile.Provider + ".service_account",
				Label:      firstNonEmpty(attrs["name"], serviceAccountID),
				Attributes: aiPrincipalAttributes(attrs, map[string]string{
					"principal_type":     "service_account",
					"service_account_id": serviceAccountID,
					"name":               strings.TrimSpace(attrs["name"]),
					"role":               strings.TrimSpace(role),
					"is_admin":           boolString(aiRoleIsAdmin(role)),
				}),
			})
		}
		return serviceAccountURN
	default:
		return aiEnsureUser(entities, links, tenantID, event, profile, firstNonEmpty(attrs["user_id"], principalID), attrs["email"], attrs["name"], role)
	}
}

func aiScopedRoleAttributes(source map[string]string, roleID string) map[string]string {
	return compactAttributes(map[string]string{
		"role_id":                           roleID,
		"role":                              roleID,
		"organization_id":                   source["organization_id"],
		"organization_uuid":                 source["organization_uuid"],
		"project_id":                        source["project_id"],
		"workspace_id":                      source["workspace_id"],
		ports.EventAttributeSourceRuntimeID: source[ports.EventAttributeSourceRuntimeID],
		"external_id":                       source["external_id"],
		"family":                            source["family"],
		"provider":                          source["provider"],
		"source_product":                    source["source_product"],
		"source_provider":                   source["source_provider"],
	})
}

func aiRoleIsAdmin(role string) bool {
	normalized := normalizeIdentifier(role)
	return strings.Contains(normalized, "admin") ||
		strings.Contains(normalized, "owner") ||
		strings.Contains(normalized, "administrator")
}

func aiRolesIncludeAdmin(roles []string) bool {
	for _, role := range roles {
		if aiRoleIsAdmin(role) {
			return true
		}
	}
	return false
}

func aiFamily(event *cerebrov1.EventEnvelope, profile aiAccessProfile) string {
	if family := strings.TrimSpace(event.GetAttributes()["family"]); family != "" {
		return family
	}
	return strings.TrimPrefix(strings.TrimSpace(event.GetKind()), profile.Provider+".")
}

func aiGovernanceControlModels(attrs map[string]string) []string {
	seen := map[string]struct{}{}
	models := []string{}
	for _, value := range []string{attrs["model"], attrs["models"], attrs["model_ids"]} {
		for _, modelID := range splitAttributeList(value) {
			if _, ok := seen[modelID]; ok {
				continue
			}
			seen[modelID] = struct{}{}
			models = append(models, modelID)
		}
	}
	return models
}

func aiUsageMetricID(family string, attrs map[string]string, fallback string) string {
	return firstNonEmpty(
		attrs["metric_id"],
		attrs[family+"_id"],
		attrs["id"],
		joinProjectionIdentity(attrs, "start_time", "end_time", "project_id", "workspace_id", "user_id", "api_key_id", "model", "line_item", "amount_currency"),
		fallback,
	)
}

func aiUsageMetricType(family string) string {
	if strings.Contains(normalizeIdentifier(family), "cost") {
		return "cost"
	}
	return "usage"
}

func aiUsageMetricLabel(family string, attrs map[string]string, fallback string) string {
	return firstNonEmpty(
		attrs["line_item"],
		attrs["model"],
		attrs["project_id"],
		attrs["workspace_id"],
		aiUsageMetricType(family)+" metric",
		fallback,
	)
}

func aiUsageMetricLinkAttributes(event *cerebrov1.EventEnvelope, matchType string, family string, metricType string) map[string]string {
	attrs := event.GetAttributes()
	linkAttrs := aiEventLinkAttributes(event, matchType)
	addProjectedAttribute(linkAttrs, "family", family)
	addProjectedAttribute(linkAttrs, "metric_type", metricType)
	addProjectedAttribute(linkAttrs, "start_time", attrs["start_time"])
	addProjectedAttribute(linkAttrs, "end_time", attrs["end_time"])
	addProjectedAttribute(linkAttrs, "amount_value", attrs["amount_value"])
	addProjectedAttribute(linkAttrs, "cost_usd", attrs["cost_usd"])
	return linkAttrs
}

func aiEventLinkAttributes(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	attrs := map[string]string{"event_id": event.GetId()}
	addProjectedAttribute(attrs, "at", eventObservedAt(event))
	addProjectedAttribute(attrs, "match_type", matchType)
	return attrs
}

func aiPrincipalAttributes(source map[string]string, base map[string]string) map[string]string {
	out := cloneStringMap(base)
	for _, key := range []string{ports.EventAttributeSourceRuntimeID, "external_id", "family", "provider", "source_product", "source_provider"} {
		addProjectedAttribute(out, key, source[key])
	}
	for key, value := range out {
		if strings.TrimSpace(value) == "" {
			delete(out, key)
		}
	}
	return out
}

func splitAttributeList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
