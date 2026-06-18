package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type aiAccessProfile struct {
	Provider string
}

var (
	openAIAccessProfile    = aiAccessProfile{Provider: "openai"}
	anthropicAccessProfile = aiAccessProfile{Provider: "anthropic"}
)

func openAIUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUserProjections(event, openAIAccessProfile)
}

func anthropicUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUserProjections(event, anthropicAccessProfile)
}

func openAIProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectProjections(event, openAIAccessProfile)
}

func anthropicOrganizationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiOrganizationProjections(event, anthropicAccessProfile)
}

func anthropicWorkspaceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiWorkspaceProjections(event, anthropicAccessProfile)
}

func openAIGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupProjections(event, openAIAccessProfile)
}

func openAIGroupUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupMembershipProjections(event, openAIAccessProfile)
}

func openAIProjectUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedUserAccessProjections(event, openAIAccessProfile, "project")
}

func anthropicWorkspaceMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedUserAccessProjections(event, anthropicAccessProfile, "workspace")
}

func anthropicComplianceGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupRoleAssignmentProjections(event, anthropicAccessProfile)
}

func anthropicComplianceGroupMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupMembershipProjections(event, anthropicAccessProfile)
}

func openAIServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiServiceAccountProjections(event, openAIAccessProfile, "project")
}

func anthropicServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiServiceAccountProjections(event, anthropicAccessProfile, "organization")
}

func openAICredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiCredentialProjections(event, openAIAccessProfile)
}

func anthropicCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiCredentialProjections(event, anthropicAccessProfile)
}

func openAIRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiRoleProjections(event, openAIAccessProfile)
}

func anthropicComplianceRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedRoleProjections(event, anthropicAccessProfile)
}

func openAIUserRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIAccessProfile, "user", "organization")
}

func openAIGroupRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIAccessProfile, "group", "organization")
}

func openAIProjectUserRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIAccessProfile, "user", "project")
}

func openAIProjectGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedGroupAccessProjections(event, openAIAccessProfile, "project")
}

func openAIProjectGroupRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIAccessProfile, "group", "project")
}

func openAIProjectEntitlementProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectEntitlementProjections(event, openAIAccessProfile)
}

func openAIGovernanceControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGovernanceControlProjections(event, openAIAccessProfile)
}

func anthropicGovernanceControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGovernanceControlProjections(event, anthropicAccessProfile)
}

func anthropicFederationIssuerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiFederationIssuerProjections(event, anthropicAccessProfile)
}

func anthropicFederationRuleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiFederationRuleProjections(event, anthropicAccessProfile)
}

func openAIAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiAuditProjections(event, openAIAccessProfile)
}

func anthropicComplianceActivityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiAuditProjections(event, anthropicAccessProfile)
}

func aiUserProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	userID := firstNonEmpty(attrs["user_id"], attrs["id"])
	email := strings.TrimSpace(attrs["email"])
	userURN := identityPrincipalURN(tenantID, profile.Provider, "user", userID, email)
	if userURN != "" {
		userAttrs := aiPrincipalAttributes(attrs, map[string]string{
			"principal_type": "user",
			"user_id":        userID,
			"email":          email,
			"name":           firstNonEmpty(attrs["name"], attrs["display_name"]),
			"role":           strings.TrimSpace(attrs["role"]),
			"status":         strings.TrimSpace(attrs["status"]),
			"added_at":       strings.TrimSpace(attrs["added_at"]),
			"is_admin":       boolString(aiRoleIsAdmin(attrs["role"])),
		})
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".user",
			Label:      firstNonEmpty(attrs["name"], email, userID),
			Attributes: userAttrs,
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
		aiLinkPrincipalToScope(links, tenantID, event, userURN, orgURN, attrs["role"], "organization_membership")
	}
	return identityProjectionResult(entities, links)
}

func aiOrganizationProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entities := map[string]*ports.ProjectedEntity{}
	aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, event.GetAttributes())
	return identityProjectionResult(entities, nil)
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

func aiWorkspaceProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	workspaceURN := aiEnsureWorkspace(entities, tenantID, event.GetSourceId(), profile, attrs)
	if workspaceURN != "" && orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), workspaceURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "workspace_organization")))
	}
	return identityProjectionResult(entities, links)
}

func aiGroupProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	groupURN := aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, attrs)
	if groupURN != "" && orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "group_organization")))
	}
	return identityProjectionResult(entities, links)
}

func aiGroupMembershipProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	groupURN := aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, attrs)
	userID := firstNonEmpty(attrs["user_id"], attrs["member_user_id"], attrs["member_id"])
	email := firstNonEmpty(attrs["email"], attrs["user_email"], attrs["member_email"])
	userURN := aiEnsureUser(entities, links, tenantID, event, profile, userID, email, firstNonEmpty(attrs["name"], attrs["member_name"]), attrs["role"])
	if userURN != "" && groupURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, groupURN, relationMemberOf, aiEventLinkAttributes(event, "group_membership")))
	}
	return identityProjectionResult(entities, links)
}

func aiScopedUserAccessProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile, scopeKind string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	userID := firstNonEmpty(attrs["user_id"], attrs["id"])
	email := strings.TrimSpace(attrs["email"])
	userURN := aiEnsureUser(entities, links, tenantID, event, profile, userID, email, attrs["name"], attrs["role"])
	aiLinkPrincipalToScope(links, tenantID, event, userURN, scopeURN, firstNonEmpty(attrs["workspace_role"], attrs["role"]), scopeKind+"_membership")
	return identityProjectionResult(entities, links)
}

func aiScopedGroupAccessProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile, scopeKind string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	groupURN := aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, attrs)
	aiLinkPrincipalToScope(links, tenantID, event, groupURN, scopeURN, attrs["role"], scopeKind+"_group_membership")
	return identityProjectionResult(entities, links)
}

func aiServiceAccountProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile, defaultScopeKind string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeKind := defaultScopeKind
	if strings.TrimSpace(attrs["project_id"]) != "" {
		scopeKind = "project"
	}
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	serviceAccountID := firstNonEmpty(attrs["service_account_id"], attrs["id"])
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
				"role":               strings.TrimSpace(attrs["role"]),
				"status":             strings.TrimSpace(attrs["status"]),
				"created_at":         strings.TrimSpace(attrs["created_at"]),
				"description":        strings.TrimSpace(attrs["description"]),
				"is_admin":           boolString(aiRoleIsAdmin(attrs["role"])),
			}),
		})
		aiLinkPrincipalToScope(links, tenantID, event, serviceAccountURN, scopeURN, attrs["role"], scopeKind+"_service_account")
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
	credentialURN := projectionURN(tenantID, profile.Provider+"_credential", credentialID)
	if credentialURN == "" {
		return identityProjectionResult(entities, links)
	}
	credentialType := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(event.GetKind()), profile.Provider+"."), "project_")
	if credentialType == "" {
		credentialType = "credential"
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        credentialURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + ".credential",
		Label:      firstNonEmpty(attrs["name"], credentialID),
		Attributes: aiPrincipalAttributes(attrs, map[string]string{
			"credential_id":   credentialID,
			"credential_type": credentialType,
			"api_key_id":      strings.TrimSpace(attrs["api_key_id"]),
			"external_key_id": strings.TrimSpace(attrs["external_key_id"]),
			"name":            strings.TrimSpace(attrs["name"]),
			"status":          strings.TrimSpace(attrs["status"]),
			"provider":        strings.TrimSpace(attrs["provider"]),
			"created_at":      strings.TrimSpace(attrs["created_at"]),
			"last_used_at":    strings.TrimSpace(attrs["last_used_at"]),
		}),
	})
	scopeKind := aiCredentialScopeKind(attrs, event.GetKind())
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

func aiRoleProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, attrs, aiRoleScopeKind(attrs, event.GetKind()))
	return identityProjectionResult(entities, nil)
}

func aiScopedRoleProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeKind := aiRoleScopeKind(attrs, event.GetKind())
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, attrs, scopeKind)
	aiLinkRoleToScope(links, tenantID, event, roleURN, scopeURN, aiRoleID(attrs), "role_scope")
	if roleURN != "" && scopeURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, scopeURN, relationBelongsTo, aiEventLinkAttributes(event, "role_scope_container")))
	}
	return identityProjectionResult(entities, links)
}

func aiSubjectRoleProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile, subjectKind string, scopeKind string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, attrs, scopeKind)
	subjectURN := ""
	switch subjectKind {
	case "group":
		subjectURN = aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, attrs)
	default:
		subjectURN = aiEnsureUser(entities, links, tenantID, event, profile, attrs["user_id"], attrs["email"], attrs["name"], attrs["role"])
	}
	if subjectURN != "" && roleURN != "" {
		role := aiRoleID(attrs)
		relation := relationAssignedTo
		if aiRoleIsAdmin(role) {
			relation = relationCanAdmin
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, roleURN, relation, aiEventLinkAttributes(event, subjectKind+"_role")))
	}
	aiLinkRoleToScope(links, tenantID, event, roleURN, scopeURN, aiRoleID(attrs), "role_scope")
	aiLinkPrincipalToScope(links, tenantID, event, subjectURN, scopeURN, aiRoleID(attrs), subjectKind+"_"+scopeKind+"_role_access")
	return identityProjectionResult(entities, links)
}

func aiGroupRoleAssignmentProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	groupURN := aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, attrs)
	if groupURN != "" && orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "group_organization")))
	}
	roleIDs := aiRoleIDsFromAttribute(attrs["roles"])
	for _, roleID := range roleIDs {
		roleAttrs := aiScopedRoleAttributes(attrs, roleID)
		roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, "organization")
		if groupURN != "" && roleURN != "" {
			linkAttrs := aiEventLinkAttributes(event, "group_role")
			addProjectedAttribute(linkAttrs, "role", roleID)
			addProjectedAttribute(linkAttrs, "role_id", roleID)
			addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(roleID)))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, roleURN, aiRoleAssignmentRelation(roleID), linkAttrs))
		}
		aiLinkRoleToScope(links, tenantID, event, roleURN, orgURN, roleID, "group_role_scope")
	}
	aiLinkPrincipalRolesToScope(links, tenantID, event, groupURN, orgURN, roleIDs, "group_organization_role_access")
	return identityProjectionResult(entities, links)
}

func aiProjectEntitlementProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, attrs)
	switch strings.TrimSpace(attrs["family"]) {
	case "project_model_permission":
		for _, modelID := range splitAttributeList(attrs["model_ids"]) {
			modelURN := projectionURN(tenantID, profile.Provider+"_model", modelID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        modelURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: profile.Provider + ".model",
				Label:      modelID,
				Attributes: map[string]string{"model_id": modelID},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), projectURN, modelURN, relationCanPerform, aiEventLinkAttributes(event, "project_model_permission")))
		}
	case "project_hosted_tool_permission":
		for _, tool := range []string{"code_interpreter", "file_search", "image_generation", "mcp", "web_search"} {
			if !projectionBool(attrs[tool+"_enabled"]) {
				continue
			}
			toolURN := projectionURN(tenantID, profile.Provider+"_hosted_tool", tool)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        toolURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: profile.Provider + ".hosted_tool",
				Label:      strings.ReplaceAll(tool, "_", " "),
				Attributes: map[string]string{"tool": tool, "enabled": "true"},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), projectURN, toolURN, relationCanPerform, aiEventLinkAttributes(event, "project_hosted_tool_permission")))
		}
	default:
		return genericInventoryProjections(event)
	}
	return identityProjectionResult(entities, links)
}

func aiGovernanceControlProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	family := aiFamily(event, profile)
	controlID := aiGovernanceControlID(family, attrs, event.GetId())
	if controlID == "" {
		return identityProjectionResult(entities, links)
	}
	controlURN := projectionURN(tenantID, profile.Provider+"_"+family, strings.Split(controlID, "|")...)
	controlType := aiGovernanceControlType(family)
	scopeKind := aiGovernanceControlScopeKind(attrs, event.GetKind(), family)
	controlAttrs := cloneAttributes(attrs)
	controlAttrs["event_kind"] = event.GetKind()
	controlAttrs["source_event_id"] = event.GetId()
	addProjectedAttribute(controlAttrs, "control_id", controlID)
	addProjectedAttribute(controlAttrs, "control_type", controlType)
	addProjectedAttribute(controlAttrs, "scope_kind", scopeKind)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        controlURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + "." + family,
		Label:      aiGovernanceControlLabel(family, attrs, controlID),
		Attributes: controlAttrs,
	})
	scopeURN := aiEnsureScope(entities, tenantID, event.GetSourceId(), profile, scopeKind, attrs)
	if scopeURN != "" {
		linkAttrs := aiEventLinkAttributes(event, "governance_control_scope")
		addProjectedAttribute(linkAttrs, "control_type", controlType)
		addProjectedAttribute(linkAttrs, "family", family)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), controlURN, scopeURN, relationBelongsTo, linkAttrs))
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
		addLink(links, projectedLink(tenantID, event.GetSourceId(), controlURN, modelURN, relationAssociatedWith, aiEventLinkAttributes(event, "governance_control_model")))
	}
	userID := firstNonEmpty(attrs["user_id"], attrs["actor_user_id"])
	userEmail := firstNonEmpty(attrs["email"], attrs["actor_email"])
	if userID != "" || userEmail != "" {
		userURN := aiEnsureUser(entities, links, tenantID, event, profile, userID, userEmail, attrs["name"], "")
		addLink(links, projectedLink(tenantID, event.GetSourceId(), controlURN, userURN, relationAssociatedWith, aiEventLinkAttributes(event, "governance_control_principal")))
	}
	return identityProjectionResult(entities, links)
}

func aiFederationIssuerProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	issuerID := firstNonEmpty(attrs["federation_issuer_id"], attrs["issuer_id"])
	issuerURN := projectionURN(tenantID, profile.Provider+"_federation_issuer", issuerID)
	if issuerURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        issuerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".federation_issuer",
			Label:      firstNonEmpty(attrs["name"], attrs["issuer"], issuerID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"federation_issuer_id": issuerID,
				"issuer":               strings.TrimSpace(attrs["issuer"]),
				"name":                 strings.TrimSpace(attrs["name"]),
				"status":               strings.TrimSpace(attrs["status"]),
				"created_at":           strings.TrimSpace(attrs["created_at"]),
				"updated_at":           strings.TrimSpace(attrs["updated_at"]),
			}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), issuerURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "federation_issuer_organization")))
	}
	return identityProjectionResult(entities, links)
}

func aiFederationRuleProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	ruleID := firstNonEmpty(attrs["federation_rule_id"], attrs["id"])
	ruleURN := projectionURN(tenantID, profile.Provider+"_federation_rule", ruleID)
	issuerURN := projectionURN(tenantID, profile.Provider+"_federation_issuer", firstNonEmpty(attrs["issuer_id"], attrs["federation_issuer_id"]))
	serviceAccountURN := identityPrincipalURN(tenantID, profile.Provider, "service_account", attrs["service_account_id"], "")
	if ruleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ruleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".federation_rule",
			Label:      firstNonEmpty(attrs["subject"], ruleID),
			Attributes: aiPrincipalAttributes(attrs, map[string]string{
				"federation_rule_id": ruleID,
				"issuer_id":          strings.TrimSpace(attrs["issuer_id"]),
				"service_account_id": strings.TrimSpace(attrs["service_account_id"]),
				"subject":            strings.TrimSpace(attrs["subject"]),
				"scopes":             strings.TrimSpace(attrs["scopes"]),
				"created_at":         strings.TrimSpace(attrs["created_at"]),
				"updated_at":         strings.TrimSpace(attrs["updated_at"]),
			}),
		})
	}
	if issuerURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        issuerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".federation_issuer",
			Label:      firstNonEmpty(attrs["issuer_id"], attrs["federation_issuer_id"]),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), issuerURN, ruleURN, relationGrantsEntitlement, aiEventLinkAttributes(event, "issuer_rule")))
	}
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        serviceAccountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".service_account",
			Label:      attrs["service_account_id"],
			Attributes: map[string]string{"service_account_id": attrs["service_account_id"], "principal_type": "service_account"},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), ruleURN, serviceAccountURN, relationCanAssume, aiEventLinkAttributes(event, "federation_rule_service_account")))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), ruleURN, serviceAccountURN, relationCanImpersonate, aiEventLinkAttributes(event, "federation_rule_service_account")))
	}
	return identityProjectionResult(entities, links)
}

func aiAuditProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	actorID := firstNonEmpty(attrs["actor_user_id"], attrs["actor_id"])
	actorEmail := strings.TrimSpace(attrs["actor_email"])
	actorType := firstNonEmpty(attrs["actor_type"], "user")
	if strings.TrimSpace(attrs["actor_api_key_id"]) != "" || aiActorTypeIsCredential(actorType) {
		actorType = "credential"
		actorID = firstNonEmpty(attrs["actor_api_key_id"], actorID)
	}
	actorURN := ""
	if identityPrincipalType(actorType) == "service_account" {
		actorURN = identityPrincipalURN(tenantID, profile.Provider, "service_account", actorID, "")
	} else if actorType == "credential" {
		actorURN = projectionURN(tenantID, profile.Provider+"_credential", actorID)
	} else {
		actorURN = aiEnsureUser(entities, links, tenantID, event, profile, actorID, actorEmail, attrs["actor_name"], "")
	}
	if actorURN != "" && actorType == "credential" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".credential",
			Label:      actorID,
			Attributes: map[string]string{"credential_id": actorID, "principal_type": "credential"},
		})
	}
	targetURN := aiAuditTargetURN(entities, tenantID, event.GetSourceId(), profile, attrs)
	if actorURN != "" && targetURN != "" {
		linkAttrs := aiEventLinkAttributes(event, "audit_activity")
		addProjectedAttribute(linkAttrs, "event_type", firstNonEmpty(attrs["event_type"], attrs["activity_type"]))
		addProjectedAttribute(linkAttrs, "activity_type", attrs["activity_type"])
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, targetURN, relationActedOn, linkAttrs))
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
	if ownerServiceAccountID := strings.TrimSpace(attrs["owner_service_account_id"]); ownerServiceAccountID != "" {
		ownerURN := identityPrincipalURN(tenantID, profile.Provider, "service_account", ownerServiceAccountID, "")
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ownerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".service_account",
			Label:      ownerServiceAccountID,
			Attributes: map[string]string{"service_account_id": ownerServiceAccountID, "principal_type": "service_account"},
		})
		return ownerURN
	}
	if ownerUserID := firstNonEmpty(attrs["owner_user_id"], attrs["user_id"]); ownerUserID != "" || strings.TrimSpace(attrs["email"]) != "" {
		return aiEnsureUser(entities, links, tenantID, event, profile, ownerUserID, attrs["email"], attrs["name"], "")
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

func aiGovernanceControlScopeKind(attrs map[string]string, kind string, family string) string {
	switch {
	case strings.TrimSpace(attrs["project_id"]) != "":
		return "project"
	case strings.TrimSpace(attrs["workspace_id"]) != "":
		return "workspace"
	case strings.Contains(kind, ".project_") || strings.HasPrefix(family, "project_"):
		return "project"
	case strings.Contains(kind, ".workspace_") || strings.HasPrefix(family, "workspace_"):
		return "workspace"
	default:
		return "organization"
	}
}

func aiRoleScopeKind(attrs map[string]string, kind string) string {
	switch {
	case strings.TrimSpace(attrs["project_id"]) != "":
		return "project"
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

func aiLinkPrincipalRolesToScope(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, principalURN string, scopeURN string, roles []string, matchType string) {
	if principalURN == "" || scopeURN == "" || len(roles) == 0 {
		return
	}
	linkAttrs := aiEventLinkAttributes(event, matchType)
	addProjectedAttribute(linkAttrs, "roles", strings.Join(roles, ","))
	if len(roles) == 1 {
		addProjectedAttribute(linkAttrs, "role", roles[0])
	}
	addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRolesIncludeAdmin(roles)))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, scopeURN, aiScopeAccessRelation(roles), linkAttrs))
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

func aiAuditTargetURN(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, attrs map[string]string) string {
	switch {
	case strings.TrimSpace(attrs["project_id"]) != "":
		return aiEnsureProject(entities, tenantID, sourceID, profile, attrs)
	case strings.TrimSpace(attrs["api_key_id"]) != "":
		credentialURN := projectionURN(tenantID, profile.Provider+"_credential", attrs["api_key_id"])
		addEntity(entities, &ports.ProjectedEntity{
			URN:        credentialURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: profile.Provider + ".credential",
			Label:      attrs["api_key_id"],
			Attributes: map[string]string{"credential_id": attrs["api_key_id"]},
		})
		return credentialURN
	case strings.TrimSpace(attrs["organization_id"]) != "" || strings.TrimSpace(attrs["organization_uuid"]) != "":
		return aiEnsureOrganization(entities, tenantID, sourceID, profile, attrs)
	default:
		return aiEnsureOrganization(entities, tenantID, sourceID, profile, attrs)
	}
}

func aiRoleID(attrs map[string]string) string {
	return firstNonEmpty(attrs["role_id"], attrs["role"], attrs["name"], attrs["role_name"], attrs["predefined_role"])
}

func aiRoleIDsFromAttribute(value string) []string {
	seen := map[string]struct{}{}
	roles := []string{}
	for _, roleID := range splitAttributeList(value) {
		if _, ok := seen[roleID]; ok {
			continue
		}
		seen[roleID] = struct{}{}
		roles = append(roles, roleID)
	}
	return roles
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

func aiActorTypeIsCredential(actorType string) bool {
	normalized := normalizeIdentifier(actorType)
	return strings.Contains(normalized, "api_key") ||
		strings.Contains(normalized, "apikey") ||
		strings.Contains(normalized, "credential")
}

func aiFamily(event *cerebrov1.EventEnvelope, profile aiAccessProfile) string {
	if family := strings.TrimSpace(event.GetAttributes()["family"]); family != "" {
		return family
	}
	return strings.TrimPrefix(strings.TrimSpace(event.GetKind()), profile.Provider+".")
}

func aiGovernanceControlID(family string, attrs map[string]string, fallback string) string {
	switch family {
	case "project_rate_limit":
		return firstNonEmpty(joinProjectionIdentity(attrs, "project_id", "rate_limit_id", "model", "name"), fallback)
	case "workspace_rate_limit":
		return firstNonEmpty(joinProjectionIdentity(attrs, "workspace_id", "rate_limit_id", "model", "name"), fallback)
	case "rate_limit":
		return firstNonEmpty(joinProjectionIdentity(attrs, "rate_limit_id", "group_type", "model", "name"), joinProjectionIdentity(attrs, "id", "group_type", "model", "name"), fallback)
	case "project_data_retention":
		return firstNonEmpty(joinProjectionIdentity(attrs, "project_id", "retention_type", "object"), fallback)
	case "data_retention":
		return firstNonEmpty(joinProjectionIdentity(attrs, "organization_id", "organization_uuid", "retention_type", "object"), joinProjectionIdentity(attrs, "retention_type", "object"), fallback)
	case "project_spend_alert":
		return firstNonEmpty(joinProjectionIdentity(attrs, "project_id", "spend_alert_id", "name"), fallback)
	case "spend_alert":
		return firstNonEmpty(attrs["spend_alert_id"], attrs["id"], attrs["name"], fallback)
	case "project_certificate":
		return firstNonEmpty(joinProjectionIdentity(attrs, "project_id", "certificate_id"), fallback)
	case "certificate":
		return firstNonEmpty(attrs["certificate_id"], attrs["id"], attrs["name"], fallback)
	case "spend_limit":
		return firstNonEmpty(attrs["spend_limit_id"], attrs["id"], joinProjectionIdentity(attrs, "scope_type", "user_id", "period", "amount"), fallback)
	case "spend_limit_increase_request":
		return firstNonEmpty(attrs["request_id"], attrs["id"], joinProjectionIdentity(attrs, "user_id", "period", "amount"), fallback)
	case "compliance_organization_setting":
		return firstNonEmpty(joinProjectionIdentity(attrs, "organization_uuid", "organization_id", "setting_name", "name"), fallback)
	}
	return firstNonEmpty(inventoryEntityID("", family, attrs), fallback)
}

func aiGovernanceControlType(family string) string {
	controlType := strings.TrimSpace(family)
	controlType = strings.TrimPrefix(controlType, "project_")
	controlType = strings.TrimPrefix(controlType, "workspace_")
	controlType = strings.TrimPrefix(controlType, "compliance_organization_")
	if controlType == "" {
		return "governance_control"
	}
	return controlType
}

func aiGovernanceControlLabel(family string, attrs map[string]string, fallback string) string {
	return firstNonEmpty(
		attrs["name"],
		attrs["setting_name"],
		attrs["model"],
		attrs["rate_limit_id"],
		attrs["spend_alert_id"],
		attrs["certificate_id"],
		attrs["retention_type"],
		aiGovernanceControlType(family),
		fallback,
	)
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
