package sourceprojection

import (
	"encoding/json"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type aiAccessProfile struct {
	Provider string
}

type aiInviteProjectMembership struct {
	ProjectID string
	Role      string
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

func anthropicProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectProjections(event, anthropicAccessProfile)
}

func anthropicProjectCollaboratorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectCollaboratorProjections(event, anthropicAccessProfile)
}

func anthropicOrganizationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiOrganizationProjections(event, anthropicAccessProfile)
}

func openAIInviteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiInviteProjections(event, openAIAccessProfile)
}

func anthropicInviteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiInviteProjections(event, anthropicAccessProfile)
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

func anthropicComplianceRolePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiRolePermissionProjections(event, anthropicAccessProfile)
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

func openAIUsageMetricProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUsageMetricProjections(event, openAIAccessProfile)
}

func anthropicUsageMetricProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUsageMetricProjections(event, anthropicAccessProfile)
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

func aiInviteProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	inviteID := firstNonEmpty(attrs["invite_id"], attrs["id"], event.GetId())
	inviteURN := projectionURN(tenantID, profile.Provider+"_invite", inviteID)
	if inviteURN == "" {
		return identityProjectionResult(entities, links)
	}
	email := strings.TrimSpace(attrs["email"])
	role := firstNonEmpty(attrs["role"], attrs["organization_role"], attrs["role_name"])
	status := strings.TrimSpace(attrs["status"])
	inviteAttrs := aiPrincipalAttributes(attrs, map[string]string{
		"invite_id":    inviteID,
		"email":        email,
		"role":         role,
		"status":       status,
		"created_at":   strings.TrimSpace(attrs["created_at"]),
		"accepted_at":  strings.TrimSpace(attrs["accepted_at"]),
		"expires_at":   strings.TrimSpace(attrs["expires_at"]),
		"access_state": aiInviteAccessState(status),
		"is_admin":     boolString(aiRoleIsAdmin(role)),
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        inviteURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + ".invite",
		Label:      firstNonEmpty(email, inviteID),
		Attributes: inviteAttrs,
	})
	orgURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), inviteURN, orgURN, relationBelongsTo, aiEventLinkAttributes(event, "invite_organization")))
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), inviteURN, email, event.GetOccurredAt())
	if !aiInviteAccessIntentActive(status) {
		return identityProjectionResult(entities, links)
	}
	if role != "" {
		roleAttrs := aiScopedRoleAttributes(attrs, role)
		roleAttrs["role"] = role
		roleAttrs["role_id"] = role
		roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, "organization")
		if roleURN != "" {
			linkAttrs := aiEventLinkAttributes(event, "invite_role")
			addProjectedAttribute(linkAttrs, "role", role)
			addProjectedAttribute(linkAttrs, "status", status)
			addProjectedAttribute(linkAttrs, "access_state", aiInviteAccessState(status))
			addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(role)))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), inviteURN, roleURN, aiRoleAssignmentRelation(role), linkAttrs))
			aiLinkRoleToScope(links, tenantID, event, roleURN, orgURN, role, "invite_role_scope")
		}
	}
	for _, projectMembership := range aiInviteProjectMemberships(event) {
		projectAttrs := cloneAttributes(attrs)
		projectAttrs["project_id"] = projectMembership.ProjectID
		projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, projectAttrs)
		if projectURN == "" {
			continue
		}
		projectRole := firstNonEmpty(projectMembership.Role, role)
		if projectRole != "" {
			roleAttrs := aiScopedRoleAttributes(projectAttrs, projectRole)
			roleAttrs["role"] = projectRole
			roleAttrs["role_id"] = projectRole
			roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, "project")
			if roleURN != "" {
				linkAttrs := aiEventLinkAttributes(event, "invite_project_role")
				addProjectedAttribute(linkAttrs, "project_id", projectMembership.ProjectID)
				addProjectedAttribute(linkAttrs, "role", projectRole)
				addProjectedAttribute(linkAttrs, "status", status)
				addProjectedAttribute(linkAttrs, "access_state", aiInviteAccessState(status))
				addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(projectRole)))
				addLink(links, projectedLink(tenantID, event.GetSourceId(), inviteURN, roleURN, aiRoleAssignmentRelation(projectRole), linkAttrs))
				aiLinkRoleToScope(links, tenantID, event, roleURN, projectURN, projectRole, "invite_project_role_scope")
			}
		}
		linkAttrs := aiEventLinkAttributes(event, "invite_project_access_intent")
		addProjectedAttribute(linkAttrs, "project_id", projectMembership.ProjectID)
		addProjectedAttribute(linkAttrs, "role", projectRole)
		addProjectedAttribute(linkAttrs, "status", status)
		addProjectedAttribute(linkAttrs, "access_state", aiInviteAccessState(status))
		addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(projectRole)))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), inviteURN, projectURN, aiScopeAccessRelation([]string{projectRole}), linkAttrs))
	}
	linkAttrs := aiEventLinkAttributes(event, "invite_access_intent")
	addProjectedAttribute(linkAttrs, "role", role)
	addProjectedAttribute(linkAttrs, "status", status)
	addProjectedAttribute(linkAttrs, "access_state", aiInviteAccessState(status))
	addProjectedAttribute(linkAttrs, "is_admin", boolString(aiRoleIsAdmin(role)))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), inviteURN, orgURN, aiScopeAccessRelation([]string{role}), linkAttrs))
	return identityProjectionResult(entities, links)
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

func aiRolePermissionProjections(event *cerebrov1.EventEnvelope, profile aiAccessProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	roleID := aiRoleID(attrs)
	permissionID := aiRolePermissionID(attrs, "")
	if roleID == "" || permissionID == "" {
		return identityProjectionResult(entities, links)
	}
	scopeURN := aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, attrs)
	roleURN := aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, attrs, "organization")
	entitlementURN := projectionURN(tenantID, profile.Provider+"_entitlement", "role_permission", roleID, permissionID)
	entitlementAttrs := cloneAttributes(attrs)
	entitlementAttrs["entitlement_id"] = "role_permission:" + roleID + ":" + permissionID
	entitlementAttrs["entitlement_type"] = "role_permission"
	entitlementAttrs["permission_id"] = permissionID
	entitlementAttrs["role_id"] = roleID
	addEntity(entities, &ports.ProjectedEntity{
		URN:        entitlementURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.Provider + ".entitlement",
		Label:      firstNonEmpty(attrs["permission_name"], attrs["permission"], permissionID),
		Attributes: entitlementAttrs,
	})
	linkAttrs := aiEventLinkAttributes(event, "role_permission")
	addProjectedAttribute(linkAttrs, "role_id", roleID)
	addProjectedAttribute(linkAttrs, "permission_id", permissionID)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, entitlementURN, relationGrantsEntitlement, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, scopeURN, relationBelongsTo, aiEventLinkAttributes(event, "role_permission_scope")))
	aiLinkRoleToScope(links, tenantID, event, roleURN, scopeURN, roleID, "role_permission_scope_access")
	capabilityID := aiRolePermissionCapabilityID(attrs)
	capabilityURN := projectionURN(tenantID, "privileged_capability", capabilityID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        capabilityURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "privileged.capability",
		Label:      strings.ReplaceAll(capabilityID, "_", " "),
		Attributes: map[string]string{"capability_id": capabilityID},
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, aiEventLinkAttributes(event, "role_permission_capability")))
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
	actorAPIKeyID := strings.TrimSpace(firstNonEmpty(attrs["actor_api_key_id"], attrs["actor_admin_api_key_id"]))
	actorUserID := strings.TrimSpace(attrs["actor_user_id"])
	actorServiceAccountID := strings.TrimSpace(attrs["actor_service_account_id"])
	actorEmail := strings.TrimSpace(attrs["actor_email"])
	actorType := strings.TrimSpace(attrs["actor_type"])
	actorID := firstNonEmpty(actorUserID, attrs["actor_id"])
	if actorAPIKeyID != "" {
		actorType = "credential"
		actorID = actorAPIKeyID
	} else if actorServiceAccountID != "" {
		actorType = "service_account"
		actorID = actorServiceAccountID
	} else if actorType == "" {
		actorType = "user"
	}
	actorURN := ""
	if identityPrincipalType(actorType) == "service_account" {
		actorURN = aiEnsureServiceAccount(entities, tenantID, event.GetSourceId(), profile, actorID, attrs["actor_name"], "", attrs)
	} else if actorType == "credential" {
		actorURN = aiEnsureCredential(entities, tenantID, event.GetSourceId(), profile, actorID, attrs)
	} else {
		actorURN = aiEnsureUser(entities, links, tenantID, event, profile, actorID, actorEmail, attrs["actor_name"], "")
	}
	if actorURN != "" && actorAPIKeyID != "" {
		ownerURN := aiAuditCredentialOwnerURN(entities, links, tenantID, event, profile, actorUserID, actorServiceAccountID, actorEmail)
		if ownerURN != "" {
			linkAttrs := aiEventLinkAttributes(event, "audit_actor_credential_owner")
			addProjectedAttribute(linkAttrs, "credential_id", actorAPIKeyID)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), ownerURN, actorURN, relationAssignedTo, linkAttrs))
		}
	}
	for _, targetURN := range aiAuditTargetURNs(entities, links, tenantID, event, profile, attrs) {
		if actorURN != "" && targetURN != "" {
			linkAttrs := aiEventLinkAttributes(event, "audit_activity")
			addProjectedAttribute(linkAttrs, "event_type", firstNonEmpty(attrs["event_type"], attrs["activity_type"]))
			addProjectedAttribute(linkAttrs, "activity_type", attrs["activity_type"])
			addProjectedAttribute(linkAttrs, "actor_type", actorType)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, targetURN, relationActedOn, linkAttrs))
		}
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

func aiEnsureServiceAccount(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, serviceAccountID string, name string, role string, attrs map[string]string) string {
	serviceAccountURN := identityPrincipalURN(tenantID, profile.Provider, "service_account", serviceAccountID, "")
	if serviceAccountURN == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        serviceAccountURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.Provider + ".service_account",
		Label:      firstNonEmpty(name, serviceAccountID),
		Attributes: aiPrincipalAttributes(attrs, map[string]string{
			"principal_type":     "service_account",
			"service_account_id": serviceAccountID,
			"name":               strings.TrimSpace(name),
			"role":               strings.TrimSpace(role),
			"is_admin":           boolString(aiRoleIsAdmin(role)),
		}),
	})
	return serviceAccountURN
}

func aiEnsureCredential(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile aiAccessProfile, credentialID string, attrs map[string]string) string {
	credentialURN := projectionURN(tenantID, profile.Provider+"_credential", credentialID)
	if credentialURN == "" {
		return ""
	}
	baseAttrs := map[string]string{
		"credential_id":  strings.TrimSpace(credentialID),
		"principal_type": "credential",
		"api_key_id":     strings.TrimSpace(credentialID),
	}
	if credentialID == strings.TrimSpace(firstNonEmpty(attrs["actor_api_key_id"], attrs["actor_admin_api_key_id"])) {
		baseAttrs["actor_user_id"] = strings.TrimSpace(attrs["actor_user_id"])
		baseAttrs["actor_service_account_id"] = strings.TrimSpace(attrs["actor_service_account_id"])
	}
	credentialAttrs := aiPrincipalAttributes(attrs, baseAttrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        credentialURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.Provider + ".credential",
		Label:      credentialID,
		Attributes: credentialAttrs,
	})
	return credentialURN
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
		return aiEnsureUser(entities, links, tenantID, event, profile, ownerUserID, attrs["email"], firstNonEmpty(attrs["owner_name"], attrs["name"]), "")
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

func aiAuditTargetURNs(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, attrs map[string]string) []string {
	targetURNs := []string{}
	appendTarget := func(targetURN string) {
		if targetURN == "" {
			return
		}
		for _, existing := range targetURNs {
			if existing == targetURN {
				return
			}
		}
		targetURNs = append(targetURNs, targetURN)
	}
	appendTarget(aiAuditTargetURN(entities, links, tenantID, event, profile, attrs))

	eventType := strings.TrimSpace(firstNonEmpty(attrs["event_type"], attrs["activity_type"]))
	if strings.HasPrefix(eventType, "role.assignment.") && strings.TrimSpace(attrs["principal_id"]) != "" {
		appendTarget(aiAuditPrincipalURN(entities, links, tenantID, event, profile, attrs["principal_id"], attrs["principal_type"], attrs))
	}
	return targetURNs
}

func aiAuditTargetURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, attrs map[string]string) string {
	sourceID := event.GetSourceId()
	eventType := strings.TrimSpace(firstNonEmpty(attrs["event_type"], attrs["activity_type"]))
	switch {
	case strings.HasPrefix(eventType, "api_key.") && strings.TrimSpace(attrs["api_key_id"]) != "":
		return aiEnsureCredential(entities, tenantID, sourceID, profile, attrs["api_key_id"], attrs)
	case strings.HasPrefix(eventType, "user.") && (strings.TrimSpace(attrs["user_id"]) != "" || strings.TrimSpace(attrs["email"]) != ""):
		return aiEnsureUser(entities, links, tenantID, event, profile, attrs["user_id"], attrs["email"], attrs["name"], attrs["role"])
	case strings.HasPrefix(eventType, "service_account.") && strings.TrimSpace(attrs["service_account_id"]) != "":
		return aiEnsureServiceAccount(entities, tenantID, sourceID, profile, attrs["service_account_id"], attrs["name"], attrs["role"], attrs)
	case strings.HasPrefix(eventType, "group.") && strings.TrimSpace(attrs["group_id"]) != "":
		return aiEnsureGroup(entities, tenantID, sourceID, profile, attrs)
	case strings.HasPrefix(eventType, "role.assignment.") && strings.TrimSpace(attrs["resource_id"]) != "":
		return aiAuditResourceURN(entities, links, tenantID, event, profile, attrs["resource_id"], attrs["resource_type"], attrs)
	case strings.HasPrefix(eventType, "role.assignment.") && strings.TrimSpace(attrs["principal_id"]) != "":
		return aiAuditPrincipalURN(entities, links, tenantID, event, profile, attrs["principal_id"], attrs["principal_type"], attrs)
	case strings.HasPrefix(eventType, "role.") && strings.TrimSpace(attrs["role_id"]) != "":
		return aiEnsureRole(entities, tenantID, sourceID, profile, attrs, aiAuditRoleScopeKind(attrs))
	case firstNonEmpty(attrs["claude_chat_id"], attrs["chat_id"]) != "":
		return aiAuditActivityResourceURN(entities, links, tenantID, event, profile, firstNonEmpty(attrs["claude_chat_id"], attrs["chat_id"]), "claude_chat", attrs)
	case firstNonEmpty(attrs["claude_file_id"], attrs["file_id"]) != "":
		return aiAuditActivityResourceURN(entities, links, tenantID, event, profile, firstNonEmpty(attrs["claude_file_id"], attrs["file_id"]), "claude_file", attrs)
	case strings.HasPrefix(eventType, "project.") && strings.TrimSpace(attrs["project_id"]) != "":
		return aiEnsureProject(entities, tenantID, sourceID, profile, attrs)
	case strings.TrimSpace(attrs["claude_project_id"]) != "":
		projectAttrs := cloneAttributes(attrs)
		projectAttrs["project_id"] = attrs["claude_project_id"]
		return aiEnsureProject(entities, tenantID, sourceID, profile, projectAttrs)
	case strings.TrimSpace(attrs["project_id"]) != "":
		return aiEnsureProject(entities, tenantID, sourceID, profile, attrs)
	case strings.TrimSpace(attrs["api_key_id"]) != "":
		return aiEnsureCredential(entities, tenantID, sourceID, profile, attrs["api_key_id"], attrs)
	case strings.TrimSpace(attrs["user_id"]) != "" || strings.TrimSpace(attrs["email"]) != "":
		return aiEnsureUser(entities, links, tenantID, event, profile, attrs["user_id"], attrs["email"], attrs["name"], attrs["role"])
	case strings.TrimSpace(attrs["service_account_id"]) != "":
		return aiEnsureServiceAccount(entities, tenantID, sourceID, profile, attrs["service_account_id"], attrs["name"], attrs["role"], attrs)
	case strings.TrimSpace(attrs["group_id"]) != "":
		return aiEnsureGroup(entities, tenantID, sourceID, profile, attrs)
	case strings.TrimSpace(attrs["role_id"]) != "":
		return aiEnsureRole(entities, tenantID, sourceID, profile, attrs, aiAuditRoleScopeKind(attrs))
	case strings.TrimSpace(attrs["resource_id"]) != "":
		return aiAuditResourceURN(entities, links, tenantID, event, profile, attrs["resource_id"], attrs["resource_type"], attrs)
	case strings.TrimSpace(attrs["organization_id"]) != "" || strings.TrimSpace(attrs["organization_uuid"]) != "":
		return aiEnsureOrganization(entities, tenantID, sourceID, profile, attrs)
	default:
		return aiEnsureOrganization(entities, tenantID, sourceID, profile, attrs)
	}
}

func aiAuditCredentialOwnerURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, userID string, serviceAccountID string, email string) string {
	if strings.TrimSpace(serviceAccountID) != "" {
		return aiEnsureServiceAccount(entities, tenantID, event.GetSourceId(), profile, serviceAccountID, "", "", event.GetAttributes())
	}
	if strings.TrimSpace(userID) != "" || strings.TrimSpace(email) != "" {
		return aiEnsureUser(entities, links, tenantID, event, profile, userID, email, "", "")
	}
	return ""
}

func aiAuditActivityResourceURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, resourceID string, resourceType string, attrs map[string]string) string {
	resourceAttrs := cloneAttributes(attrs)
	resourceAttrs["resource_id"] = resourceID
	resourceAttrs["resource_type"] = resourceType
	resourceURN := aiAuditResourceURN(entities, links, tenantID, event, profile, resourceID, resourceType, resourceAttrs)
	if resourceURN == "" {
		return ""
	}
	projectID := firstNonEmpty(attrs["claude_project_id"], attrs["project_id"])
	if projectID == "" {
		return resourceURN
	}
	projectAttrs := cloneAttributes(attrs)
	projectAttrs["project_id"] = projectID
	projectURN := aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, projectAttrs)
	if projectURN == "" {
		return resourceURN
	}
	linkAttrs := aiEventLinkAttributes(event, "audit_activity_resource_project")
	addProjectedAttribute(linkAttrs, "resource_id", resourceID)
	addProjectedAttribute(linkAttrs, "resource_type", resourceType)
	addProjectedAttribute(linkAttrs, "project_id", projectID)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, projectURN, relationBelongsTo, linkAttrs))
	return resourceURN
}

func aiAuditPrincipalURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, principalID string, principalType string, attrs map[string]string) string {
	normalizedType := normalizeIdentifier(principalType)
	switch {
	case strings.Contains(normalizedType, "group"):
		groupAttrs := cloneAttributes(attrs)
		groupAttrs["group_id"] = principalID
		return aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, groupAttrs)
	case strings.Contains(normalizedType, "service_account") || strings.Contains(normalizedType, "serviceaccount"):
		return aiEnsureServiceAccount(entities, tenantID, event.GetSourceId(), profile, principalID, attrs["name"], attrs["role"], attrs)
	case strings.Contains(normalizedType, "role"):
		roleAttrs := cloneAttributes(attrs)
		roleAttrs["role_id"] = principalID
		return aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, aiAuditRoleScopeKind(attrs))
	case normalizedType == "" || strings.Contains(normalizedType, "user"):
		return aiEnsureUser(entities, links, tenantID, event, profile, principalID, attrs["email"], attrs["name"], attrs["role"])
	default:
		return aiAuditResourceURN(entities, links, tenantID, event, profile, principalID, principalType, attrs)
	}
}

func aiAuditResourceURN(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile aiAccessProfile, resourceID string, resourceType string, attrs map[string]string) string {
	switch identityPrincipalType(resourceType) {
	case "group":
		groupAttrs := cloneAttributes(attrs)
		groupAttrs["group_id"] = resourceID
		return aiEnsureGroup(entities, tenantID, event.GetSourceId(), profile, groupAttrs)
	case "service_account":
		return aiEnsureServiceAccount(entities, tenantID, event.GetSourceId(), profile, resourceID, attrs["name"], attrs["role"], attrs)
	case "role":
		roleAttrs := cloneAttributes(attrs)
		roleAttrs["role_id"] = resourceID
		return aiEnsureRole(entities, tenantID, event.GetSourceId(), profile, roleAttrs, aiAuditRoleScopeKind(attrs))
	}
	normalizedType := normalizeIdentifier(resourceType)
	switch {
	case strings.Contains(normalizedType, "project"):
		projectAttrs := cloneAttributes(attrs)
		projectAttrs["project_id"] = resourceID
		return aiEnsureProject(entities, tenantID, event.GetSourceId(), profile, projectAttrs)
	case strings.Contains(normalizedType, "organization") || normalizedType == "org":
		orgAttrs := cloneAttributes(attrs)
		orgAttrs["organization_id"] = resourceID
		return aiEnsureOrganization(entities, tenantID, event.GetSourceId(), profile, orgAttrs)
	case strings.Contains(normalizedType, "user"):
		return aiEnsureUser(entities, links, tenantID, event, profile, resourceID, attrs["email"], attrs["name"], attrs["role"])
	default:
		resourceType = firstNonEmpty(resourceType, "resource")
		resourceURN := projectionURN(tenantID, profile.Provider+"_resource", resourceType, resourceID)
		if resourceURN == "" {
			return ""
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.Provider + ".resource",
			Label:      firstNonEmpty(attrs["name"], resourceID),
			Attributes: compactAttributes(map[string]string{
				"activity_type":     attrs["activity_type"],
				"claude_project_id": attrs["claude_project_id"],
				"created_at":        attrs["created_at"],
				"family":            attrs["family"],
				"filename":          attrs["filename"],
				"project_id":        attrs["project_id"],
				"provider":          attrs["provider"],
				"resource_id":       resourceID,
				"resource_type":     resourceType,
			}),
		})
		return resourceURN
	}
}

func aiAuditRoleScopeKind(attrs map[string]string) string {
	resourceType := normalizeIdentifier(attrs["resource_type"])
	switch {
	case strings.TrimSpace(attrs["project_id"]) != "" || strings.Contains(resourceType, "project"):
		return "project"
	default:
		return "organization"
	}
}

func aiInviteAccessState(status string) string {
	normalized := normalizeIdentifier(status)
	switch {
	case normalized == "":
		return "invited"
	case strings.Contains(normalized, "pending") || strings.Contains(normalized, "sent") || strings.Contains(normalized, "invited"):
		return "invited"
	case strings.Contains(normalized, "accept"):
		return "accepted"
	case strings.Contains(normalized, "expir"):
		return "expired"
	case strings.Contains(normalized, "revok") || strings.Contains(normalized, "cancel") || strings.Contains(normalized, "delete") || strings.Contains(normalized, "declin"):
		return "inactive"
	default:
		return normalized
	}
}

func aiInviteAccessIntentActive(status string) bool {
	switch aiInviteAccessState(status) {
	case "invited", "accepted":
		return true
	default:
		return false
	}
}

func aiInviteProjectMemberships(event *cerebrov1.EventEnvelope) []aiInviteProjectMembership {
	if len(event.GetPayload()) == 0 {
		return nil
	}
	var payload struct {
		Projects []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return nil
	}
	memberships := make([]aiInviteProjectMembership, 0, len(payload.Projects))
	seen := map[string]struct{}{}
	for _, project := range payload.Projects {
		projectID := strings.TrimSpace(project.ID)
		if projectID == "" {
			continue
		}
		role := strings.TrimSpace(project.Role)
		key := projectID + "\x00" + role
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		memberships = append(memberships, aiInviteProjectMembership{ProjectID: projectID, Role: role})
	}
	return memberships
}

func aiRoleID(attrs map[string]string) string {
	return firstNonEmpty(attrs["role_id"], attrs["role"], attrs["name"], attrs["role_name"], attrs["predefined_role"])
}

func aiRolePermissionID(attrs map[string]string, fallback string) string {
	return firstNonEmpty(attrs["permission_id"], attrs["permission"], attrs["permission_name"], attrs["name"], fallback)
}

func aiRolePermissionCapabilityID(attrs map[string]string) string {
	normalized := normalizeIdentifier(strings.Join([]string{
		attrs["permission_id"],
		attrs["permission"],
		attrs["permission_name"],
		attrs["action"],
		attrs["resource_type"],
		attrs["scope"],
		attrs["category"],
	}, " "))
	switch {
	case strings.Contains(normalized, "delete") || strings.Contains(normalized, "destroy") || strings.Contains(normalized, "purge"):
		return "ai_data_delete"
	case strings.Contains(normalized, "admin") || strings.Contains(normalized, "manage") || strings.Contains(normalized, "write") || strings.Contains(normalized, "create") || strings.Contains(normalized, "update"):
		return "ai_admin"
	case strings.Contains(normalized, "read") || strings.Contains(normalized, "view") || strings.Contains(normalized, "list") || strings.Contains(normalized, "export"):
		return "ai_data_read"
	default:
		return "ai_compliance_access"
	}
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
		orgID := firstNonEmpty(attrs["organization_id"], attrs["organization_uuid"])
		return firstNonEmpty(joinScopedProjectionIdentity(orgID, attrs, "retention_type", "object"), joinProjectionIdentity(attrs, "retention_type", "object"), fallback)
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
		orgID := firstNonEmpty(attrs["organization_uuid"], attrs["organization_id"])
		return firstNonEmpty(joinScopedProjectionIdentity(orgID, attrs, "setting_name", "name"), fallback)
	}
	return firstNonEmpty(inventoryEntityID("", family, attrs), fallback)
}

func joinScopedProjectionIdentity(scopeID string, attrs map[string]string, keys ...string) string {
	values := []string{}
	if scopeID = strings.TrimSpace(scopeID); scopeID != "" {
		values = append(values, scopeID)
	}
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, "|")
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
