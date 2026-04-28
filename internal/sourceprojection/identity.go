package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func oktaGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, "okta")
}

func oktaGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, "okta")
}

func oktaApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, "okta")
}

func oktaAppAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAppAssignmentProjections(event, "okta")
}

func oktaAdminRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, "okta")
}

func googleWorkspaceUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, "google_workspace")
}

func googleWorkspaceGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, "google_workspace")
}

func googleWorkspaceGroupMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, "google_workspace")
}

func googleWorkspaceRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, "google_workspace")
}

func googleWorkspaceAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, "google_workspace")
}

func identityUserProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	userID := firstNonEmpty(attributes["user_id"], attributes["id"], attributes["primary_email"], attributes["email"], attributes["login"])
	email := firstNonEmpty(attributes["email"], attributes["primary_email"], attributes["login"])
	login := firstNonEmpty(attributes["login"], attributes["primary_email"], attributes["email"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := identityOrgURN(tenantID, provider, domain)
	addIdentityOrg(entities, tenantID, event.GetSourceId(), provider, domain, orgURN)

	userURN := identityUserURN(tenantID, provider, userID, email)
	if userURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".user",
			Label:      firstNonEmpty(attributes["display_name"], attributes["name"], email, login, userID),
			Attributes: map[string]string{
				"domain":             domain,
				"user_id":            userID,
				"email":              email,
				"login":              login,
				"status":             strings.TrimSpace(attributes["status"]),
				"created_at":         firstNonEmpty(attributes["created_at"], attributes["creation_time"]),
				"last_login_at":      firstNonEmpty(attributes["last_login_at"], attributes["last_login_time"]),
				"is_admin":           firstNonEmpty(attributes["is_admin"], attributes["admin"]),
				"is_delegated_admin": strings.TrimSpace(attributes["is_delegated_admin"]),
				"mfa_enrolled":       firstNonEmpty(attributes["mfa_enrolled"], attributes["is_enrolled_in_2sv"]),
				"mfa_enforced":       firstNonEmpty(attributes["mfa_enforced"], attributes["is_enforced_in_2sv"]),
				"suspended":          strings.TrimSpace(attributes["suspended"]),
				"archived":           strings.TrimSpace(attributes["archived"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), userURN, email)
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), userURN, login)
		}
	}
	return identityProjectionResult(entities, links)
}

func identityGroupProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	groupID := firstNonEmpty(attributes["group_id"], attributes["id"], attributes["group_email"], attributes["email"])
	groupEmail := firstNonEmpty(attributes["group_email"], attributes["email"])
	groupURN := identityGroupURN(tenantID, provider, groupID, groupEmail)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := identityOrgURN(tenantID, provider, domain)
	addIdentityOrg(entities, tenantID, event.GetSourceId(), provider, domain, orgURN)
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".group",
			Label:      firstNonEmpty(attributes["group_name"], attributes["name"], groupEmail, groupID),
			Attributes: map[string]string{
				"domain":             domain,
				"group_id":           groupID,
				"group_email":        groupEmail,
				"group_name":         firstNonEmpty(attributes["group_name"], attributes["name"]),
				"description":        strings.TrimSpace(attributes["description"]),
				"admin_created":      strings.TrimSpace(attributes["admin_created"]),
				"direct_members":     strings.TrimSpace(attributes["direct_members_count"]),
				"non_editable_alias": strings.TrimSpace(attributes["non_editable_alias"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), groupURN, groupEmail)
	}
	return identityProjectionResult(entities, links)
}

func identityGroupMembershipProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	groupURN := identityGroupURN(tenantID, provider, attributes["group_id"], firstNonEmpty(attributes["group_email"], attributes["email"]))
	memberEmail := firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"])
	memberID := firstNonEmpty(attributes["member_user_id"], attributes["user_id"], attributes["member_id"], memberEmail)
	memberType := strings.ToLower(firstNonEmpty(attributes["member_type"], attributes["type"], "user"))
	memberURN := identityPrincipalURN(tenantID, provider, memberType, memberID, memberEmail)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".group",
			Label:      firstNonEmpty(attributes["group_name"], attributes["group_email"], attributes["group_id"]),
			Attributes: map[string]string{
				"group_id":    strings.TrimSpace(attributes["group_id"]),
				"group_email": strings.TrimSpace(attributes["group_email"]),
			},
		})
	}
	if memberURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        memberURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + "." + identityPrincipalType(memberType),
			Label:      firstNonEmpty(attributes["member_name"], memberEmail, memberID),
			Attributes: map[string]string{
				"email":       memberEmail,
				"member_id":   memberID,
				"member_type": memberType,
				"role":        strings.TrimSpace(attributes["role"]),
				"status":      strings.TrimSpace(attributes["member_status"]),
			},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), memberURN, memberEmail)
		if groupURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, groupURN, relationMemberOf, map[string]string{
				"event_id": event.GetId(),
				"role":     strings.TrimSpace(attributes["role"]),
			}))
		}
	}
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), groupURN, firstNonEmpty(attributes["group_email"], attributes["group_id"]))
	return identityProjectionResult(entities, links)
}

func identityApplicationProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	appURN := identityApplicationURN(tenantID, provider, firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"], attributes["id"]))
	entities := map[string]*ports.ProjectedEntity{}
	if appURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        appURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".application",
			Label:      firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"], attributes["client_id"], attributes["app_id"]),
			Attributes: map[string]string{
				"app_id":      firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"], attributes["id"]),
				"app_name":    firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"]),
				"oauth2":      strings.TrimSpace(attributes["oauth2"]),
				"saml":        strings.TrimSpace(attributes["saml"]),
				"domain_wide": strings.TrimSpace(attributes["domain_wide_delegation"]),
			},
		})
	}
	return identityProjectionResult(entities, nil)
}

func identityAppAssignmentProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["user_id"], attributes["group_id"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	appURN := identityApplicationURN(tenantID, provider, firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"]))
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + "." + identityPrincipalType(subjectType),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), subjectURN, subjectEmail)
	}
	if appURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        appURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".application",
			Label:      firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["client_id"], attributes["app_id"]),
			Attributes: map[string]string{"app_id": firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"])},
		})
	}
	if subjectURN != "" && appURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, appURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func identityRoleAssignmentProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["assigned_to"], attributes["user_id"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	roleID := firstNonEmpty(attributes["role_id"], attributes["role_assignment_id"], attributes["role_name"], attributes["role_type"])
	roleURN := projectionURN(tenantID, provider+"_admin_role", roleID)
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + "." + identityPrincipalType(subjectType),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType, "is_admin": "true"},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), subjectURN, subjectEmail)
	}
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".admin_role",
			Label:      firstNonEmpty(attributes["role_name"], attributes["role_type"], roleID),
			Attributes: map[string]string{"role_id": roleID, "role_type": strings.TrimSpace(attributes["role_type"])},
		})
	}
	if subjectURN != "" && roleURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, roleURN, relationCanAdmin, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func identityAuditProjections(event *cerebrov1.EventEnvelope, provider string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	actorEmail := firstNonEmpty(attributes["actor_email"], attributes["actor_alternate_id"], attributes["email"])
	actorURN := identityUserURN(tenantID, provider, firstNonEmpty(attributes["actor_id"], actorEmail), actorEmail)
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["target_id"], attributes["app_id"], attributes["group_id"], attributes["role_id"])
	resourceType := normalizeIdentifier(firstNonEmpty(attributes["resource_type"], attributes["target_type"], "resource"))
	resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + ".user",
			Label:      firstNonEmpty(attributes["actor_name"], actorEmail, attributes["actor_id"]),
			Attributes: map[string]string{"email": actorEmail, "actor_id": strings.TrimSpace(attributes["actor_id"])},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), actorURN, actorEmail)
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["target_name"], resourceID),
			Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType},
		})
	}
	if actorURN != "" && resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, map[string]string{
			"event_id":   event.GetId(),
			"event_type": firstNonEmpty(attributes["event_type"], attributes["event_name"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func identityProjectionResult(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addIdentityOrg(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, provider string, domain string, orgURN string) {
	if orgURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        orgURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: provider + ".org",
		Label:      domain,
		Attributes: map[string]string{"domain": domain},
	})
}

func identityOrgURN(tenantID string, provider string, domain string) string {
	return projectionURN(tenantID, provider+"_org", domain)
}

func identityUserURN(tenantID string, provider string, userID string, email string) string {
	if trimmed := strings.TrimSpace(userID); trimmed != "" {
		return projectionURN(tenantID, provider+"_user", trimmed)
	}
	if normalizedEmail := normalizeIdentifier(email); normalizedEmail != "" {
		return projectionURN(tenantID, provider+"_user", "email", normalizedEmail)
	}
	return ""
}

func identityGroupURN(tenantID string, provider string, groupID string, groupEmail string) string {
	if trimmed := strings.TrimSpace(groupID); trimmed != "" {
		return projectionURN(tenantID, provider+"_group", trimmed)
	}
	if normalizedEmail := normalizeIdentifier(groupEmail); normalizedEmail != "" {
		return projectionURN(tenantID, provider+"_group", "email", normalizedEmail)
	}
	return ""
}

func identityApplicationURN(tenantID string, provider string, appID string) string {
	return projectionURN(tenantID, provider+"_application", appID)
}

func identityPrincipalURN(tenantID string, provider string, principalType string, principalID string, email string) string {
	switch identityPrincipalType(principalType) {
	case "group":
		return identityGroupURN(tenantID, provider, principalID, email)
	default:
		return identityUserURN(tenantID, provider, principalID, email)
	}
}

func identityPrincipalType(value string) string {
	normalized := normalizeIdentifier(value)
	if strings.Contains(normalized, "group") {
		return "group"
	}
	return "user"
}
