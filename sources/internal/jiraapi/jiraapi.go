package jiraapi

import (
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID               = "jira"
	DefaultFamily          = FamilyUsers
	DefaultHealthPath      = "/rest/api/3/myself"
	DefaultBaseURLTemplate = "https://${config.site_url}"
	TokenScheme            = "Basic"

	FamilyUsers             = "users"
	FamilyGroups            = "groups"
	FamilyGroupMembers      = "group_members"
	FamilyProjects          = "projects"
	FamilyProjectRoles      = "project_roles"
	FamilyPermissionSchemes = "permission_schemes"
	FamilyAuditEvents       = "audit_events"
)

var TemplateKeys = []string{"password", "username", "site_url"}

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		usersFamily(),
		groupsFamily(),
		groupMembersFamily(),
		projectsFamily(),
		projectRolesFamily(),
		permissionSchemesFamily(),
		auditEventsFamily(),
	}
}

func FamilyNames() []string {
	families := Families()
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.Name)
	}
	return names
}

func PathParamValues(cfg sourcecdk.Config, family string) (string, []string) {
	switch strings.TrimSpace(family) {
	case FamilyGroupMembers:
		return "group_id", configListValues(cfg, "group_ids", "group_id")
	case FamilyProjectRoles:
		return "project_id_or_key", configListValues(cfg, "project_id_or_keys", "project_ids", "project_keys", "project_id", "project_key")
	default:
		return "", nil
	}
}

func usersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyUsers,
		Path:            "/rest/api/3/users/search",
		URNKind:         "jira_users",
		IDKeys:          []string{"accountId", "account_id", "user_id", "id", "emailAddress"},
		CursorParam:     "startAt",
		PageFirstCursor: "0",
		PageSizeParams:  []string{"maxResults"},
		TimestampKeys:   []string{"updated_at", "last_seen_at", "created_at"},
		Attributes: map[string]string{
			"account_id":      "accountId",
			"account_type":    "accountType",
			"avatar_url":      "avatarUrls.48x48|avatarUrls.32x32|avatarUrls.24x24|avatarUrls.16x16",
			"display_name":    "displayName|name",
			"email":           "emailAddress|email",
			"login":           "emailAddress|accountId",
			"locale":          "locale",
			"resource_id":     "accountId",
			"resource_name":   "displayName|name|emailAddress|accountId",
			"source_event_id": "accountId",
			"status":          "active",
			"time_zone":       "timeZone",
			"user_id":         "accountId",
		},
		StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "identity_user", "schema": FamilyUsers, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "jira_users"},
	}
}

func groupsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyGroups,
		Path:            "/rest/api/3/group/bulk",
		URNKind:         "jira_groups",
		IDKeys:          []string{"groupId", "group_id", "id", "name"},
		CursorParam:     "startAt",
		NextCursorKeys:  []string{"nextPage"},
		PageFirstCursor: "0",
		PageSizeParams:  []string{"maxResults"},
		ListKeys:        []string{"values"},
		Attributes: map[string]string{
			"description":     "description",
			"group_id":        "groupId|id",
			"group_name":      "name|displayName",
			"resource_id":     "groupId|id|name",
			"resource_name":   "name|displayName|groupId",
			"source_event_id": "groupId|id|name",
		},
		StaticAttributes: map[string]string{"record_class": "identity_group", "resource_type": "identity_group", "schema": FamilyGroups, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "jira_groups"},
	}
}

func groupMembersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyGroupMembers,
		Path:            "/rest/api/3/group/member",
		PathParams:      []string{"group_id"},
		URNKind:         "jira_group_members",
		IDKeys:          []string{"accountId", "account_id", "user_id", "emailAddress"},
		CursorParam:     "startAt",
		NextCursorKeys:  []string{"nextPage"},
		PageFirstCursor: "0",
		PageSizeParams:  []string{"maxResults"},
		ListKeys:        []string{"values"},
		Attributes: map[string]string{
			"account_id":      "accountId",
			"display_name":    "displayName|name",
			"email":           "emailAddress|email",
			"group_id":        "group_id",
			"member_email":    "emailAddress|email",
			"member_name":     "displayName|name",
			"member_status":   "active",
			"account_type":    "accountType",
			"member_user_id":  "accountId",
			"resource_id":     "accountId",
			"resource_name":   "displayName|name|emailAddress|accountId",
			"source_event_id": "accountId",
			"user_id":         "accountId",
		},
		StaticAttributes: map[string]string{"member_type": "user", "record_class": "identity_group_membership", "resource_type": "group_membership", "schema": FamilyGroupMembers, "source_system": SourceID},
		Config: jsonapi.FamilyConfig{
			ConfigQuery:     map[string]string{"groupId": "group_id"},
			EncodeURNID:     true,
			IdentityKeys:    []string{"group_id"},
			StaticQuery:     map[string]string{"includeInactiveUsers": "true"},
			ResourceURNKind: "jira_users",
		},
	}
}

func projectsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyProjects,
		Path:            "/rest/api/3/project/search",
		URNKind:         "jira_projects",
		IDKeys:          []string{"id", "uuid", "key", "self"},
		CursorParam:     "startAt",
		NextCursorKeys:  []string{"nextPage"},
		PageFirstCursor: "0",
		PageSizeParams:  []string{"maxResults"},
		ListKeys:        []string{"values"},
		TimestampKeys:   []string{"insight.lastIssueUpdateTime", "archivedDate", "deletedDate", "updated_at", "created_at"},
		Attributes: map[string]string{
			"archived":        "archived",
			"category_id":     "projectCategory.id",
			"category_name":   "projectCategory.name",
			"deleted":         "deleted",
			"lead_user_id":    "lead.accountId",
			"project_id":      "id",
			"project_key":     "key",
			"project_name":    "name",
			"project_type":    "projectTypeKey",
			"project_uuid":    "uuid",
			"resource_id":     "id",
			"resource_name":   "name|key|id",
			"resource_type":   "project",
			"self_url":        "self",
			"simplified":      "simplified",
			"source_event_id": "id",
			"style":           "style",
			"updated_at":      "insight.lastIssueUpdateTime|archivedDate|deletedDate",
		},
		StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "project", "schema": FamilyProjects, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "jira_projects"},
	}
}

func projectRolesFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:                  FamilyProjectRoles,
		Path:                  "/rest/api/3/project/{project_id_or_key}/roledetails",
		DetailPath:            "/rest/api/3/project/{project_id_or_key}/role/{id}",
		AllowBareDetailRecord: true,
		PathParams:            []string{"project_id_or_key"},
		URNKind:               "jira_project_roles",
		IDKeys:                []string{"id", "self", "name"},
		DisablePageSize:       true,
		Attributes: map[string]string{
			"admin":             "admin",
			"default":           "default",
			"description":       "description",
			"project_id":        "scope.project.id|project.id|projectId|project_id",
			"project_id_or_key": "project_id_or_key",
			"project_key":       "scope.project.key|project.key|projectKey|project_id_or_key",
			"resource_id":       "id|self",
			"resource_name":     "name|translatedName|id",
			"resource_type":     "project_role",
			"role_configurable": "roleConfigurable",
			"role_id":           "id",
			"role_name":         "name|translatedName",
			"role_type":         "scope.type",
			"self_url":          "self",
			"source_event_id":   "id|self",
		},
		StaticAttributes: map[string]string{"record_class": "identity_role_assignment", "resource_type": "project_role", "schema": FamilyProjectRoles, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, IdentityKeys: []string{"project_id_or_key"}, RequireDetail: true, ResourceURNKind: "jira_project_roles"},
	}
}

func permissionSchemesFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyPermissionSchemes,
		Path:            "/rest/api/3/permissionscheme",
		URNKind:         "jira_permission_schemes",
		IDKeys:          []string{"id", "name", "self"},
		DisablePageSize: true,
		ListKeys:        []string{"permissionSchemes"},
		Attributes: map[string]string{
			"description":     "description",
			"policy_id":       "id",
			"policy_name":     "name",
			"policy_type":     "permission_scheme",
			"resource_id":     "id",
			"resource_name":   "name|id",
			"resource_type":   "permission_scheme",
			"self_url":        "self",
			"source_event_id": "id",
		},
		StaticAttributes: map[string]string{"policy_type": "permission_scheme", "record_class": "policy", "resource_type": "permission_scheme", "schema": FamilyPermissionSchemes, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{StaticQuery: map[string]string{"expand": "permissions"}, EncodeURNID: true, ResourceURNKind: "jira_permission_schemes"},
	}
}

func auditEventsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyAuditEvents,
		Path:            "/rest/api/3/auditing/record",
		URNKind:         "jira_audit_events",
		IDKeys:          []string{"id", "event_id", "uuid", "request_id"},
		CursorParam:     "offset",
		PageFirstCursor: "0",
		PageSizeParams:  []string{"limit"},
		ListKeys:        []string{"records"},
		TimestampKeys:   []string{"created"},
		Attributes: map[string]string{
			"actor_id":        "authorAccountId|actor_id|actor.id|user.id",
			"actor_name":      "authorKey|actor.name|user.name",
			"category":        "category",
			"changed_values":  "changedValues",
			"created_at":      "created",
			"event_source":    "eventSource",
			"event_type":      "summary|category|eventSource",
			"id":              "id",
			"remote_address":  "remoteAddress",
			"resource_id":     "objectItem.id",
			"resource_name":   "objectItem.name",
			"resource_type":   "objectItem.typeName",
			"source_event_id": "id",
			"summary":         "summary",
		},
		StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "audit_event", "schema": FamilyAuditEvents, "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "jira_audit_events"},
	}
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		raw := strings.TrimSpace(sourcecdk.ConfigValue(cfg, key))
		if raw == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			if value := strings.TrimSpace(part); value != "" {
				values = append(values, value)
			}
		}
	}
	return compactUnique(values)
}

func compactUnique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
