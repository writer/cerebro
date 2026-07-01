package oneloginapi

import (
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID                  = "onelogin"
	DefaultFamily             = FamilyUsers
	DefaultBaseURLTemplate    = "https://${config.subdomain}.onelogin.com"
	OAuthTokenURLTemplate     = "https://${config.subdomain}.onelogin.com/auth/oauth2/v2/token" // #nosec G101 -- endpoint template, not credential material.
	DefaultHealthPath         = "/api/2/users?limit=1"
	TokenScheme               = "bearer:"
	FamilyUsers               = "users"
	FamilyGroups              = "groups"
	FamilyRoles               = "roles"
	FamilyApps                = "apps"
	FamilyAuditEvents         = "audit_events"
	FamilyPrivileges          = "privileges"
	FamilyMappings            = "mappings"
	FamilyUserApps            = "user_apps"
	FamilyUserPrivileges      = "user_privileges"
	FamilyDelegatedPrivileges = "delegated_privileges"
	FamilyMFADevices          = "mfa_devices"
	FamilyRoleUsers           = "role_users"
	FamilyRoleAdmins          = "role_admins"
	FamilyRoleApps            = "role_apps"
	FamilyAppUsers            = "app_users"
	FamilyAppRules            = "app_rules"
	FamilyPrivilegeUsers      = "privilege_users"
	FamilyPrivilegeRoles      = "privilege_roles"
)

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		usersFamily(),
		groupsFamily(),
		rolesFamily(),
		appsFamily(),
		auditEventsFamily(),
		privilegesFamily(),
		mappingsFamily(),
		userAppsFamily(),
		userPrivilegesFamily(),
		delegatedPrivilegesFamily(),
		mfaDevicesFamily(),
		roleUsersFamily(),
		roleAdminsFamily(),
		roleAppsFamily(),
		appUsersFamily(),
		appRulesFamily(),
		privilegeUsersFamily(),
		privilegeRolesFamily(),
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

func FamilyName(cfg sourcecdk.Config) string {
	if family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")); family != "" {
		return family
	}
	return DefaultFamily
}

func PathParamValues(cfg sourcecdk.Config) (string, []string) {
	switch FamilyName(cfg) {
	case FamilyUserApps, FamilyUserPrivileges, FamilyDelegatedPrivileges, FamilyMFADevices:
		return "user_id", ConfigListValues(cfg, "user_ids", "user_id")
	case FamilyRoleUsers, FamilyRoleAdmins, FamilyRoleApps:
		return "role_id", ConfigListValues(cfg, "role_ids", "role_id")
	case FamilyAppUsers, FamilyAppRules:
		return "app_id", ConfigListValues(cfg, "app_ids", "app_id")
	case FamilyPrivilegeUsers, FamilyPrivilegeRoles:
		return "privilege_id", ConfigListValues(cfg, "privilege_ids", "privilege_id")
	default:
		return "", nil
	}
}

func usersFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:          FamilyUsers,
		Path:          "/api/2/users",
		URNKind:       "onelogin_users",
		IDKeys:        []string{"id", "email", "username"},
		TimestampKeys: []string{"updated_at", "created_at", "last_login"},
		Attributes: map[string]string{
			"user_id":           "id",
			"source_event_id":   "id",
			"email":             "email",
			"primary_email":     "email",
			"login":             "username|email",
			"display_name":      "name|display_name|firstname|username|email",
			"first_name":        "firstname|first_name",
			"last_name":         "lastname|last_name",
			"department":        "department",
			"job_title":         "title|job_title",
			"manager_id":        "manager_ad_id|manager_id",
			"group_id":          "group_id",
			"role_ids":          "role_ids",
			"directory_id":      "directory_id",
			"external_id":       "external_id",
			"status":            "status|state",
			"state":             "state",
			"trusted_idp_id":    "trusted_idp_id",
			"created_at":        "created_at",
			"updated_at":        "updated_at",
			"last_login_at":     "last_login",
			"activated_at":      "activated_at",
			"locked_until":      "locked_until",
			"mfa_enrolled":      "mfa_enrolled|otp_devices_count",
			"resource_id":       "id",
			"resource_name":     "name|display_name|username|email",
			"resource_type":     "user",
			"observed_at":       "updated_at|created_at|last_login",
			"source_system_id":  "id",
			"source_system_url": "url",
		},
		StaticAttributes: staticAttributes("users", "identity_user", "identity_user"),
	})
}

func groupsFamily() jsonapi.Family {
	return v1PagedFamily(jsonapi.Family{
		Name:          FamilyGroups,
		Path:          "/api/1/groups",
		URNKind:       "onelogin_groups",
		IDKeys:        []string{"id", "name"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"updated_at", "created_at"},
		Attributes: map[string]string{
			"group_id":        "id",
			"source_event_id": "id",
			"group_name":      "name",
			"description":     "description",
			"reference":       "reference",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "group",
			"observed_at":     "updated_at|created_at",
		},
		StaticAttributes: staticAttributes("groups", "identity_group", "identity_group"),
	})
}

func rolesFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:          FamilyRoles,
		Path:          "/api/2/roles",
		URNKind:       "onelogin_roles",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"updated_at", "created_at"},
		Attributes: map[string]string{
			"group_id":        "id",
			"role_id":         "id",
			"source_event_id": "id",
			"group_name":      "name",
			"role_name":       "name",
			"description":     "description",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "role",
			"observed_at":     "updated_at|created_at",
		},
		StaticAttributes: staticAttributes("roles", "identity_group", "role"),
	})
}

func appsFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:          FamilyApps,
		Path:          "/api/2/apps",
		URNKind:       "onelogin_apps",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"updated_at", "created_at"},
		Attributes: map[string]string{
			"app_id":               "id",
			"application_id":       "id",
			"source_event_id":      "id",
			"app_name":             "name",
			"app_label":            "name",
			"name":                 "name",
			"description":          "description",
			"connector_id":         "connector_id",
			"auth_method":          "auth_method",
			"sign_on_mode":         "auth_method_description|auth_method",
			"policy_id":            "policy_id",
			"visible":              "visible",
			"provisioning_status":  "provisioning_status",
			"provisioning_state":   "provisioning_state",
			"provisioning_enabled": "provisioning_enabled",
			"resource_id":          "id",
			"resource_name":        "name",
			"resource_type":        "application",
			"observed_at":          "updated_at|created_at",
		},
		StaticAttributes: staticAttributes("apps", "identity_application", "application"),
	})
}

func auditEventsFamily() jsonapi.Family {
	return v1PagedFamily(jsonapi.Family{
		Name:          FamilyAuditEvents,
		Path:          "/api/1/events",
		URNKind:       "onelogin_audit_events",
		IDKeys:        []string{"id", "event_id", "uuid", "request_id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"created_at", "updated_at", "observed_at"},
		Attributes: map[string]string{
			"id":              "id",
			"source_event_id": "id",
			"event_type":      "event_type|event_type_id|type|action",
			"event_type_id":   "event_type_id",
			"actor_id":        "actor_user_id|user_id|user.id|actor.id",
			"actor_email":     "user.email|actor.email|email",
			"actor_name":      "user.name|actor.name",
			"actor_type":      "actor_type|user.type",
			"resource_id":     "app_id|group_id|role_id|object_id|target_id|id",
			"resource_name":   "app_name|group_name|role_name|object_name|target_name",
			"resource_type":   "resource_type|object_type|target_type",
			"resource_email":  "target_email|user.email",
			"app_id":          "app_id",
			"group_id":        "group_id",
			"role_id":         "role_id",
			"ip_address":      "ipaddr|ip_address|client_ip",
			"notes":           "notes",
			"created_at":      "created_at",
			"observed_at":     "created_at|updated_at|observed_at",
		},
		StaticAttributes: staticAttributes("audit_events", "audit_event", "audit_event"),
	})
}

func privilegesFamily() jsonapi.Family {
	return staticFamily(jsonapi.Family{
		Name:    FamilyPrivileges,
		Path:    "/api/1/privileges",
		URNKind: "onelogin_privileges",
		IDKeys:  []string{"id", "name"},
		Attributes: map[string]string{
			"role_id":          "id",
			"role_name":        "name",
			"role_type":        "privilege",
			"source_event_id":  "id",
			"entitlement_id":   "id",
			"entitlement_name": "name",
			"capability":       "identity_admin",
			"is_admin":         "true",
			"description":      "description",
			"privilege":        "privilege",
			"resource_id":      "id",
			"resource_name":    "name",
			"resource_type":    "privilege",
		},
		StaticAttributes: staticAttributes("privileges", "identity_role_assignment", "privilege"),
	})
}

func mappingsFamily() jsonapi.Family {
	return staticFamily(jsonapi.Family{
		Name:    FamilyMappings,
		Path:    "/api/2/mappings",
		URNKind: "onelogin_mappings",
		IDKeys:  []string{"id", "name"},
		Attributes: map[string]string{
			"policy_id":       "user_mappings",
			"policy_name":     "User mappings",
			"policy_type":     "user_mapping",
			"policy_rule_id":  "id",
			"source_event_id": "id",
			"name":            "name",
			"priority":        "position|priority",
			"status":          "enabled|status",
			"conditions":      "conditions",
			"actions":         "actions",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "user_mapping",
		},
		StaticAttributes: staticAttributes("mappings", "identity_policy_rule", "user_mapping"),
	})
}

func userAppsFamily() jsonapi.Family {
	return userScopedFamily(jsonapi.Family{
		Name:       FamilyUserApps,
		Path:       "/api/2/users/{user_id}/apps",
		PathParams: []string{"user_id"},
		URNKind:    "onelogin_user_apps",
		IDKeys:     []string{"id", "app_id", "login_id"},
		Attributes: map[string]string{
			"subject_id":           "user_id",
			"subject_type":         "user",
			"user_id":              "user_id",
			"app_id":               "id|app_id",
			"application_id":       "id|app_id",
			"source_event_id":      "login_id|id|app_id",
			"app_name":             "name",
			"app_label":            "name",
			"status":               "provisioning_status|status",
			"assignment_status":    "provisioning_status|status",
			"provisioning_state":   "provisioning_state",
			"provisioning_enabled": "provisioning_enabled",
			"login_id":             "login_id",
			"resource_id":          "id|app_id",
			"resource_name":        "name",
			"resource_type":        "application_assignment",
		},
		StaticAttributes: staticAttributes("user_apps", "identity_app_assignment", "application_assignment"),
	})
}

func userPrivilegesFamily() jsonapi.Family {
	return userScopedFamily(jsonapi.Family{
		Name:       FamilyUserPrivileges,
		Path:       "/api/2/users/{user_id}/privileges",
		PathParams: []string{"user_id"},
		URNKind:    "onelogin_user_privileges",
		IDKeys:     []string{"id", "name"},
		Attributes: map[string]string{
			"subject_id":       "user_id",
			"subject_type":     "user",
			"user_id":          "user_id",
			"role_id":          "id",
			"role_name":        "name",
			"role_type":        "privilege",
			"source_event_id":  "id",
			"entitlement_id":   "id",
			"entitlement_name": "name",
			"capability":       "identity_admin",
			"is_admin":         "true",
			"resource_id":      "id",
			"resource_name":    "name",
			"resource_type":    "user_privilege",
		},
		StaticAttributes: staticAttributes("user_privileges", "identity_role_assignment", "user_privilege"),
	})
}

func delegatedPrivilegesFamily() jsonapi.Family {
	family := userPrivilegesFamily()
	family.Name = FamilyDelegatedPrivileges
	family.Path = "/api/2/users/{user_id}/delegated_privileges"
	family.URNKind = "onelogin_delegated_privileges"
	family.StaticAttributes = staticAttributes("delegated_privileges", "identity_role_assignment", "delegated_privilege")
	family.Attributes["resource_type"] = "delegated_privilege"
	return family
}

func mfaDevicesFamily() jsonapi.Family {
	return userScopedFamily(jsonapi.Family{
		Name:       FamilyMFADevices,
		Path:       "/api/2/mfa/users/{user_id}/devices",
		PathParams: []string{"user_id"},
		URNKind:    "onelogin_mfa_devices",
		IDKeys:     []string{"device_id", "id", "auth_factor_id"},
		Attributes: map[string]string{
			"subject_id":        "user_id",
			"subject_type":      "user",
			"user_id":           "user_id",
			"credential_id":     "device_id|id|auth_factor_id",
			"credential_name":   "user_display_name|type_display_name|auth_factor_name",
			"credential_type":   "auth_factor_name|type_display_name|type|factor_type",
			"source_event_id":   "device_id|id|auth_factor_id",
			"status":            "status|state",
			"default":           "default",
			"auth_factor_name":  "auth_factor_name",
			"type_display_name": "type_display_name",
			"resource_id":       "device_id|id|auth_factor_id",
			"resource_name":     "user_display_name|type_display_name|auth_factor_name",
			"resource_type":     "mfa_device",
		},
		StaticAttributes: staticAttributes("mfa_devices", "identity_credential", "mfa_device"),
	})
}

func roleUsersFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:       FamilyRoleUsers,
		Path:       "/api/2/roles/{role_id}/users",
		PathParams: []string{"role_id"},
		URNKind:    "onelogin_role_users",
		IDKeys:     []string{"id", "user_id", "email"},
		Attributes: map[string]string{
			"group_id":        "role_id",
			"role_id":         "role_id",
			"member_user_id":  "id|user_id",
			"member_id":       "id|user_id",
			"member_email":    "email",
			"member_name":     "name|username|email",
			"member_type":     "user",
			"member_status":   "status|state",
			"source_event_id": "id|user_id|email",
			"email":           "email",
			"resource_id":     "id|user_id",
			"resource_name":   "name|username|email",
			"resource_type":   "role_user",
		},
		StaticAttributes: staticAttributes("role_users", "identity_group_membership", "role_membership"),
	})
}

func roleAdminsFamily() jsonapi.Family {
	family := roleUsersFamily()
	family.Name = FamilyRoleAdmins
	family.Path = "/api/2/roles/{role_id}/admins"
	family.URNKind = "onelogin_role_admins"
	family.StaticAttributes = staticAttributes("role_admins", "identity_role_assignment", "role_admin")
	family.Attributes["subject_id"] = "id|user_id"
	family.Attributes["subject_type"] = "user"
	family.Attributes["role_type"] = "admin_role"
	family.Attributes["is_admin"] = "true"
	family.Attributes["capability"] = "identity_admin"
	family.Attributes["resource_type"] = "role_admin"
	return family
}

func roleAppsFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:       FamilyRoleApps,
		Path:       "/api/2/roles/{role_id}/apps",
		PathParams: []string{"role_id"},
		URNKind:    "onelogin_role_apps",
		IDKeys:     []string{"id", "app_id", "name"},
		Attributes: map[string]string{
			"subject_id":      "role_id",
			"subject_type":    "group",
			"group_id":        "role_id",
			"role_id":         "role_id",
			"app_id":          "id|app_id",
			"application_id":  "id|app_id",
			"app_name":        "name",
			"app_label":       "name",
			"source_event_id": "id|app_id",
			"resource_id":     "id|app_id",
			"resource_name":   "name",
			"resource_type":   "role_app",
		},
		StaticAttributes: staticAttributes("role_apps", "identity_app_assignment", "role_app_assignment"),
	})
}

func appUsersFamily() jsonapi.Family {
	return v2PagedFamily(jsonapi.Family{
		Name:       FamilyAppUsers,
		Path:       "/api/2/apps/{app_id}/users",
		PathParams: []string{"app_id"},
		URNKind:    "onelogin_app_users",
		IDKeys:     []string{"id", "user_id", "email"},
		Attributes: map[string]string{
			"subject_id":        "id|user_id",
			"subject_type":      "user",
			"subject_email":     "email",
			"user_id":           "id|user_id",
			"email":             "email",
			"app_id":            "app_id",
			"application_id":    "app_id",
			"source_event_id":   "id|user_id|email",
			"status":            "status|state",
			"assignment_status": "status|state",
			"resource_id":       "id|user_id",
			"resource_name":     "name|username|email",
			"resource_type":     "app_user",
		},
		StaticAttributes: staticAttributes("app_users", "identity_app_assignment", "app_user_assignment"),
	})
}

func appRulesFamily() jsonapi.Family {
	return staticFamily(jsonapi.Family{
		Name:       FamilyAppRules,
		Path:       "/api/2/apps/{app_id}/rules",
		PathParams: []string{"app_id"},
		URNKind:    "onelogin_app_rules",
		IDKeys:     []string{"id", "name"},
		Attributes: map[string]string{
			"policy_id":       "app_id",
			"policy_name":     "OneLogin app rules",
			"policy_type":     "app_rule",
			"policy_rule_id":  "id",
			"source_event_id": "id",
			"name":            "name",
			"priority":        "position|priority",
			"status":          "enabled|status",
			"app_id":          "app_id",
			"conditions":      "conditions",
			"actions":         "actions",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "app_rule",
		},
		StaticAttributes: staticAttributes("app_rules", "identity_policy_rule", "app_rule"),
	})
}

func privilegeUsersFamily() jsonapi.Family {
	return v1CursorObjectFamily(jsonapi.Family{
		Name:       FamilyPrivilegeUsers,
		Path:       "/api/1/privileges/{privilege_id}/users",
		PathParams: []string{"privilege_id"},
		URNKind:    "onelogin_privilege_users",
		IDKeys:     []string{"user_id"},
		ListKeys:   []string{"users"},
		Attributes: map[string]string{
			"subject_id":      "user_id",
			"subject_type":    "user",
			"user_id":         "user_id",
			"role_id":         "privilege_id",
			"role_type":       "privilege",
			"source_event_id": "user_id",
			"entitlement_id":  "privilege_id",
			"capability":      "identity_admin",
			"is_admin":        "true",
			"resource_id":     "user_id",
			"resource_type":   "privilege_user",
		},
		StaticAttributes: staticAttributes("privilege_users", "identity_role_assignment", "privilege_user"),
	})
}

func privilegeRolesFamily() jsonapi.Family {
	return v1CursorObjectFamily(jsonapi.Family{
		Name:       FamilyPrivilegeRoles,
		Path:       "/api/1/privileges/{privilege_id}/roles",
		PathParams: []string{"privilege_id"},
		URNKind:    "onelogin_privilege_roles",
		IDKeys:     []string{"role_id"},
		ListKeys:   []string{"roles"},
		Attributes: map[string]string{
			"subject_id":      "role_id",
			"subject_type":    "group",
			"role_id":         "privilege_id",
			"source_event_id": "role_id",
			"entitlement_id":  "privilege_id",
			"capability":      "identity_admin",
			"is_admin":        "true",
			"resource_id":     "role_id",
			"resource_type":   "privilege_role",
		},
		StaticAttributes: staticAttributes("privilege_roles", "identity_role_assignment", "privilege_role"),
	})
}

func v2PagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "cursor"
	family.NextCursorHeaders = []string{"After-Cursor"}
	if len(family.PageSizeParams) == 0 {
		family.PageSizeParams = []string{"limit"}
	}
	family.Config = oneloginConfig(family.Config)
	return family
}

func v1PagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "after_cursor"
	family.NextCursorKeys = []string{"pagination.after_cursor", "pagination.afterCursor", "after_cursor", "afterCursor"}
	if len(family.PageSizeParams) == 0 {
		family.PageSizeParams = []string{"limit"}
	}
	family.Config = oneloginConfig(family.Config)
	return family
}

func v1CursorObjectFamily(family jsonapi.Family) jsonapi.Family {
	family = v1PagedFamily(family)
	family.NextCursorKeys = []string{"afterCursor", "after_cursor", "nextLink"}
	if len(family.PageSizeParams) == 0 {
		family.PageSizeParams = []string{"limit"}
	}
	return family
}

func userScopedFamily(family jsonapi.Family) jsonapi.Family {
	family.DisablePageSize = true
	family.Config = oneloginConfig(family.Config)
	if family.Config.ConfigAttributes == nil {
		family.Config.ConfigAttributes = map[string]string{}
	}
	family.Config.ConfigAttributes["user_id"] = "user_id"
	return family
}

func staticFamily(family jsonapi.Family) jsonapi.Family {
	family.DisablePageSize = true
	family.Config = oneloginConfig(family.Config)
	return family
}

func staticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	return map[string]string{
		"record_class":  recordClass,
		"resource_type": resourceType,
		"schema":        schema,
		"source_system": "onelogin",
	}
}

func oneloginConfig(config jsonapi.FamilyConfig) jsonapi.FamilyConfig {
	if config.ConfigAttributes == nil {
		config.ConfigAttributes = map[string]string{}
	}
	config.ConfigAttributes["tenant_id"] = "tenant_id"
	return config
}

func ConfigListValues(cfg sourcecdk.Config, keys ...string) []string {
	var values []string
	for _, key := range keys {
		raw := sourcecdk.ConfigValue(cfg, key)
		if raw == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			if value := strings.TrimSpace(part); value != "" {
				values = append(values, value)
			}
		}
	}
	return compactUniqueStrings(values)
}

func compactUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
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
