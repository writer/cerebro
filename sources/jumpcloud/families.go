package jumpcloud

import "github.com/writer/cerebro/sources/internal/jsonapi"

func jumpCloudFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		jumpCloudUsersFamily(),
		jumpCloudGroupsFamily(),
		jumpCloudSystemsFamily(),
		jumpCloudApplicationsFamily(),
		jumpCloudSystemGroupsFamily(),
		jumpCloudGroupMembersFamily(),
	}
}

func jumpCloudUsersFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:          familyUsers,
		Path:          "/systemusers",
		URNKind:       "jumpcloud_users",
		IDKeys:        []string{"_id", "id", "email", "username"},
		ListKeys:      []string{"results"},
		TimestampKeys: []string{"updated", "created", "lastLogin"},
		Attributes: map[string]string{
			"user_id":         "_id|id",
			"source_event_id": "_id|id",
			"email":           "email",
			"primary_email":   "email",
			"login":           "username|email",
			"display_name":    "displayname|displayName|username|email",
			"first_name":      "firstname|firstName",
			"last_name":       "lastname|lastName",
			"department":      "department",
			"job_title":       "jobTitle|job_title",
			"employee_id":     "employeeIdentifier",
			"status":          "state|status",
			"activated":       "activated",
			"suspended":       "suspended",
			"mfa_enabled":     "totp_enabled|enable_user_portal_multifactor|mfa.configured",
			"resource_id":     "_id|id",
			"resource_name":   "displayname|username|email",
			"observed_at":     "updated|created",
		},
		StaticAttributes: jumpCloudStaticAttributes("users", "identity_user", "identity_user"),
		Config:           jumpCloudFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "jumpcloud_users", TotalKeys: []string{"totalCount"}}),
	})
}

func jumpCloudGroupsFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:          familyGroups,
		Path:          "/v2/usergroups",
		URNKind:       "jumpcloud_groups",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"updated", "created"},
		Attributes: map[string]string{
			"group_id":        "id",
			"source_event_id": "id",
			"group_name":      "name",
			"group_type":      "type",
			"description":     "attributes.description|description",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "type",
		},
		StaticAttributes: jumpCloudStaticAttributes("groups", "identity_group", "user_group"),
		Config:           jumpCloudFamilyConfig(jsonapi.FamilyConfig{}),
	})
}

func jumpCloudSystemsFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:          familySystems,
		Path:          "/systems",
		URNKind:       "jumpcloud_systems",
		IDKeys:        []string{"_id", "id", "displayName", "hostname"},
		ListKeys:      []string{"results"},
		TimestampKeys: []string{"lastContact", "updated", "created"},
		Attributes: map[string]string{
			"system_id":       "_id|id",
			"source_event_id": "_id|id",
			"resource_id":     "_id|id",
			"resource_name":   "displayName|hostname",
			"resource_type":   "system",
			"hostname":        "hostname",
			"display_name":    "displayName",
			"os":              "os",
			"os_version":      "version",
			"architecture":    "arch",
			"agent_version":   "agentVersion",
			"active":          "active",
			"last_contact_at": "lastContact",
			"remote_ip":       "remoteIP",
			"observed_at":     "lastContact|created",
		},
		StaticAttributes: jumpCloudStaticAttributes("systems", "asset", "system"),
		Config:           jumpCloudFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "jumpcloud_systems", TotalKeys: []string{"totalCount"}}),
	})
}

func jumpCloudApplicationsFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:          familyApplications,
		Path:          "/applications",
		URNKind:       "jumpcloud_applications",
		IDKeys:        []string{"_id", "id", "displayName", "name"},
		ListKeys:      []string{"results"},
		TimestampKeys: []string{"updated", "created"},
		Attributes: map[string]string{
			"app_id":          "_id|id",
			"source_event_id": "_id|id",
			"app_name":        "displayName|displayLabel|name",
			"app_url":         "ssoUrl|learnMore",
			"resource_id":     "_id|id",
			"resource_name":   "displayName|displayLabel|name",
			"resource_type":   "application",
			"observed_at":     "updated|created",
		},
		StaticAttributes: jumpCloudStaticAttributes("applications", "identity_application", "application"),
		Config:           jumpCloudFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "jumpcloud_applications", TotalKeys: []string{"totalCount"}}),
	})
}

func jumpCloudSystemGroupsFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:          familySystemGroups,
		Path:          "/v2/systemgroups",
		URNKind:       "jumpcloud_system_groups",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"updated", "created"},
		Attributes: map[string]string{
			"group_id":        "id",
			"source_event_id": "id",
			"group_name":      "name",
			"group_type":      "type",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "system_group",
		},
		StaticAttributes: jumpCloudStaticAttributes("system_groups", "identity_group", "system_group"),
		Config:           jumpCloudFamilyConfig(jsonapi.FamilyConfig{}),
	})
}

func jumpCloudGroupMembersFamily() jsonapi.Family {
	return jumpCloudPagedFamily(jsonapi.Family{
		Name:       familyGroupMembers,
		Path:       "/v2/usergroups/{group_id}/members",
		PathParams: []string{"group_id"},
		URNKind:    "jumpcloud_group_members",
		IDKeys:     []string{"to.id", "id"},
		Attributes: map[string]string{
			"group_id":        "group_id",
			"member_id":       "to.id|id",
			"member_user_id":  "to.id|id",
			"member_type":     "to.type|type",
			"source_event_id": "to.id|id",
			"resource_id":     "to.id|id",
			"resource_type":   "to.type|type",
		},
		StaticAttributes: jumpCloudStaticAttributes("group_members", "identity_group_membership", "identity_membership"),
		Config: jumpCloudFamilyConfig(jsonapi.FamilyConfig{
			IdentityKeys:     []string{"group_id"},
			ResourceURNKind:  "jumpcloud_users",
			ConfigAttributes: map[string]string{"group_id": "group_id"},
		}),
	})
}

func jumpCloudPagedFamily(family jsonapi.Family) jsonapi.Family {
	if family.CursorParam == "" {
		family.CursorParam = "skip"
	}
	if family.PageFirstCursor == "" {
		family.PageFirstCursor = "0"
	}
	if len(family.PageSizeParams) == 0 {
		family.PageSizeParams = []string{"limit"}
	}
	return family
}

func jumpCloudStaticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	return map[string]string{
		"record_class":  recordClass,
		"resource_type": resourceType,
		"schema":        schema,
		"source_system": "jumpcloud",
	}
}

func jumpCloudFamilyConfig(config jsonapi.FamilyConfig) jsonapi.FamilyConfig {
	if config.ConfigAttributes == nil {
		config.ConfigAttributes = map[string]string{}
	}
	config.ConfigAttributes["tenant_id"] = "tenant_id"
	return config
}
