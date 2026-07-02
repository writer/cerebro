package sailpointapi

import "github.com/writer/cerebro/sources/internal/jsonapi"

const (
	FamilyIdentities                     = "identities"
	FamilyAccounts                       = "accounts"
	FamilyAccountEntitlements            = "account_entitlements"
	FamilySources                        = "sources"
	FamilySourceSchemas                  = "source_schemas"
	FamilySourceHealth                   = "source_health"
	FamilySourceProvisioningPolicies     = "source_provisioning_policies"
	FamilySourceSchedules                = "source_schedules"
	FamilyAccessProfiles                 = "access_profiles"
	FamilyAccessProfileEntitlements      = "access_profile_entitlements"
	FamilyRoles                          = "roles"
	FamilyRoleAssignedIdentities         = "role_assigned_identities"
	FamilyRoleEntitlements               = "role_entitlements"
	FamilyRoleDimensions                 = "role_dimensions"
	FamilyEntitlements                   = "entitlements"
	FamilyIdentityEntitlements           = "identity_entitlements"
	FamilyIdentityRoleAssignments        = "identity_role_assignments"
	FamilyIdentityProfiles               = "identity_profiles"
	FamilyLifecycleStates                = "lifecycle_states"
	FamilyWorkgroups                     = "workgroups"
	FamilyWorkgroupMembers               = "workgroup_members"
	FamilyCampaigns                      = "campaigns"
	FamilyCertifications                 = "certifications"
	FamilyCertificationAccessReviewItems = "certification_access_review_items"
	FamilyAccessRequestStatus            = "access_request_status"
	FamilyAccountActivities              = "account_activities"
	FamilyPersonalAccessTokens           = "personal_access_tokens"
	FamilySegments                       = "segments"
)

type Fanout struct {
	Param     string
	ConfigKey string
}

var familyNames = []string{
	FamilyIdentities,
	FamilyAccounts,
	FamilyAccountEntitlements,
	FamilySources,
	FamilySourceSchemas,
	FamilySourceHealth,
	FamilySourceProvisioningPolicies,
	FamilySourceSchedules,
	FamilyAccessProfiles,
	FamilyAccessProfileEntitlements,
	FamilyRoles,
	FamilyRoleAssignedIdentities,
	FamilyRoleEntitlements,
	FamilyRoleDimensions,
	FamilyEntitlements,
	FamilyIdentityEntitlements,
	FamilyIdentityRoleAssignments,
	FamilyIdentityProfiles,
	FamilyLifecycleStates,
	FamilyWorkgroups,
	FamilyWorkgroupMembers,
	FamilyCampaigns,
	FamilyCertifications,
	FamilyCertificationAccessReviewItems,
	FamilyAccessRequestStatus,
	FamilyAccountActivities,
	FamilyPersonalAccessTokens,
	FamilySegments,
}

var fanouts = map[string]Fanout{
	FamilyAccountEntitlements:            {Param: "account_id", ConfigKey: "account_ids"},
	FamilySourceSchemas:                  {Param: "source_id", ConfigKey: "source_ids"},
	FamilySourceHealth:                   {Param: "source_id", ConfigKey: "source_ids"},
	FamilySourceProvisioningPolicies:     {Param: "source_id", ConfigKey: "source_ids"},
	FamilySourceSchedules:                {Param: "source_id", ConfigKey: "source_ids"},
	FamilyAccessProfileEntitlements:      {Param: "access_profile_id", ConfigKey: "access_profile_ids"},
	FamilyRoleAssignedIdentities:         {Param: "role_id", ConfigKey: "role_ids"},
	FamilyRoleEntitlements:               {Param: "role_id", ConfigKey: "role_ids"},
	FamilyRoleDimensions:                 {Param: "role_id", ConfigKey: "role_ids"},
	FamilyIdentityEntitlements:           {Param: "identity_id", ConfigKey: "identity_ids"},
	FamilyIdentityRoleAssignments:        {Param: "identity_id", ConfigKey: "identity_ids"},
	FamilyLifecycleStates:                {Param: "identity_profile_id", ConfigKey: "identity_profile_ids"},
	FamilyWorkgroupMembers:               {Param: "workgroup_id", ConfigKey: "workgroup_ids"},
	FamilyCertificationAccessReviewItems: {Param: "certification_id", ConfigKey: "certification_ids"},
}

func FamilyNames() []string {
	return append([]string(nil), familyNames...)
}

func FanoutFor(family string) (Fanout, bool) {
	fanout, ok := fanouts[family]
	return fanout, ok
}

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		paged(FamilyIdentities, "/identities", "sailpoint_identitynow_identities", []string{"id"}, []string{"modified", "created"}, map[string]string{
			"user_id":         "id",
			"display_name":    "name|attributes.displayName",
			"email":           "emailAddress|attributes.email",
			"login":           "alias|attributes.uid|attributes.login",
			"status":          "identityStatus|processingState|attributes.cloudStatus",
			"lifecycle_state": "lifecycleState.name|lifecycleState|attributes.cloudLifecycleState",
			"manager_id":      "managerRef.id",
			"manager":         "managerRef.name",
			"department":      "attributes.department",
			"job_title":       "attributes.title|attributes.jobTitle",
			"employee_number": "attributes.identificationNumber|attributes.employeeNumber",
			"created_at":      "created",
			"observed_at":     "modified|created",
		}, "identity_user"),
		withStaticAttributes(paged(FamilyAccounts, "/accounts", "sailpoint_identitynow_accounts", []string{"id", "nativeIdentity", "uuid"}, []string{"modified", "created"}, map[string]string{
			"account_id":          "id",
			"native_identity":     "nativeIdentity",
			"uuid":                "uuid",
			"identity_id":         "identityId|identity.id",
			"identity_name":       "identity.name",
			"source_id":           "sourceId",
			"source_name":         "sourceName",
			"resource_id":         "id",
			"resource_name":       "name|nativeIdentity|attributes.displayName",
			"resource_owner_id":   "identityId|identity.id",
			"resource_owner_name": "identity.name",
			"status":              "identityState|cloudLifecycleState",
			"disabled":            "disabled",
			"locked":              "locked",
			"authoritative":       "authoritative",
			"system_account":      "systemAccount",
			"uncorrelated":        "uncorrelated",
			"has_entitlements":    "hasEntitlements",
			"created_at":          "created",
			"observed_at":         "modified|created",
		}, "identity_account"), map[string]string{"resource_type": "account"}),
		scopedPaged(FamilyAccountEntitlements, "/accounts/{account_id}/entitlements", "sailpoint_identitynow_account_entitlements", []string{"id", "name"}, []string{"modified", "created"}, []string{"account_id"}, map[string]string{
			"account_id":        "account_id",
			"entitlement_id":    "id",
			"entitlement_name":  "name",
			"entitlement_value": "value",
			"attribute":         "attribute",
			"source_id":         "source.id",
			"source_name":       "source.name",
			"privileged":        "privileged",
			"requestable":       "requestable",
			"created_at":        "created",
			"observed_at":       "modified|created",
		}, "account_entitlement"),
		withStaticAttributes(paged(FamilySources, "/sources", "sailpoint_identitynow_sources", []string{"id", "name"}, []string{"modified", "created", "since"}, map[string]string{
			"app_id":          "id",
			"app_name":        "name",
			"resource_id":     "id",
			"resource_name":   "name",
			"source_id":       "id",
			"source_name":     "name",
			"source_type":     "type",
			"connector_name":  "connectorName|connector",
			"connector_id":    "connectorId",
			"connection_type": "connectionType",
			"status":          "status",
			"healthy":         "healthy",
			"authoritative":   "authoritative",
			"owner_id":        "owner.id",
			"owner_name":      "owner.name",
			"created_at":      "created",
			"observed_at":     "modified|since|created",
		}, "identity_source"), map[string]string{"resource_type": "source"}),
		scopedUnpaged(FamilySourceSchemas, "/sources/{source_id}/schemas", "sailpoint_identitynow_source_schemas", []string{"id", "name"}, []string{"modified", "created"}, []string{"source_id"}, map[string]string{
			"source_id":              "source_id",
			"schema_id":              "id",
			"schema_name":            "name",
			"native_object_type":     "nativeObjectType",
			"identity_attribute":     "identityAttribute",
			"display_attribute":      "displayAttribute",
			"hierarchy_attribute":    "hierarchyAttribute",
			"include_permissions":    "includePermissions",
			"attribute_names":        "attributes.name",
			"entitlement_attributes": "attributes.isEntitlement",
			"created_at":             "created",
			"observed_at":            "modified|created",
		}, "source_schema"),
		scopedSingleton(FamilySourceHealth, "/sources/{source_id}/source-health", "sailpoint_identitynow_source_health", []string{"id", "source_id"}, []string{}, []string{"source_id"}, map[string]string{
			"source_id":     "id|source_id",
			"source_name":   "name",
			"source_type":   "type",
			"status":        "status",
			"hostname":      "hostname",
			"org":           "org",
			"authoritative": "isAuthoritative",
			"cluster":       "isCluster",
		}, "source_health"),
		withStaticAttributes(withIDTemplate(scopedUnpaged(FamilySourceProvisioningPolicies, "/sources/{source_id}/provisioning-policies", "sailpoint_identitynow_source_provisioning_policies", []string{"id", "usageType", "name"}, []string{}, []string{"source_id"}, map[string]string{
			"source_id":          "source_id",
			"policy_id":          "_record_id|usageType|name",
			"policy_name":        "name",
			"policy_description": "description",
			"usage_type":         "usageType",
			"field_names":        "fields.name",
		}, "policy"), "${source_id}-${usageType}"), map[string]string{"policy_type": "provisioning_policy"}),
		withStaticAttributes(withIDTemplate(scopedUnpaged(FamilySourceSchedules, "/sources/{source_id}/schedules", "sailpoint_identitynow_source_schedules", []string{"type", "cronExpression"}, []string{}, []string{"source_id"}, map[string]string{
			"source_id":       "source_id",
			"schedule_id":     "_record_id|type",
			"schedule_type":   "type",
			"cron_expression": "cronExpression",
			"policy_id":       "_record_id|type",
			"policy_name":     "type",
		}, "policy"), "${source_id}-${type}"), map[string]string{"policy_type": "source_schedule"}),
		withStaticAttributes(paged(FamilyAccessProfiles, "/access-profiles", "sailpoint_identitynow_access_profiles", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"access_profile_id":   "id",
			"access_profile_name": "name",
			"policy_id":           "id",
			"policy_name":         "name",
			"policy_status":       "enabled",
			"description":         "description",
			"source_id":           "source.id",
			"source_name":         "source.name",
			"owner_id":            "owner.id",
			"owner_name":          "owner.name",
			"enabled":             "enabled",
			"requestable":         "requestable",
			"created_at":          "created",
			"observed_at":         "modified|created",
		}, "access_profile"), map[string]string{"policy_type": "access_profile"}),
		scopedPaged(FamilyAccessProfileEntitlements, "/access-profiles/{access_profile_id}/entitlements", "sailpoint_identitynow_access_profile_entitlements", []string{"id", "name"}, []string{"modified", "created"}, []string{"access_profile_id"}, map[string]string{
			"access_profile_id": "access_profile_id",
			"entitlement_id":    "id",
			"entitlement_name":  "name",
			"entitlement_value": "value",
			"source_id":         "source.id",
			"source_name":       "source.name",
			"privileged":        "privileged",
			"requestable":       "requestable",
			"created_at":        "created",
			"observed_at":       "modified|created",
		}, "access_profile_entitlement"),
		withStaticAttributes(paged50(FamilyRoles, "/roles", "sailpoint_identitynow_roles", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"role_id":       "id",
			"role_name":     "name",
			"policy_id":     "id",
			"policy_name":   "name",
			"policy_status": "enabled",
			"description":   "description",
			"owner_id":      "owner.id",
			"owner_name":    "owner.name",
			"enabled":       "enabled",
			"requestable":   "requestable",
			"privileged":    "privilegeLevel",
			"created_at":    "created",
			"observed_at":   "modified|created",
		}, "role"), map[string]string{"role_type": "role", "policy_type": "role"}),
		withStaticAttributes(scopedPaged(FamilyRoleAssignedIdentities, "/roles/{role_id}/assigned-identities", "sailpoint_identitynow_role_assigned_identities", []string{"id", "email", "name"}, []string{}, []string{"role_id"}, map[string]string{
			"role_id":           "role_id",
			"subject_id":        "id",
			"subject_name":      "name|aliasName",
			"subject_email":     "email",
			"email":             "email",
			"user_id":           "id",
			"assignment_source": "roleAssignmentSource",
		}, "role_assignment"), map[string]string{"subject_type": "user"}),
		scopedPaged50(FamilyRoleEntitlements, "/roles/{role_id}/entitlements", "sailpoint_identitynow_role_entitlements", []string{"id", "name"}, []string{"modified", "created"}, []string{"role_id"}, map[string]string{
			"role_id":           "role_id",
			"entitlement_id":    "id",
			"entitlement_name":  "name",
			"entitlement_value": "value",
			"source_id":         "source.id",
			"source_name":       "source.name",
			"privileged":        "privileged",
			"created_at":        "created",
			"observed_at":       "modified|created",
		}, "role_entitlement"),
		withStaticAttributes(scopedPaged50(FamilyRoleDimensions, "/roles/{role_id}/dimensions", "sailpoint_identitynow_role_dimensions", []string{"id", "name"}, []string{"modified", "created"}, []string{"role_id"}, map[string]string{
			"role_id":        "role_id",
			"dimension_id":   "id",
			"dimension_name": "name",
			"policy_id":      "id",
			"policy_name":    "name",
			"owner_id":       "owner.id",
			"owner_name":     "owner.name",
			"parent_id":      "parentId",
			"created_at":     "created",
			"observed_at":    "modified|created",
		}, "role_dimension"), map[string]string{"policy_type": "role_dimension"}),
		paged(FamilyEntitlements, "/entitlements", "sailpoint_identitynow_entitlements", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"entitlement_id":    "id",
			"entitlement_name":  "name",
			"entitlement_value": "value",
			"attribute":         "attribute",
			"description":       "description",
			"source_id":         "source.id",
			"source_name":       "source.name",
			"owner_id":          "owner.id",
			"owner_name":        "owner.name",
			"privileged":        "privileged",
			"requestable":       "requestable",
			"created_at":        "created",
			"observed_at":       "modified|created",
		}, "entitlement"),
		withStaticAttributes(scopedPaged(FamilyIdentityEntitlements, "/entitlements/identities/{identity_id}/entitlements", "sailpoint_identitynow_identity_entitlements", []string{"objectRef.id", "objectRef.name", "id"}, []string{}, []string{"identity_id"}, map[string]string{
			"identity_id":      "identity_id",
			"subject_id":       "identity_id",
			"entitlement_id":   "objectRef.id|id",
			"entitlement_name": "objectRef.name|name",
			"entitlement_type": "objectRef.type|type",
			"tags":             "tags",
		}, "identity_entitlement"), map[string]string{"subject_type": "user"}),
		withStaticAttributes(scopedUnpaged(FamilyIdentityRoleAssignments, "/identities/{identity_id}/role-assignments", "sailpoint_identitynow_identity_role_assignments", []string{"id", "role.id", "role.name"}, []string{"addedDate", "startDate"}, []string{"identity_id"}, map[string]string{
			"identity_id":         "identity_id",
			"subject_id":          "identity_id",
			"role_assignment_id":  "id",
			"role_id":             "role.id",
			"role_name":           "role.name",
			"assignment_source":   "assignmentSource",
			"assigned_dimensions": "assignedDimensions.name|assignedDimensions.id",
			"start_date":          "startDate",
			"remove_date":         "removeDate",
			"added_date":          "addedDate",
		}, "role_assignment"), map[string]string{"subject_type": "user", "role_type": "role"}),
		withStaticAttributes(paged(FamilyIdentityProfiles, "/identity-profiles", "sailpoint_identitynow_identity_profiles", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"identity_profile_id":   "id",
			"identity_profile_name": "name",
			"policy_id":             "id",
			"policy_name":           "name",
			"description":           "description",
			"owner_id":              "owner.id",
			"owner_name":            "owner.name",
			"source_id":             "authoritativeSource.id",
			"source_name":           "authoritativeSource.name",
			"identity_count":        "identityCount",
			"created_at":            "created",
			"observed_at":           "modified|created",
		}, "identity_profile"), map[string]string{"policy_type": "identity_profile"}),
		withStaticAttributes(scopedPaged(FamilyLifecycleStates, "/identity-profiles/{identity_profile_id}/lifecycle-states", "sailpoint_identitynow_lifecycle_states", []string{"id", "name", "technicalName"}, []string{"modified", "created"}, []string{"identity_profile_id"}, map[string]string{
			"identity_profile_id": "identity_profile_id",
			"lifecycle_state_id":  "id",
			"lifecycle_state":     "technicalName|name",
			"policy_id":           "id",
			"policy_name":         "name|technicalName",
			"enabled":             "enabled",
			"identity_count":      "identityCount",
			"identity_state":      "identityState",
			"access_profile_ids":  "accessProfileIds",
			"created_at":          "created",
			"observed_at":         "modified|created",
		}, "lifecycle_state"), map[string]string{"policy_type": "lifecycle_state"}),
		paged(FamilyWorkgroups, "/workgroups", "sailpoint_identitynow_workgroups", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"group_id":         "id",
			"group_name":       "name",
			"description":      "description",
			"member_count":     "memberCount",
			"connection_count": "connectionCount",
			"owner_id":         "owner.id",
			"owner_name":       "owner.name|owner.displayName",
			"owner_email":      "owner.emailAddress",
			"created_at":       "created",
			"observed_at":      "modified|created",
		}, "governance_group"),
		withStaticAttributes(scopedPaged50(FamilyWorkgroupMembers, "/workgroups/{workgroup_id}/members", "sailpoint_identitynow_workgroup_members", []string{"id", "email", "name"}, []string{}, []string{"workgroup_id"}, map[string]string{
			"group_id":      "workgroup_id",
			"member_id":     "id",
			"member_name":   "name",
			"member_email":  "email",
			"member_type":   "type",
			"user_id":       "id",
			"email":         "email",
			"subject_id":    "id",
			"subject_name":  "name",
			"subject_email": "email",
		}, "governance_group_member"), map[string]string{"subject_type": "user"}),
		withStaticAttributes(paged(FamilyCampaigns, "/campaigns", "sailpoint_identitynow_campaigns", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"campaign_id":   "id",
			"campaign_name": "name",
			"policy_id":     "id",
			"policy_name":   "name",
			"campaign_type": "type",
			"status":        "status",
			"description":   "description",
			"deadline":      "deadline",
			"created_at":    "created",
			"observed_at":   "modified|created",
		}, "certification_campaign"), map[string]string{"policy_type": "certification_campaign"}),
		paged(FamilyCertifications, "/certifications", "sailpoint_identitynow_certifications", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"certification_id":   "id",
			"certification_name": "name",
			"campaign_id":        "campaign.id",
			"campaign_name":      "campaign.name",
			"reviewer_id":        "reviewer.id",
			"reviewer_name":      "reviewer.name",
			"completed":          "completed",
			"signed":             "signed",
			"phase":              "phase",
			"due":                "due",
			"created_at":         "created",
			"observed_at":        "modified|created",
		}, "certification"),
		scopedPaged(FamilyCertificationAccessReviewItems, "/certifications/{certification_id}/access-review-items", "sailpoint_identitynow_certification_access_review_items", []string{"id"}, []string{}, []string{"certification_id"}, map[string]string{
			"certification_id": "certification_id",
			"review_item_id":   "id",
			"completed":        "completed",
			"decision":         "decision",
			"new_access":       "newAccess",
			"identity_id":      "identitySummary.id|identitySummary.identityId",
			"identity_name":    "identitySummary.name",
			"access_id":        "accessSummary.id",
			"access_name":      "accessSummary.name",
			"access_type":      "accessSummary.type",
		}, "certification_review_item"),
		paged(FamilyAccessRequestStatus, "/access-request-status", "sailpoint_identitynow_access_request_status", []string{"id", "accessRequestId", "name"}, []string{"modified", "created"}, map[string]string{
			"access_request_id":  "accessRequestId|id",
			"request_item_id":    "id",
			"request_name":       "name",
			"request_type":       "requestType",
			"state":              "state",
			"type":               "type",
			"requester_id":       "requester.id",
			"requester_name":     "requester.name",
			"requested_for_id":   "requestedFor.id",
			"requested_for_name": "requestedFor.name",
			"description":        "description",
			"created_at":         "created",
			"observed_at":        "modified|created",
		}, "access_request_status"),
		withStaticAttributes(paged(FamilyAccountActivities, "/account-activities", "sailpoint_identitynow_account_activities", []string{"id", "name"}, []string{"modified", "created", "completed"}, map[string]string{
			"activity_id":   "id",
			"activity_name": "name",
			"activity_type": "type",
			"status":        "executionStatus|completionStatus",
			"completed":     "completed",
			"actor_id":      "requesterIdentitySummary.id",
			"actor_name":    "requesterIdentitySummary.name",
			"resource_id":   "targetIdentitySummary.id",
			"resource_name": "targetIdentitySummary.name",
			"event_type":    "type",
			"created_at":    "created",
			"observed_at":   "modified|completed|created",
		}, "account_activity"), map[string]string{"resource_type": "identity"}),
		withStaticAttributes(paged50(FamilyPersonalAccessTokens, "/personal-access-tokens", "sailpoint_identitynow_personal_access_tokens", []string{"id", "name"}, []string{"lastUsed", "created", "expirationDate"}, map[string]string{
			"credential_id":                 "id",
			"credential_name":               "name",
			"subject_id":                    "owner.id",
			"subject_name":                  "owner.name",
			"scope":                         "scope",
			"last_used_at":                  "lastUsed",
			"expires_at":                    "expirationDate",
			"managed":                       "managed",
			"user_aware_never_expires":      "userAwareTokenNeverExpires",
			"access_token_validity_seconds": "accessTokenValiditySeconds",
			"created_at":                    "created",
			"observed_at":                   "lastUsed|created",
		}, "credential"), map[string]string{"credential_type": "personal_access_token", "subject_type": "user"}),
		withStaticAttributes(paged(FamilySegments, "/segments", "sailpoint_identitynow_segments", []string{"id", "name"}, []string{"modified", "created"}, map[string]string{
			"segment_id":   "id",
			"segment_name": "name",
			"policy_id":    "id",
			"policy_name":  "name",
			"description":  "description",
			"active":       "active",
			"owner_id":     "owner.id",
			"owner_name":   "owner.name",
			"created_at":   "created",
			"observed_at":  "modified|created",
		}, "segment"), map[string]string{"policy_type": "segment"}),
	}
}

func paged(name, path, urnKind string, idKeys, timestampKeys []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := base(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.CursorParam = "offset"
	family.PageFirstCursor = "0"
	family.PageSizeParams = []string{"limit"}
	family.Config.OffsetCursor = true
	return family
}

func paged50(name, path, urnKind string, idKeys, timestampKeys []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := paged(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.Config.DefaultPageSize = 50
	return family
}

func scopedPaged(name, path, urnKind string, idKeys, timestampKeys, pathParams []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := paged(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.PathParams = pathParams
	return family
}

func scopedPaged50(name, path, urnKind string, idKeys, timestampKeys, pathParams []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := paged50(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.PathParams = pathParams
	return family
}

func unpaged(name, path, urnKind string, idKeys, timestampKeys []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := base(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.DisablePageSize = true
	return family
}

func scopedUnpaged(name, path, urnKind string, idKeys, timestampKeys, pathParams []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := unpaged(name, path, urnKind, idKeys, timestampKeys, attrs, recordClass)
	family.PathParams = pathParams
	return family
}

func scopedSingleton(name, path, urnKind string, idKeys, timestampKeys, pathParams []string, attrs map[string]string, recordClass string) jsonapi.Family {
	family := scopedUnpaged(name, path, urnKind, idKeys, timestampKeys, pathParams, attrs, recordClass)
	family.Singleton = true
	return family
}

func withIDTemplate(family jsonapi.Family, idTemplate string) jsonapi.Family {
	family.Config.IDTemplate = idTemplate
	return family
}

func withStaticAttributes(family jsonapi.Family, attrs map[string]string) jsonapi.Family {
	for key := range attrs {
		delete(family.Attributes, key)
	}
	jsonapi.MergeStaticAttributes(&family, attrs)
	return family
}

func base(name, path, urnKind string, idKeys, timestampKeys []string, attrs map[string]string, recordClass string) jsonapi.Family {
	return jsonapi.Family{
		Name:          name,
		Path:          path,
		URNKind:       urnKind,
		IDKeys:        idKeys,
		TimestampKeys: timestampKeys,
		Attributes:    attrs,
		StaticAttributes: map[string]string{
			"record_class":  recordClass,
			"schema":        name,
			"source_system": "sailpoint_identitynow",
		},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
		},
	}
}
