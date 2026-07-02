package snykapi

import (
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID               = "snyk"
	DefaultFamily          = FamilyOrgs
	DefaultAPIVersion      = "2026-03-25"
	DefaultHealthPath      = "/orgs?version=" + DefaultAPIVersion
	DefaultBaseURLTemplate = "https://api.snyk.io/rest"
	TokenScheme            = "Token"
	APIVersionConfig       = "api_version"
	OrgIDConfig            = "org_id"
	GroupIDConfig          = "group_id"
	AssetIDConfig          = "asset_id"
	FamilyOrgs             = "orgs"
	FamilyGroups           = "groups"
	FamilyProjects         = "projects"
	FamilyTargets          = "targets"
	FamilyAssets           = "assets"
	FamilyFindings         = "findings"
	FamilyVulnerabilities  = "vulnerabilities"
	FamilyOrgMemberships   = "org_memberships"
	FamilyServiceAccounts  = "service_accounts"
	FamilyAuditLogs        = "audit_logs"
	FamilyCollections      = "collections"
	FamilyCloudEnvs        = "cloud_environments"
	FamilyCloudResources   = "cloud_resources"
	FamilyCloudScans       = "cloud_scans"
	FamilyGroupMemberships = "group_memberships"
	FamilyGroupSvcAccounts = "group_service_accounts"
	FamilyGroupAuditLogs   = "group_audit_logs"
	FamilyAssetProjects    = "asset_project_relationships"
	FamilyAssetTargets     = "asset_target_relationships"
)

const (
	orgIDConfig            = OrgIDConfig
	groupIDConfig          = GroupIDConfig
	assetIDConfig          = AssetIDConfig
	familyOrgs             = FamilyOrgs
	familyGroups           = FamilyGroups
	familyProjects         = FamilyProjects
	familyTargets          = FamilyTargets
	familyAssets           = FamilyAssets
	familyFindings         = FamilyFindings
	familyVulnerabilities  = FamilyVulnerabilities
	familyOrgMemberships   = FamilyOrgMemberships
	familyServiceAccounts  = FamilyServiceAccounts
	familyAuditLogs        = FamilyAuditLogs
	familyCollections      = FamilyCollections
	familyCloudEnvs        = FamilyCloudEnvs
	familyCloudResources   = FamilyCloudResources
	familyCloudScans       = FamilyCloudScans
	familyGroupMemberships = FamilyGroupMemberships
	familyGroupSvcAccounts = FamilyGroupSvcAccounts
	familyGroupAuditLogs   = FamilyGroupAuditLogs
	familyAssetProjects    = FamilyAssetProjects
	familyAssetTargets     = FamilyAssetTargets
)

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		snykOrgsFamily(),
		snykGroupsFamily(),
		snykProjectsFamily(),
		snykTargetsFamily(),
		snykAssetsFamily(),
		snykFindingsFamily(),
		snykVulnerabilitiesFamily(),
		snykOrgMembershipsFamily(),
		snykServiceAccountsFamily(),
		snykAuditLogsFamily(),
		snykCollectionsFamily(),
		snykCloudEnvironmentsFamily(),
		snykCloudResourcesFamily(),
		snykCloudScansFamily(),
		snykGroupMembershipsFamily(),
		snykGroupServiceAccountsFamily(),
		snykGroupAuditLogsFamily(),
		snykAssetProjectsFamily(),
		snykAssetTargetsFamily(),
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
	case FamilyGroupMemberships, FamilyGroupSvcAccounts, FamilyGroupAuditLogs:
		return GroupIDConfig, configListValues(cfg, "group_ids", GroupIDConfig)
	case FamilyAssetProjects, FamilyAssetTargets:
		return AssetIDConfig, configListValues(cfg, "asset_ids", AssetIDConfig)
	default:
		return "", nil
	}
}

func snykOrgsFamily() jsonapi.Family {
	return snykPagedFamily(jsonapi.Family{
		Name:          familyOrgs,
		Path:          "/orgs",
		URNKind:       "snyk_orgs",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
		Attributes: map[string]string{
			"org_id":          "id",
			"name":            "attributes.name|name",
			"slug":            "attributes.slug",
			"group_id":        "relationships.group.data.id",
			"created_at":      "attributes.created_at",
			"updated_at":      "attributes.updated_at",
			"source_event_id": "id",
		},
		StaticAttributes: snykStaticAttributes("orgs", "asset", "snyk_org"),
	})
}

func snykGroupsFamily() jsonapi.Family {
	return snykPagedFamily(jsonapi.Family{
		Name:          familyGroups,
		Path:          "/groups",
		URNKind:       "snyk_groups",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
		Attributes: map[string]string{
			"group_id":        "id",
			"name":            "attributes.name|name",
			"slug":            "attributes.slug",
			"created_at":      "attributes.created_at",
			"updated_at":      "attributes.updated_at",
			"source_event_id": "id",
		},
		StaticAttributes: snykStaticAttributes("groups", "asset", "snyk_group"),
	})
}

func snykProjectsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyProjects,
		Path:          "/orgs/{org_id}/projects",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_projects",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created", "attributes.created_at", "attributes.updated_at"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"project_id":      "id",
			"name":            "attributes.name|name",
			"origin":          "attributes.origin",
			"type":            "attributes.type",
			"target_id":       "relationships.target.data.id|attributes.target_id",
			"created_at":      "attributes.created|attributes.created_at",
			"updated_at":      "attributes.updated_at",
			"source_event_id": "id",
			"resource_id":     "id",
			"resource_name":   "attributes.name|name",
		},
		StaticAttributes: snykStaticAttributes("projects", "asset", "snyk_project"),
	})
}

func snykTargetsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyTargets,
		Path:          "/orgs/{org_id}/targets",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_targets",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"target_id":       "id",
			"display_name":    "attributes.display_name|attributes.name|name",
			"url":             "attributes.url",
			"source_type":     "attributes.source_type",
			"is_private":      "attributes.is_private",
			"created_at":      "attributes.created_at",
			"updated_at":      "attributes.updated_at",
			"source_event_id": "id",
			"resource_id":     "id",
			"resource_name":   "attributes.display_name|attributes.name|name",
		},
		StaticAttributes: snykStaticAttributes("targets", "asset", "snyk_target"),
	})
}

func snykAssetsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyAssets,
		Path:          "/orgs/{org_id}/inventory/assets",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_assets",
		IDKeys:        []string{"id", "urn", "resource_urn", "name"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.updated_at", "attributes.created_at", "observed_at", "updated_at", "last_seen_at", "created_at"},
		Attributes: map[string]string{
			"org_id":                   orgIDConfig,
			"asset_id":                 "id",
			"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
			"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
			"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
			"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
			"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
			"observed_at":              "attributes.updated_at|observed_at|updated_at|last_seen_at",
			"resource_id":              "id",
			"resource_name":            "attributes.name|attributes.display_name|name|display_name|hostname|metadata.resource_name",
			"resource_type":            "attributes.type|resource_type|type|kind",
			"resource_urn":             "resource_urn|urn|metadata.resource_urn",
			"source_event_id":          "event_id|id|metadata.event_id",
			"tenant_id":                "tenant_id|metadata.tenant_id",
		},
		StaticAttributes: snykStaticAttributes("assets", "asset", ""),
	})
}

func snykFindingsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyFindings,
		Path:          "/orgs/{org_id}/issues",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_findings",
		IDKeys:        []string{"id", "finding_id", "resource_urn"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.updated_at", "attributes.created_at", "attributes.discovered_at", "observed_at", "updated_at", "last_seen_at", "created_at"},
		Attributes:    snykIssueAttributes(),
		StaticAttributes: map[string]string{
			"record_class":  "finding",
			"schema":        "findings",
			"source_system": "snyk",
		},
	})
}

func snykVulnerabilitiesFamily() jsonapi.Family {
	family := snykFindingsFamily()
	family.Name = familyVulnerabilities
	family.URNKind = "snyk_vulnerabilities"
	family.StaticAttributes = map[string]string{
		"record_class":  "finding",
		"schema":        "vulnerabilities",
		"source_system": "snyk",
	}
	family.Config.StaticQuery = map[string]string{"type": "package_vulnerability"}
	return family
}

func snykOrgMembershipsFamily() jsonapi.Family {
	family := snykOrgPagedFamily(jsonapi.Family{
		Name:          familyOrgMemberships,
		Path:          "/orgs/{org_id}/memberships",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_org_memberships",
		IDKeys:        []string{"id", "relationships.user.data.id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"membership_id":   "id",
			"source_event_id": "id|relationships.user.data.id",
			"group_id":        orgIDConfig,
			"member_user_id":  "relationships.user.data.id",
			"member_type":     "relationships.user.data.type",
			"role_id":         "relationships.role.data.id",
			"role":            "relationships.role.data.id",
			"created_at":      "attributes.created_at",
			"resource_id":     "relationships.user.data.id",
			"resource_type":   "relationships.user.data.type",
		},
		StaticAttributes: snykStaticAttributes("org_memberships", "identity_group_membership", "snyk_org_membership"),
	})
	family.Config.IdentityKeys = []string{orgIDConfig, "relationships.user.data.id"}
	family.Config.ConfigAttributes["group_id"] = OrgIDConfig
	family.Config.ResourceURNKind = "runtime_users"
	return family
}

func snykServiceAccountsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyServiceAccounts,
		Path:          "/orgs/{org_id}/service_accounts",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_service_accounts",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.access_token_expires_at"},
		Attributes: map[string]string{
			"org_id":                  orgIDConfig,
			"service_account_id":      "id",
			"source_event_id":         "id",
			"resource_id":             "id",
			"resource_name":           "attributes.name",
			"name":                    "attributes.name",
			"auth_type":               "attributes.auth_type",
			"level":                   "attributes.level",
			"role_id":                 "attributes.role_id",
			"client_id":               "attributes.client_id",
			"created_at":              "attributes.created_at",
			"access_token_expires_at": "attributes.access_token_expires_at",
		},
		StaticAttributes: snykStaticAttributes("service_accounts", "asset", "snyk_service_account"),
	})
}

func snykAuditLogsFamily() jsonapi.Family {
	family := snykOrgPagedFamily(jsonapi.Family{
		Name:          familyAuditLogs,
		Path:          "/orgs/{org_id}/audit_logs/search",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_audit_logs",
		IDKeys:        []string{"created", "event", "content.user_id", "content.email"},
		ListKeys:      []string{"data.items"},
		TimestampKeys: []string{"created"},
		Attributes: map[string]string{
			"org_id":          "org_id|" + orgIDConfig,
			"group_id":        "group_id",
			"project_id":      "project_id",
			"source_event_id": "_record_id",
			"event_type":      "event",
			"actor_id":        "content.user_id|content.user.id|content.actor.id",
			"actor_email":     "content.email|content.user.email|content.actor.email",
			"resource_id":     "project_id|org_id|group_id",
			"resource_type":   "content.type|event",
			"observed_at":     "created",
		},
		StaticAttributes: snykStaticAttributes("audit_logs", "audit_event", "snyk_audit_log"),
	})
	family.CursorParam = "cursor"
	family.PageSizeParams = []string{"size"}
	family.Config.IDTemplate = "${created}-${event}-" +
		"${content.user_id|content.user.id|content.actor.id|content.email|content.user.email|content.actor.email|project_id|group_id|org_id}-" +
		"${project_id|group_id|org_id|content.target.id|content.object.id|content.user_id|content.user.id|content.actor.id|content.email|content.user.email|content.actor.email}"
	family.Config.IdentityKeys = []string{
		"event",
		"content.user_id",
		"content.user.id",
		"content.actor.id",
		"content.email",
		"content.user.email",
		"content.actor.email",
		"project_id",
		"org_id",
		"group_id",
		"content.target.id",
		"content.object.id",
	}
	return family
}

func snykCollectionsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyCollections,
		Path:          "/orgs/{org_id}/collections",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_collections",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
		Attributes: map[string]string{
			"org_id":                "relationships.org.data.id|" + orgIDConfig,
			"collection_id":         "id",
			"source_event_id":       "id",
			"resource_id":           "id",
			"resource_name":         "attributes.name",
			"name":                  "attributes.name",
			"is_generated":          "attributes.is_generated",
			"created_by_user_id":    "relationships.created_by_user.data.id",
			"projects_count":        "meta.projects_count",
			"issues_critical_count": "meta.issues_critical_count",
			"issues_high_count":     "meta.issues_high_count",
			"issues_medium_count":   "meta.issues_medium_count",
			"issues_low_count":      "meta.issues_low_count",
		},
		StaticAttributes: snykStaticAttributes("collections", "asset", "snyk_collection"),
	})
}

func snykCloudEnvironmentsFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyCloudEnvs,
		Path:          "/orgs/{org_id}/cloud/environments",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_cloud_environments",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.updated_at", "attributes.created_at"},
		Attributes: map[string]string{
			"org_id":          "relationships.organization.data.id|" + orgIDConfig,
			"environment_id":  "id",
			"source_event_id": "id",
			"resource_id":     "id|attributes.native_id",
			"resource_name":   "attributes.name",
			"resource_type":   "attributes.kind|type",
			"kind":            "attributes.kind",
			"native_id":       "attributes.native_id|attributes.properties.account_id",
			"project_id":      "relationships.project.data.id",
			"created_at":      "attributes.created_at",
			"updated_at":      "attributes.updated_at",
		},
		StaticAttributes: snykStaticAttributes("cloud_environments", "cloud_resource", "snyk_cloud_environment"),
	})
}

func snykCloudResourcesFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyCloudResources,
		Path:          "/orgs/{org_id}/cloud/resources",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_cloud_resources",
		IDKeys:        []string{"attributes.native_id", "attributes.resource_id", "id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.updated_at", "attributes.created_at"},
		Attributes: map[string]string{
			"org_id":          "relationships.organization.data.id|" + orgIDConfig,
			"source_event_id": "id|attributes.resource_id|attributes.native_id",
			"resource_id":     "attributes.native_id|attributes.resource_id|id",
			"resource_name":   "attributes.name|attributes.resource_id|attributes.native_id",
			"resource_type":   "attributes.resource_type|type",
			"platform":        "attributes.platform",
			"kind":            "attributes.kind",
			"location":        "attributes.location",
			"namespace":       "attributes.namespace",
			"environment_id":  "relationships.environment.data.id",
			"scan_id":         "relationships.scan.data.id",
			"created_at":      "attributes.created_at",
			"updated_at":      "attributes.updated_at",
		},
		StaticAttributes: snykStaticAttributes("cloud_resources", "cloud_resource", "cloud_resource"),
	})
}

func snykCloudScansFamily() jsonapi.Family {
	return snykOrgPagedFamily(jsonapi.Family{
		Name:          familyCloudScans,
		Path:          "/orgs/{org_id}/cloud/scans",
		PathParams:    []string{orgIDConfig},
		URNKind:       "snyk_cloud_scans",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.finished_at", "attributes.created_at"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"scan_id":         "id",
			"source_event_id": "id",
			"resource_id":     "id",
			"resource_name":   "attributes.name|id",
			"status":          "attributes.status",
			"kind":            "attributes.kind",
			"error":           "attributes.error",
			"environment_id":  "relationships.environment.data.id|attributes.environment_id",
			"created_at":      "attributes.created_at",
			"finished_at":     "attributes.finished_at",
		},
		StaticAttributes: snykStaticAttributes("cloud_scans", "asset", "snyk_cloud_scan"),
	})
}

func snykGroupMembershipsFamily() jsonapi.Family {
	family := snykPagedFamily(jsonapi.Family{
		Name:          familyGroupMemberships,
		Path:          "/groups/{group_id}/memberships",
		PathParams:    []string{groupIDConfig},
		URNKind:       "snyk_group_memberships",
		IDKeys:        []string{"id", "relationships.user.data.id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at"},
		Attributes: map[string]string{
			"group_id":        groupIDConfig,
			"membership_id":   "id",
			"source_event_id": "id|relationships.user.data.id",
			"member_user_id":  "relationships.user.data.id",
			"member_type":     "relationships.user.data.type",
			"role_id":         "relationships.role.data.id",
			"role":            "relationships.role.data.id",
			"created_at":      "attributes.created_at",
			"resource_id":     "relationships.user.data.id",
			"resource_type":   "relationships.user.data.type",
		},
		StaticAttributes: snykStaticAttributes("group_memberships", "identity_group_membership", "snyk_group_membership"),
	})
	family.Config.IdentityKeys = []string{groupIDConfig, "relationships.user.data.id"}
	family.Config.ResourceURNKind = "runtime_users"
	return family
}

func snykGroupServiceAccountsFamily() jsonapi.Family {
	return snykPagedFamily(jsonapi.Family{
		Name:          familyGroupSvcAccounts,
		Path:          "/groups/{group_id}/service_accounts",
		PathParams:    []string{groupIDConfig},
		URNKind:       "snyk_group_service_accounts",
		IDKeys:        []string{"id"},
		ListKeys:      []string{"data"},
		TimestampKeys: []string{"attributes.created_at", "attributes.access_token_expires_at"},
		Attributes: map[string]string{
			"group_id":                groupIDConfig,
			"service_account_id":      "id",
			"source_event_id":         "id",
			"resource_id":             "id",
			"resource_name":           "attributes.name",
			"name":                    "attributes.name",
			"auth_type":               "attributes.auth_type",
			"level":                   "attributes.level",
			"role_id":                 "attributes.role_id",
			"client_id":               "attributes.client_id",
			"created_at":              "attributes.created_at",
			"access_token_expires_at": "attributes.access_token_expires_at",
		},
		StaticAttributes: snykStaticAttributes("group_service_accounts", "asset", "snyk_service_account"),
	})
}

func snykGroupAuditLogsFamily() jsonapi.Family {
	family := snykPagedFamily(jsonapi.Family{
		Name:          familyGroupAuditLogs,
		Path:          "/groups/{group_id}/audit_logs/search",
		PathParams:    []string{groupIDConfig},
		URNKind:       "snyk_group_audit_logs",
		IDKeys:        []string{"created", "event", "content.user_id", "content.email"},
		ListKeys:      []string{"data.items"},
		TimestampKeys: []string{"created"},
		Attributes: map[string]string{
			"group_id":        "group_id|" + groupIDConfig,
			"org_id":          "org_id",
			"project_id":      "project_id",
			"source_event_id": "_record_id",
			"event_type":      "event",
			"actor_id":        "content.user_id|content.user.id|content.actor.id",
			"actor_email":     "content.email|content.user.email|content.actor.email",
			"resource_id":     "project_id|org_id|group_id",
			"resource_type":   "content.type|event",
			"observed_at":     "created",
		},
		StaticAttributes: snykStaticAttributes("group_audit_logs", "audit_event", "snyk_audit_log"),
	})
	family.CursorParam = "cursor"
	family.PageSizeParams = []string{"size"}
	family.Config.IDTemplate = "${created}-${event}-" +
		"${content.user_id|content.user.id|content.actor.id|content.email|content.user.email|content.actor.email|project_id|group_id|org_id}-" +
		"${project_id|group_id|org_id|content.target.id|content.object.id|content.user_id|content.user.id|content.actor.id|content.email|content.user.email|content.actor.email}"
	family.Config.IdentityKeys = []string{
		"event",
		"content.user_id",
		"content.user.id",
		"content.actor.id",
		"content.email",
		"content.user.email",
		"content.actor.email",
		"project_id",
		"org_id",
		"group_id",
		"content.target.id",
		"content.object.id",
	}
	return family
}

func snykAssetProjectsFamily() jsonapi.Family {
	family := snykOrgPagedFamily(jsonapi.Family{
		Name:       familyAssetProjects,
		Path:       "/orgs/{org_id}/inventory/assets/{asset_id}/relationships/projects",
		PathParams: []string{orgIDConfig, assetIDConfig},
		URNKind:    "snyk_asset_project_relationships",
		IDKeys:     []string{"id"},
		ListKeys:   []string{"data"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"asset_id":        assetIDConfig,
			"project_id":      "id",
			"source_event_id": "id",
			"resource_id":     "id",
			"resource_name":   "attributes.name|name",
			"resource_type":   "type",
		},
		StaticAttributes: snykStaticAttributes("asset_project_relationships", "asset_relationship", "snyk_project"),
	})
	family.Config.IdentityKeys = []string{assetIDConfig}
	family.Config.ResourceURNKind = "snyk_projects"
	return family
}

func snykAssetTargetsFamily() jsonapi.Family {
	family := snykOrgPagedFamily(jsonapi.Family{
		Name:       familyAssetTargets,
		Path:       "/orgs/{org_id}/inventory/assets/{asset_id}/relationships/targets",
		PathParams: []string{orgIDConfig, assetIDConfig},
		URNKind:    "snyk_asset_target_relationships",
		IDKeys:     []string{"id"},
		ListKeys:   []string{"data"},
		Attributes: map[string]string{
			"org_id":          orgIDConfig,
			"asset_id":        assetIDConfig,
			"target_id":       "id",
			"source_event_id": "id",
			"resource_id":     "id",
			"resource_name":   "attributes.display_name|attributes.name|name",
			"resource_type":   "type",
		},
		StaticAttributes: snykStaticAttributes("asset_target_relationships", "asset_relationship", "snyk_target"),
	})
	family.Config.IdentityKeys = []string{assetIDConfig}
	family.Config.ResourceURNKind = "snyk_targets"
	return family
}

func snykIssueAttributes() map[string]string {
	return map[string]string{
		"org_id":                   orgIDConfig,
		"description":              "attributes.description|attributes.summary|description|summary",
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"finding_id":               "id",
		"issue_type":               "attributes.type|type",
		"observed_at":              "attributes.updated_at|attributes.discovered_at|observed_at|updated_at|last_seen_at",
		"resource_id":              "relationships.scan_item.data.id|attributes.scan_item.id|resource_id|metadata.resource_id",
		"resource_name":            "attributes.scan_item.name|attributes.package.name|name|display_name|hostname|metadata.resource_name",
		"resource_type":            "relationships.scan_item.data.type|attributes.scan_item.type|resource_type|type|metadata.resource_type",
		"resource_urn":             "resource_urn|urn|metadata.resource_urn",
		"severity":                 "attributes.effective_severity_level|attributes.severity|severity|risk|priority",
		"source_event_id":          "event_id|id|metadata.event_id",
		"status":                   "attributes.status|status|state",
		"tenant_id":                "tenant_id|metadata.tenant_id",
		"title":                    "attributes.title|attributes.key|title|name|summary",
	}
}

func snykStaticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	attrs := map[string]string{
		"record_class":  recordClass,
		"schema":        schema,
		"source_system": "snyk",
	}
	if resourceType != "" {
		attrs["resource_type"] = resourceType
	}
	return attrs
}

func snykPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "starting_after"
	family.NextCursorKeys = []string{"links.next"}
	family.PageSizeParams = []string{"limit"}
	family.Config = snykVersionedConfig()
	return family
}

func snykOrgPagedFamily(family jsonapi.Family) jsonapi.Family {
	family = snykPagedFamily(family)
	family.Config.ConfigAttributes = map[string]string{"org_id": OrgIDConfig}
	return family
}

func snykVersionedConfig() jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{ConfigQuery: map[string]string{"version": APIVersionConfig}}
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		for _, value := range strings.Split(sourcecdk.ConfigValue(cfg, key), ",") {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				values = append(values, trimmed)
			}
		}
	}
	return values
}
