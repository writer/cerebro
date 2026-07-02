package fivetranapi

import (
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID               = "fivetran"
	DefaultFamily          = FamilyUsers
	DefaultBaseURLTemplate = "https://api.fivetran.com"
	DefaultHealthPath      = "/v1/account/info"

	FamilyAccountInfo                      = "account_info"
	FamilyUsers                            = "users"
	FamilyUserConnections                  = "user_connections"
	FamilyUserGroups                       = "user_groups"
	FamilyRoles                            = "roles"
	FamilyTeams                            = "teams"
	FamilyTeamUsers                        = "team_users"
	FamilyTeamConnections                  = "team_connections"
	FamilyTeamGroups                       = "team_groups"
	FamilyGroups                           = "groups"
	FamilyGroupUsers                       = "group_users"
	FamilyGroupConnections                 = "group_connections"
	FamilyGroupPublicKeys                  = "group_public_keys"
	FamilyGroupServiceAccounts             = "group_service_accounts"
	FamilyDestinations                     = "destinations"
	FamilyConnections                      = "connections"
	FamilyConnectionCertificates           = "connection_certificates"
	FamilyConnectionFingerprints           = "connection_fingerprints"
	FamilyConnectionSchemas                = "connection_schemas"
	FamilyConnectionState                  = "connection_state"
	FamilyConnectionTableColumns           = "connection_table_columns"
	FamilyConnectorSDKPackages             = "connector_sdk_packages"
	FamilyDestinationCertificates          = "destination_certificates"
	FamilyDestinationFingerprints          = "destination_fingerprints"
	FamilyAccountLogService                = "account_log_service"
	FamilyLogServices                      = "log_services"
	FamilyWebhooks                         = "webhooks"
	FamilyExternalSecretManagers           = "external_secret_managers"
	FamilyExternalSecretManagerEntities    = "external_secret_manager_entities"
	FamilyExternalSecretManagerAssignments = "external_secret_manager_assignments"
	FamilyPrivateLinks                     = "private_links"
	FamilyProxyAgents                      = "proxy_agents"
	FamilyProxyAgentConnections            = "proxy_agent_connections"
	FamilyHybridAgents                     = "hybrid_deployment_agents"
	FamilyPublicConnectorTypes             = "public_connector_types"
	FamilyConnectorMetadata                = "connector_metadata"
	FamilyConnectorMetadataDetails         = "connector_metadata_details"
	FamilySystemKeys                       = "system_keys"
	FamilyTransformations                  = "transformations"
	FamilyTransformationProjects           = "transformation_projects"
	FamilyTransformationPackageMetadata    = "transformation_package_metadata"
	FamilyTransformationPackageDetails     = "transformation_package_details"
)

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		accountInfoFamily(),
		usersFamily(),
		userConnectionsFamily(),
		userGroupsFamily(),
		rolesFamily(),
		teamsFamily(),
		teamUsersFamily(),
		teamConnectionsFamily(),
		teamGroupsFamily(),
		groupsFamily(),
		groupUsersFamily(),
		groupConnectionsFamily(),
		groupPublicKeysFamily(),
		groupServiceAccountsFamily(),
		destinationsFamily(),
		connectionsFamily(),
		connectionCertificatesFamily(),
		connectionFingerprintsFamily(),
		connectionSchemasFamily(),
		connectionStateFamily(),
		connectionTableColumnsFamily(),
		connectorSDKPackagesFamily(),
		destinationCertificatesFamily(),
		destinationFingerprintsFamily(),
		accountLogServiceFamily(),
		logServicesFamily(),
		webhooksFamily(),
		externalSecretManagersFamily(),
		externalSecretManagerEntitiesFamily(),
		externalSecretManagerAssignmentsFamily(),
		privateLinksFamily(),
		proxyAgentsFamily(),
		proxyAgentConnectionsFamily(),
		hybridAgentsFamily(),
		publicConnectorTypesFamily(),
		connectorMetadataFamily(),
		connectorMetadataDetailsFamily(),
		systemKeysFamily(),
		transformationsFamily(),
		transformationProjectsFamily(),
		transformationPackageMetadataFamily(),
		transformationPackageDetailsFamily(),
	}
}

func accountInfoFamily() jsonapi.Family {
	family := fivetranSingletonAssetFamily(FamilyAccountInfo, "/v1/account/info", "account_info", "account")
	family.IDKeys = []string{"account_id", "account_name"}
	family.Attributes["account_id"] = "account_id"
	family.Attributes["resource_id"] = "account_id"
	family.Attributes["resource_name"] = "account_name|account_id"
	family.Attributes["source_event_id"] = "account_id"
	family.Attributes["system_key_id"] = "system_key_id"
	family.Attributes["user_id"] = "user_id"
	return family
}

func usersFamily() jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          FamilyUsers,
		Path:          "/v1/users",
		URNKind:       "fivetran_users",
		IDKeys:        []string{"id", "email"},
		TimestampKeys: []string{"created_at", "updated_at", "last_login_at", "invited_at"},
		Attributes: map[string]string{
			"user_id":         "id",
			"source_event_id": "id",
			"email":           "email",
			"primary_email":   "email",
			"login":           "email",
			"display_name":    "name|given_name|email",
			"role":            "role",
			"status":          "verified|active|status",
			"created_at":      "created_at",
			"last_login_at":   "last_login_at",
			"resource_id":     "id",
			"resource_name":   "name|email",
		},
		StaticAttributes: fivetranStaticAttributes("users", "identity_user", "identity_user"),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_users"}),
	})
}

func userConnectionsFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyUserConnections, "/v1/users/{user_id}/connections", "user_id", "connection")
}

func userGroupsFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyUserGroups, "/v1/users/{user_id}/groups", "user_id", "group")
}

func rolesFamily() jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          FamilyRoles,
		Path:          "/v1/roles",
		URNKind:       "fivetran_roles",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"created_at", "updated_at"},
		Attributes: map[string]string{
			"role_id":         "id",
			"source_event_id": "id",
			"role_name":       "name",
			"description":     "description",
			"scope":           "scope",
			"resource_id":     "id",
			"resource_name":   "name",
		},
		StaticAttributes: fivetranStaticAttributes("roles", "identity_role", "role"),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_roles"}),
	})
}

func teamsFamily() jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          FamilyTeams,
		Path:          "/v1/teams",
		URNKind:       "fivetran_teams",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"created_at", "updated_at"},
		Attributes: map[string]string{
			"team_id":         "id",
			"source_event_id": "id",
			"group_id":        "id",
			"group_name":      "name",
			"description":     "description",
			"resource_id":     "id",
			"resource_name":   "name",
		},
		StaticAttributes: fivetranStaticAttributes("teams", "identity_group", "team"),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_teams"}),
	})
}

func teamUsersFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyTeamUsers, "/v1/teams/{team_id}/users", "team_id", "user")
}

func teamConnectionsFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyTeamConnections, "/v1/teams/{team_id}/connections", "team_id", "connection")
}

func teamGroupsFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyTeamGroups, "/v1/teams/{team_id}/groups", "team_id", "group")
}

func groupsFamily() jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          FamilyGroups,
		Path:          "/v1/groups",
		URNKind:       "fivetran_groups",
		IDKeys:        []string{"id", "name"},
		TimestampKeys: []string{"created_at", "updated_at"},
		Attributes: map[string]string{
			"group_id":        "id",
			"source_event_id": "id",
			"group_name":      "name",
			"description":     "description",
			"resource_id":     "id",
			"resource_name":   "name",
		},
		StaticAttributes: fivetranStaticAttributes("groups", "identity_group", "destination_group"),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_groups"}),
	})
}

func groupUsersFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyGroupUsers, "/v1/groups/{group_id}/users", "group_id", "user")
}

func groupConnectionsFamily() jsonapi.Family {
	return fivetranScopedMembershipFamily(FamilyGroupConnections, "/v1/groups/{group_id}/connections", "group_id", "connection")
}

func groupPublicKeysFamily() jsonapi.Family {
	family := fivetranScopedCredentialFamily(FamilyGroupPublicKeys, "/v1/groups/{group_id}/public-key", "group_id", "group", "public_key")
	family.Singleton = true
	family.DisablePageSize = true
	family.IDKeys = []string{"public_key", "group_id"}
	family.Attributes["group_id"] = "group_id"
	family.Attributes["credential_id"] = "public_key|group_id"
	family.Attributes["public_key"] = "public_key"
	family.Attributes["resource_id"] = "public_key|group_id"
	family.Attributes["resource_name"] = "group_id|public_key"
	family.Attributes["source_event_id"] = "public_key|group_id"
	return family
}

func groupServiceAccountsFamily() jsonapi.Family {
	family := fivetranScopedCredentialFamily(FamilyGroupServiceAccounts, "/v1/groups/{group_id}/service-account", "group_id", "group", "service_account")
	family.Singleton = true
	family.DisablePageSize = true
	family.IDKeys = []string{"group_id"}
	family.Attributes["group_id"] = "group_id"
	family.Attributes["credential_id"] = "group_id"
	family.Attributes["resource_id"] = "group_id"
	family.Attributes["resource_name"] = "group_id"
	delete(family.Attributes, "service_account")
	family.Attributes["source_event_id"] = "group_id"
	family.Config.RedactPayloadKeys = []string{"service_account"}
	return family
}

func destinationsFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilyDestinations, "/v1/destinations", "destination", "destination")
	family.Config.StaticHeaders = fivetranV2Headers()
	return family
}

func connectionsFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilyConnections, "/v1/connections", "connection", "connection")
	family.Config.StaticHeaders = fivetranV2Headers()
	return family
}

func connectionCertificatesFamily() jsonapi.Family {
	return fivetranScopedCredentialFamily(FamilyConnectionCertificates, "/v1/connections/{connection_id}/certificates", "connection_id", "connection", "certificate")
}

func connectionFingerprintsFamily() jsonapi.Family {
	return fivetranScopedCredentialFamily(FamilyConnectionFingerprints, "/v1/connections/{connection_id}/fingerprints", "connection_id", "connection", "fingerprint")
}

func connectionSchemasFamily() jsonapi.Family {
	return fivetranScopedAssetFamily(FamilyConnectionSchemas, "/v1/connections/{connection_id}/schemas", "connection_id", "connection_schema", "connection_schema", true)
}

func connectionStateFamily() jsonapi.Family {
	return fivetranScopedAssetFamily(FamilyConnectionState, "/v1/connections/{connection_id}/state", "connection_id", "connection_state", "connection_state", true)
}

func connectionTableColumnsFamily() jsonapi.Family {
	family := fivetranPagedFamily(jsonapi.Family{
		Name:            FamilyConnectionTableColumns,
		Path:            "/v1/connections/{connection_id}/schemas/{schema_name}/tables/{table_name}/columns",
		PathParams:      []string{"connection_id", "schema_name", "table_name"},
		URNKind:         "fivetran_connection_table_columns",
		IDKeys:          []string{"id", "name"},
		DisablePageSize: true,
		MapRecords:      map[string]string{"data.columns": "config"},
		Attributes: map[string]string{
			"column_name":     "id|name",
			"connection_id":   "connection_id",
			"enabled":         "config.enabled|enabled",
			"hashed":          "config.hashed|hashed",
			"resource_id":     "id|name",
			"resource_name":   "id|name",
			"schema_name":     "schema_name",
			"source_event_id": "id|name",
			"status":          "config.enabled|enabled",
			"table_name":      "table_name",
		},
		StaticAttributes: fivetranStaticAttributes("connection_table_columns", "asset", "connection_table_column"),
		Config: fivetranFamilyConfig(jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{
				"connection_id": "connection_id",
				"schema_name":   "schema_name",
				"table_name":    "table_name",
			},
			IdentityKeys:    []string{"connection_id", "schema_name", "table_name"},
			ResourceURNKind: "fivetran_connection_table_columns",
		}),
	})
	return family
}

func connectorSDKPackagesFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyConnectorSDKPackages, "/v1/connector-sdk/packages", "connector_sdk_package", "connector_sdk_package")
}

func destinationCertificatesFamily() jsonapi.Family {
	return fivetranScopedCredentialFamily(FamilyDestinationCertificates, "/v1/destinations/{destination_id}/certificates", "destination_id", "destination", "certificate")
}

func destinationFingerprintsFamily() jsonapi.Family {
	return fivetranScopedCredentialFamily(FamilyDestinationFingerprints, "/v1/destinations/{destination_id}/fingerprints", "destination_id", "destination", "fingerprint")
}

func accountLogServiceFamily() jsonapi.Family {
	family := fivetranSingletonAssetFamily(FamilyAccountLogService, "/v1/external-logging/account", "account_log_service", "log_service")
	family.IDKeys = []string{"id", "service"}
	family.Attributes["enabled"] = "enabled"
	family.Attributes["resource_id"] = "id|service"
	family.Attributes["resource_name"] = "service|id"
	family.Attributes["service"] = "service"
	family.Attributes["source_event_id"] = "id|service"
	family.Attributes["status"] = "enabled"
	return family
}

func logServicesFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyLogServices, "/v1/external-logging", "log_service", "log_service")
}

func webhooksFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilyWebhooks, "/v1/webhooks", "webhook", "webhook")
	family.Config.RedactPayloadKeys = []string{"signing_key"}
	return family
}

func externalSecretManagersFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyExternalSecretManagers, "/v1/external-secrets-managers", "external_secret_manager", "external_secret_manager")
}

func externalSecretManagerEntitiesFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyExternalSecretManagerEntities, "/v1/external-secrets-managers-entities", "external_secret_manager_entity", "external_secret_manager_entity")
}

func externalSecretManagerAssignmentsFamily() jsonapi.Family {
	return fivetranScopedAssetFamily(FamilyExternalSecretManagerAssignments, "/v1/external-secrets-managers/{external_secret_manager_id}/entities", "external_secret_manager_id", "external_secret_manager_assignment", "external_secret_manager_assignment", false)
}

func privateLinksFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyPrivateLinks, "/v1/private-links", "private_link", "private_link")
}

func proxyAgentsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyProxyAgents, "/v1/proxy", "proxy_agent", "proxy_agent")
}

func proxyAgentConnectionsFamily() jsonapi.Family {
	return fivetranScopedAssetFamily(FamilyProxyAgentConnections, "/v1/proxy/{proxy_agent_id}/connections", "proxy_agent_id", "proxy_agent_connection", "proxy_agent_connection", false)
}

func hybridAgentsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyHybridAgents, "/v1/hybrid-deployment-agents", "hybrid_deployment_agent", "hybrid_deployment_agent")
}

func publicConnectorTypesFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyPublicConnectorTypes, "/public/connector-types", "public_connector_type", "public_connector_type")
}

func connectorMetadataFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyConnectorMetadata, "/v1/metadata/connector-types", "connector_metadata", "connector_metadata")
}

func connectorMetadataDetailsFamily() jsonapi.Family {
	family := fivetranScopedAssetFamily(FamilyConnectorMetadataDetails, "/v1/metadata/connector-types/{service}", "service", "connector_metadata_detail", "connector_metadata_detail", true)
	family.DisablePageSize = true
	family.IDKeys = []string{"id", "service", "name"}
	family.Attributes["resource_id"] = "id|service|name"
	family.Attributes["resource_name"] = "name|service|id"
	family.Attributes["service"] = "service|id"
	family.Attributes["source_event_id"] = "id|service|name"
	family.Attributes["status"] = "service_status|status"
	return family
}

func systemKeysFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilySystemKeys, "/v1/system-keys", "system_key", "system_key")
	family.Config.RedactPayloadKeys = []string{"key", "secret"}
	return family
}

func transformationsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyTransformations, "/v1/transformations", "transformation", "transformation")
}

func transformationProjectsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyTransformationProjects, "/v1/transformation-projects", "transformation_project", "transformation_project")
}

func transformationPackageMetadataFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilyTransformationPackageMetadata, "/v1/transformations/package-metadata", "transformation_package_metadata", "transformation_package_metadata")
	family.IDKeys = []string{"package_definition_id", "id", "name"}
	family.Attributes["source_event_id"] = "package_definition_id|id|name"
	family.Attributes["resource_id"] = "package_definition_id|id|name"
	family.Attributes["resource_name"] = "name|package_definition_id"
	return family
}

func transformationPackageDetailsFamily() jsonapi.Family {
	family := fivetranScopedAssetFamily(FamilyTransformationPackageDetails, "/v1/transformations/package-metadata/{package_definition_id}", "package_definition_id", "transformation_package_detail", "transformation_package_detail", true)
	family.DisablePageSize = true
	family.IDKeys = []string{"package_definition_id", "id", "name"}
	family.Attributes["package_definition_id"] = "package_definition_id|id"
	family.Attributes["resource_id"] = "package_definition_id|id|name"
	family.Attributes["resource_name"] = "name|package_definition_id|id"
	family.Attributes["source_event_id"] = "package_definition_id|id|name"
	family.Attributes["status"] = "version|status"
	return family
}

func fivetranSingletonAssetFamily(name string, path string, schema string, resourceType string) jsonapi.Family {
	family := fivetranAssetFamily(name, path, schema, resourceType)
	family.Singleton = true
	family.DisablePageSize = true
	return family
}

func fivetranScopedMembershipFamily(name string, path string, scopeParam string, memberType string) jsonapi.Family {
	staticAttributes := fivetranStaticAttributes(name, "identity_membership", memberType+"_membership")
	staticAttributes["member_type"] = memberType
	return fivetranPagedFamily(jsonapi.Family{
		Name:       name,
		Path:       path,
		PathParams: []string{scopeParam},
		URNKind:    "fivetran_" + name,
		IDKeys:     []string{"id", memberType + "_id", "user_id", "group_id", "connection_id"},
		Attributes: map[string]string{
			scopeParam:        scopeParam,
			"email":           "email",
			"member_id":       "id|" + memberType + "_id|user_id|group_id|connection_id",
			"role":            "role",
			"source_event_id": "id|" + memberType + "_id|user_id|group_id|connection_id",
			"resource_id":     "id|" + memberType + "_id|user_id|group_id|connection_id",
			"resource_name":   "name|email|schema|service",
		},
		StaticAttributes: staticAttributes,
		Config: fivetranFamilyConfig(jsonapi.FamilyConfig{
			ConfigAttributes:   map[string]string{scopeParam: scopeParam},
			IdentityKeys:       []string{scopeParam},
			IdentityResourceID: true,
			ResourceURNKind:    "fivetran_" + name,
		}),
	})
}

func fivetranAssetFamily(name string, path string, schema string, resourceType string) jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          name,
		Path:          path,
		URNKind:       "fivetran_" + name,
		IDKeys:        []string{"id", "name", "schema", "service", "package_definition_id", "entity_id", "key_id"},
		TimestampKeys: []string{"created_at", "updated_at", "last_sync_completed_at", "last_successful_sync"},
		Attributes: map[string]string{
			"source_event_id":            "id|name|schema|service|package_definition_id|entity_id|key_id",
			"resource_id":                "id|name|schema|service|package_definition_id|entity_id|key_id",
			"resource_name":              "name|schema|service|id|entity_id",
			"resource_type":              "resource_type",
			"entity_type":                "entity_type|type",
			"service":                    "service",
			"schema":                     "schema",
			"group_id":                   "group_id",
			"connection_id":              "connection_id",
			"destination_id":             "destination_id",
			"external_secret_manager_id": "external_secret_manager_id|secret_manager_id|esm_id",
			"project_id":                 "project_id|transformation_project_id",
			"transformation_project_id":  "transformation_project_id|project_id",
			"proxy_agent_id":             "proxy_agent_id|agent_id",
			"status":                     "status.setup_state|status.sync_state|status",
			"paused":                     "paused",
			"sync_frequency":             "sync_frequency|sync_frequency_in_minutes",
			"schedule_type":              "schedule_type",
			"observed_at":                "updated_at|created_at",
		},
		StaticAttributes: fivetranStaticAttributes(schema, "asset", resourceType),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_" + name}),
	})
}

func fivetranScopedAssetFamily(name string, path string, scopeParam string, schema string, resourceType string, singleton bool) jsonapi.Family {
	family := fivetranAssetFamily(name, path, schema, resourceType)
	family.PathParams = []string{scopeParam}
	family.Singleton = singleton
	if singleton {
		family.DisablePageSize = true
		family.IDKeys = append([]string{scopeParam}, family.IDKeys...)
	}
	family.Attributes[scopeParam] = scopeParam
	family.Attributes["source_event_id"] = family.Attributes["source_event_id"] + "|" + scopeParam
	family.Attributes["resource_id"] = family.Attributes["resource_id"] + "|" + scopeParam
	family.Config.ConfigAttributes[scopeParam] = scopeParam
	family.Config.IdentityKeys = []string{scopeParam}
	return family
}

func fivetranScopedCredentialFamily(name string, path string, scopeParam string, scopeResourceType string, credentialType string) jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:       name,
		Path:       path,
		PathParams: []string{scopeParam},
		URNKind:    "fivetran_" + name,
		IDKeys:     []string{"id", "hash", "name", "public_key"},
		Attributes: map[string]string{
			scopeParam:        scopeParam,
			"connection_id":   "connection_id",
			"destination_id":  "destination_id",
			"credential_id":   "id|hash|name|public_key",
			"source_event_id": "id|hash|name|public_key",
			"resource_id":     "id|hash|name|public_key",
			"resource_name":   "name|public_key|hash|id",
			"resource_type":   "credential_type",
			"scope_type":      "scope_type",
			"hash":            "hash",
			"public_key":      "public_key",
		},
		StaticAttributes: fivetranCredentialStaticAttributes(name, scopeResourceType, credentialType),
		Config: fivetranFamilyConfig(jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{scopeParam: scopeParam},
			IdentityKeys:     []string{scopeParam},
			ResourceURNKind:  "fivetran_" + name,
		}),
	})
}

func fivetranCredentialStaticAttributes(schema string, scopeType string, credentialType string) map[string]string {
	attributes := fivetranStaticAttributes(schema, "credential", credentialType)
	attributes["scope_type"] = scopeType
	return attributes
}

func fivetranPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "cursor"
	family.NextCursorKeys = []string{"data.next_cursor"}
	family.PageSizeParams = []string{"limit"}
	family.ListKeys = []string{"data.items"}
	return family
}

func fivetranStaticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	return map[string]string{
		"record_class":  recordClass,
		"resource_type": resourceType,
		"schema":        schema,
		"source_system": SourceID,
	}
}

func fivetranV2Headers() map[string]string {
	return map[string]string{"Accept": "application/json;version=2"}
}

func fivetranFamilyConfig(config jsonapi.FamilyConfig) jsonapi.FamilyConfig {
	if config.ConfigAttributes == nil {
		config.ConfigAttributes = map[string]string{}
	}
	config.ConfigAttributes["tenant_id"] = "tenant_id"
	return config
}

func FamilyName(cfg sourcecdk.Config) string {
	if family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")); family != "" {
		return family
	}
	return DefaultFamily
}

func PathParamValues(cfg sourcecdk.Config) (string, []string) {
	switch FamilyName(cfg) {
	case FamilyUserConnections, FamilyUserGroups:
		return "user_id", ConfigListValues(cfg, "user_ids", "user_id")
	case FamilyTeamUsers, FamilyTeamConnections, FamilyTeamGroups:
		return "team_id", ConfigListValues(cfg, "team_ids", "team_id")
	case FamilyGroupUsers, FamilyGroupConnections, FamilyGroupPublicKeys, FamilyGroupServiceAccounts:
		return "group_id", ConfigListValues(cfg, "group_ids", "group_id")
	case FamilyConnectionCertificates, FamilyConnectionFingerprints, FamilyConnectionSchemas, FamilyConnectionState:
		return "connection_id", ConfigListValues(cfg, "connection_ids", "connection_id")
	case FamilyDestinationCertificates, FamilyDestinationFingerprints:
		return "destination_id", ConfigListValues(cfg, "destination_ids", "destination_id")
	case FamilyExternalSecretManagerAssignments:
		return "external_secret_manager_id", ConfigListValues(cfg, "external_secret_manager_ids", "external_secret_manager_id", "esm_ids", "esm_id")
	case FamilyProxyAgentConnections:
		return "proxy_agent_id", ConfigListValues(cfg, "proxy_agent_ids", "proxy_agent_id", "agent_ids", "agent_id")
	case FamilyConnectorMetadataDetails:
		return "service", ConfigListValues(cfg, "connector_services", "services", "service")
	case FamilyTransformationPackageDetails:
		return "package_definition_id", ConfigListValues(cfg, "package_definition_ids", "package_definition_id")
	default:
		return "", nil
	}
}

func ParentFamilyForParam(param string) (string, string) {
	switch param {
	case "user_id":
		return FamilyUsers, "user_id"
	case "team_id":
		return FamilyTeams, "team_id"
	case "group_id":
		return FamilyGroups, "group_id"
	case "connection_id":
		return FamilyConnections, "resource_id"
	case "destination_id":
		return FamilyDestinations, "resource_id"
	case "external_secret_manager_id":
		return FamilyExternalSecretManagers, "resource_id"
	case "proxy_agent_id":
		return FamilyProxyAgents, "resource_id"
	case "service":
		return FamilyConnectorMetadata, "service"
	case "package_definition_id":
		return FamilyTransformationPackageMetadata, "resource_id"
	default:
		return "", ""
	}
}

func ConfigWithValue(cfg sourcecdk.Config, key string, value string) sourcecdk.Config {
	values := cfg.Values()
	values[key] = value
	return sourcecdk.NewConfig(values)
}

func ConfigListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		for _, value := range strings.Split(sourcecdk.ConfigValue(cfg, key), ",") {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func CompactStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = FirstNonEmpty(value)
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

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
