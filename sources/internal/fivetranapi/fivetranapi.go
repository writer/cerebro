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

	FamilyUsers                          = "users"
	FamilyUserConnectionMemberships      = "user_connection_memberships"
	FamilyUserGroupMemberships           = "user_group_memberships"
	FamilyGroups                         = "groups"
	FamilyGroupUsers                     = "group_users"
	FamilyGroupConnections               = "group_connections"
	FamilyTeams                          = "teams"
	FamilyTeamUsers                      = "team_users"
	FamilyTeamGroups                     = "team_groups"
	FamilyTeamConnections                = "team_connections"
	FamilyRoles                          = "roles"
	FamilyDestinations                   = "destinations"
	FamilyDestinationCertificates        = "destination_certificates"
	FamilyDestinationFingerprints        = "destination_fingerprints"
	FamilyConnections                    = "connections"
	FamilyConnectionCertificates         = "connection_certificates"
	FamilyConnectionFingerprints         = "connection_fingerprints"
	FamilyLogServices                    = "log_services"
	FamilyWebhooks                       = "webhooks"
	FamilyPrivateLinks                   = "private_links"
	FamilyProxyAgents                    = "proxy_agents"
	FamilyProxyAgentConnections          = "proxy_agent_connections"
	FamilyHybridDeploymentAgents         = "hybrid_deployment_agents"
	FamilyConnectorMetadata              = "connector_metadata"
	FamilyConnectorSDKPackages           = "connector_sdk_packages"
	FamilySystemKeys                     = "system_keys"
	FamilyExternalSecretsManagers        = "external_secrets_managers"
	FamilyExternalSecretsManagerEntities = "external_secrets_manager_entities"
	FamilyTransformations                = "transformations"
	FamilyTransformationProjects         = "transformation_projects"
	FamilyTransformationPackageMetadata  = "transformation_package_metadata"
)

var TemplateKeys = []string{"base_url", "api_key", "api_secret", "username", "password"}

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		usersFamily(),
		userConnectionMembershipsFamily(),
		userGroupMembershipsFamily(),
		groupsFamily(),
		groupUsersFamily(),
		groupConnectionsFamily(),
		teamsFamily(),
		teamUsersFamily(),
		teamGroupsFamily(),
		teamConnectionsFamily(),
		rolesFamily(),
		destinationsFamily(),
		destinationCertificatesFamily(),
		destinationFingerprintsFamily(),
		connectionsFamily(),
		connectionCertificatesFamily(),
		connectionFingerprintsFamily(),
		logServicesFamily(),
		webhooksFamily(),
		privateLinksFamily(),
		proxyAgentsFamily(),
		proxyAgentConnectionsFamily(),
		hybridDeploymentAgentsFamily(),
		connectorMetadataFamily(),
		connectorSDKPackagesFamily(),
		systemKeysFamily(),
		externalSecretsManagersFamily(),
		externalSecretsManagerEntitiesFamily(),
		transformationsFamily(),
		transformationProjectsFamily(),
		transformationPackageMetadataFamily(),
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
	case FamilyUserConnectionMemberships, FamilyUserGroupMemberships:
		return "userId", configListValues(cfg, "user_ids", "user_id")
	case FamilyGroupUsers, FamilyGroupConnections:
		return "groupId", configListValues(cfg, "group_ids", "group_id")
	case FamilyTeamUsers, FamilyTeamGroups, FamilyTeamConnections:
		return "teamId", configListValues(cfg, "team_ids", "team_id")
	case FamilyConnectionCertificates, FamilyConnectionFingerprints:
		return "connectionId", configListValues(cfg, "connection_ids", "connection_id")
	case FamilyDestinationCertificates, FamilyDestinationFingerprints:
		return "destinationId", configListValues(cfg, "destination_ids", "destination_id")
	case FamilyProxyAgentConnections:
		return "agentId", configListValues(cfg, "proxy_agent_ids", "proxy_agent_id", "agent_ids", "agent_id")
	default:
		return "", nil
	}
}

func RuntimeConfig(cfg sourcecdk.Config) (sourcecdk.Config, error) {
	resolved, err := sourcecdk.ResolveBaseURLConfig(SourceID, DefaultBaseURLTemplate, cfg, TemplateKeys)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values := resolved.Values()
	if strings.TrimSpace(values["username"]) == "" && strings.TrimSpace(values["api_key"]) != "" {
		values["username"] = strings.TrimSpace(values["api_key"])
	}
	if strings.TrimSpace(values["password"]) == "" && strings.TrimSpace(values["api_secret"]) != "" {
		values["password"] = strings.TrimSpace(values["api_secret"])
	}
	return sourcecdk.NewConfig(values), nil
}

func pagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "cursor"
	family.NextCursorKeys = []string{"data.next_cursor"}
	family.PageSizeParams = []string{"limit"}
	family.ListKeys = []string{"data.items"}
	if family.TimestampKeys == nil {
		family.TimestampKeys = []string{"updated_at", "created_at", "last_used_at", "registered_at"}
	}
	return family
}

func usersFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:    FamilyUsers,
		Path:    "/v1/users",
		URNKind: "fivetran_users",
		IDKeys:  []string{"id", "email"},
		Attributes: map[string]string{
			"active":          "active",
			"created_at":      "created_at",
			"display_name":    "given_name|family_name|email|id",
			"email":           "email",
			"family_name":     "family_name",
			"given_name":      "given_name",
			"last_login_at":   "logged_in_at",
			"login":           "email|id",
			"role":            "role",
			"source_event_id": "id",
			"status":          "active|invited|verified",
			"user_id":         "id",
			"verified":        "verified",
		},
		StaticAttributes: staticAttrs("identity_user", FamilyUsers),
	})
}

func userConnectionMembershipsFamily() jsonapi.Family {
	return membershipFamily(FamilyUserConnectionMemberships, "/v1/users/{userId}/connections", "userId", "connection")
}

func userGroupMembershipsFamily() jsonapi.Family {
	return membershipFamily(FamilyUserGroupMemberships, "/v1/users/{userId}/groups", "userId", "group")
}

func groupsFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:    FamilyGroups,
		Path:    "/v1/groups",
		URNKind: "fivetran_groups",
		IDKeys:  []string{"id", "name"},
		Attributes: map[string]string{
			"created_at":      "created_at",
			"group_id":        "id",
			"group_name":      "name",
			"name":            "name",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "group",
			"source_event_id": "id",
		},
		StaticAttributes: staticAttrs("identity_group", FamilyGroups),
	})
}

func groupUsersFamily() jsonapi.Family {
	family := usersFamily()
	family.Name = FamilyGroupUsers
	family.Path = "/v1/groups/{groupId}/users"
	family.PathParams = []string{"groupId"}
	family.URNKind = "fivetran_group_users"
	family.Config.ConfigAttributes = map[string]string{"group_id": "groupId"}
	family.Attributes["group_id"] = "group_id"
	family.StaticAttributes = staticAttrs("identity_membership", FamilyGroupUsers, map[string]string{"member_type": "user", "resource_type": "user"})
	return family
}

func groupConnectionsFamily() jsonapi.Family {
	family := connectionAssetFamily(FamilyGroupConnections, "/v1/groups/{groupId}/connections", "connection")
	family.PathParams = []string{"groupId"}
	family.Config.ConfigAttributes = map[string]string{"group_id": "groupId"}
	family.Attributes["group_id"] = "group_id"
	return family
}

func teamsFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:    FamilyTeams,
		Path:    "/v1/teams",
		URNKind: "fivetran_teams",
		IDKeys:  []string{"id", "name"},
		Attributes: map[string]string{
			"description":     "description",
			"name":            "name",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "team",
			"role":            "role",
			"source_event_id": "id",
			"team_id":         "id",
			"team_name":       "name",
		},
		StaticAttributes: staticAttrs("authorization_scope", FamilyTeams),
	})
}

func teamUsersFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:       FamilyTeamUsers,
		Path:       "/v1/teams/{teamId}/users",
		PathParams: []string{"teamId"},
		URNKind:    "fivetran_team_users",
		IDKeys:     []string{"user_id"},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"team_id": "teamId"},
		},
		Attributes: map[string]string{
			"created_at":      "created_at",
			"member_id":       "user_id",
			"member_type":     "user",
			"role":            "role",
			"source_event_id": "user_id",
			"team_id":         "team_id",
			"user_id":         "user_id",
		},
		StaticAttributes: staticAttrs("identity_membership", FamilyTeamUsers, map[string]string{"member_type": "user", "resource_type": "user"}),
	})
}

func teamGroupsFamily() jsonapi.Family {
	return membershipFamily(FamilyTeamGroups, "/v1/teams/{teamId}/groups", "teamId", "group")
}

func teamConnectionsFamily() jsonapi.Family {
	return membershipFamily(FamilyTeamConnections, "/v1/teams/{teamId}/connections", "teamId", "connection")
}

func rolesFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:    FamilyRoles,
		Path:    "/v1/roles",
		URNKind: "fivetran_roles",
		IDKeys:  []string{"name", "replacement_role_name"},
		Attributes: map[string]string{
			"description":           "description",
			"is_custom":             "is_custom",
			"is_deprecated":         "is_deprecated",
			"replacement_role_name": "replacement_role_name",
			"role_id":               "name",
			"role_name":             "name",
			"role_scope":            "scope",
			"role_status":           "is_deprecated",
			"role_type":             "scope",
			"source_event_id":       "name",
		},
		StaticAttributes: staticAttrs("authorization_role", FamilyRoles),
	})
}

func destinationsFamily() jsonapi.Family {
	return assetFamily(FamilyDestinations, "/v1/destinations", "destination")
}

func destinationCertificatesFamily() jsonapi.Family {
	return childAssetFamily(FamilyDestinationCertificates, "/v1/destinations/{destinationId}/certificates", "destinationId", "certificate")
}

func destinationFingerprintsFamily() jsonapi.Family {
	return childAssetFamily(FamilyDestinationFingerprints, "/v1/destinations/{destinationId}/fingerprints", "destinationId", "fingerprint")
}

func connectionsFamily() jsonapi.Family {
	return connectionAssetFamily(FamilyConnections, "/v1/connections", "connection")
}

func connectionCertificatesFamily() jsonapi.Family {
	return childAssetFamily(FamilyConnectionCertificates, "/v1/connections/{connectionId}/certificates", "connectionId", "certificate")
}

func connectionFingerprintsFamily() jsonapi.Family {
	return childAssetFamily(FamilyConnectionFingerprints, "/v1/connections/{connectionId}/fingerprints", "connectionId", "fingerprint")
}

func logServicesFamily() jsonapi.Family {
	return assetFamily(FamilyLogServices, "/v1/external-logging", "log_service")
}

func webhooksFamily() jsonapi.Family {
	return assetFamily(FamilyWebhooks, "/v1/webhooks", "webhook")
}

func privateLinksFamily() jsonapi.Family {
	return assetFamily(FamilyPrivateLinks, "/v1/private-links", "private_link")
}

func proxyAgentsFamily() jsonapi.Family {
	return assetFamily(FamilyProxyAgents, "/v1/proxy", "proxy_agent")
}

func proxyAgentConnectionsFamily() jsonapi.Family {
	return childAssetFamily(FamilyProxyAgentConnections, "/v1/proxy/{agentId}/connections", "agentId", "connection")
}

func hybridDeploymentAgentsFamily() jsonapi.Family {
	return assetFamily(FamilyHybridDeploymentAgents, "/v1/hybrid-deployment-agents", "hybrid_deployment_agent")
}

func connectorMetadataFamily() jsonapi.Family {
	return assetFamily(FamilyConnectorMetadata, "/v1/metadata/connector-types", "connector_type")
}

func connectorSDKPackagesFamily() jsonapi.Family {
	return assetFamily(FamilyConnectorSDKPackages, "/v1/connector-sdk/packages", "connector_sdk_package")
}

func systemKeysFamily() jsonapi.Family {
	return assetFamily(FamilySystemKeys, "/v1/system-keys", "system_key")
}

func externalSecretsManagersFamily() jsonapi.Family {
	return assetFamily(FamilyExternalSecretsManagers, "/v1/external-secrets-managers", "external_secrets_manager")
}

func externalSecretsManagerEntitiesFamily() jsonapi.Family {
	return assetFamily(FamilyExternalSecretsManagerEntities, "/v1/external-secrets-managers-entities", "external_secrets_manager_entity")
}

func transformationsFamily() jsonapi.Family {
	return assetFamily(FamilyTransformations, "/v1/transformations", "transformation")
}

func transformationProjectsFamily() jsonapi.Family {
	return assetFamily(FamilyTransformationProjects, "/v1/transformation-projects", "transformation_project")
}

func transformationPackageMetadataFamily() jsonapi.Family {
	return assetFamily(FamilyTransformationPackageMetadata, "/v1/transformations/package-metadata", "transformation_package_metadata")
}

func assetFamily(name string, path string, resourceType string) jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:    name,
		Path:    path,
		URNKind: "fivetran_" + name,
		IDKeys:  []string{"id", "name", "connection_id"},
		Attributes: map[string]string{
			"account_id":      "account_id",
			"active":          "active|enabled|online",
			"created_at":      "created_at|registered_at",
			"created_by":      "created_by|created_by_id",
			"description":     "description|state_summary",
			"display_name":    "display_name|name",
			"enabled":         "enabled|active",
			"group_id":        "group_id",
			"name":            "name|display_name|schema|service|type|id",
			"region":          "region",
			"resource_id":     "id|connection_id",
			"resource_name":   "name|display_name|schema|service|type|id|connection_id",
			"resource_status": "status|setup_status|state|enabled|active|online|paused",
			"resource_type":   resourceType,
			"service":         "service|type",
			"source_event_id": "id|connection_id|name",
			"updated_at":      "updated_at|last_used_at|last_started_at|last_ended_at",
			"version":         "version|service_version",
		},
		StaticAttributes: staticAttrs("asset", name, map[string]string{"resource_type": resourceType}),
	})
}

func connectionAssetFamily(name string, path string, resourceType string) jsonapi.Family {
	family := assetFamily(name, path, resourceType)
	family.Attributes["connection_id"] = "id|connection_id"
	family.Attributes["destination_id"] = "destination_id"
	family.Attributes["paused"] = "paused"
	family.Attributes["schema"] = "schema"
	family.Attributes["sync_frequency"] = "sync_frequency"
	return family
}

func childAssetFamily(name string, path string, param string, resourceType string) jsonapi.Family {
	family := assetFamily(name, path, resourceType)
	family.PathParams = []string{param}
	configKey := configKeyForPathParam(param)
	family.Config.ConfigAttributes = map[string]string{configKey: param}
	family.Attributes[configKey] = configKey
	return family
}

func membershipFamily(name string, path string, param string, memberType string) jsonapi.Family {
	family := pagedFamily(jsonapi.Family{
		Name:       name,
		Path:       path,
		PathParams: []string{param},
		URNKind:    "fivetran_" + name,
		IDKeys:     []string{"id", "user_id", "connection_id"},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{configKeyForPathParam(param): param},
		},
		Attributes: map[string]string{
			"created_at":      "created_at",
			"member_id":       "id|user_id|connection_id",
			"member_type":     memberType,
			"name":            "name|id|user_id|connection_id",
			"resource_id":     "id|user_id|connection_id",
			"resource_name":   "name|id|user_id|connection_id",
			"resource_type":   memberType,
			"role":            "role",
			"source_event_id": "id|user_id|connection_id",
		},
		StaticAttributes: staticAttrs("relationship", name, map[string]string{"member_type": memberType, "resource_type": memberType}),
	})
	family.Attributes[configKeyForPathParam(param)] = configKeyForPathParam(param)
	return family
}

func configKeyForPathParam(param string) string {
	switch param {
	case "userId":
		return "user_id"
	case "groupId":
		return "group_id"
	case "teamId":
		return "team_id"
	case "connectionId":
		return "connection_id"
	case "destinationId":
		return "destination_id"
	case "agentId":
		return "proxy_agent_id"
	default:
		return strings.TrimSpace(param)
	}
}

func staticAttrs(recordClass string, schema string, extras ...map[string]string) map[string]string {
	attrs := map[string]string{
		"record_class":  recordClass,
		"schema":        schema,
		"source_system": SourceID,
	}
	for _, extra := range extras {
		for key, value := range extra {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				attrs[key] = value
			}
		}
	}
	return attrs
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, key := range keys {
		for _, value := range strings.FieldsFunc(sourcecdk.ConfigValue(cfg, key), func(r rune) bool {
			return r == ',' || r == '\n' || r == '\t' || r == ' '
		}) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values
}
