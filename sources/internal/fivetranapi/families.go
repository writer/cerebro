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

	FamilyUsers                  = "users"
	FamilyUserConnections        = "user_connections"
	FamilyUserGroups             = "user_groups"
	FamilyRoles                  = "roles"
	FamilyTeams                  = "teams"
	FamilyTeamUsers              = "team_users"
	FamilyTeamConnections        = "team_connections"
	FamilyTeamGroups             = "team_groups"
	FamilyGroups                 = "groups"
	FamilyGroupUsers             = "group_users"
	FamilyGroupConnections       = "group_connections"
	FamilyDestinations           = "destinations"
	FamilyConnections            = "connections"
	FamilyConnectionCertificates = "connection_certificates"
	FamilyConnectionFingerprints = "connection_fingerprints"
	FamilyLogServices            = "log_services"
	FamilyWebhooks               = "webhooks"
	FamilyPrivateLinks           = "private_links"
	FamilyProxyAgents            = "proxy_agents"
	FamilyHybridAgents           = "hybrid_deployment_agents"
	FamilyConnectorMetadata      = "connector_metadata"
	FamilySystemKeys             = "system_keys"
	FamilyTransformations        = "transformations"
)

func Families() []jsonapi.Family {
	return []jsonapi.Family{
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
		destinationsFamily(),
		connectionsFamily(),
		connectionCertificatesFamily(),
		connectionFingerprintsFamily(),
		logServicesFamily(),
		webhooksFamily(),
		privateLinksFamily(),
		proxyAgentsFamily(),
		hybridAgentsFamily(),
		connectorMetadataFamily(),
		systemKeysFamily(),
		transformationsFamily(),
	}
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
	return fivetranConnectionCredentialFamily(FamilyConnectionCertificates, "/v1/connections/{connection_id}/certificates", "certificate")
}

func connectionFingerprintsFamily() jsonapi.Family {
	return fivetranConnectionCredentialFamily(FamilyConnectionFingerprints, "/v1/connections/{connection_id}/fingerprints", "fingerprint")
}

func logServicesFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyLogServices, "/v1/external-logging", "log_service", "log_service")
}

func webhooksFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyWebhooks, "/v1/webhooks", "webhook", "webhook")
}

func privateLinksFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyPrivateLinks, "/v1/private-links", "private_link", "private_link")
}

func proxyAgentsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyProxyAgents, "/v1/proxy", "proxy_agent", "proxy_agent")
}

func hybridAgentsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyHybridAgents, "/v1/hybrid-deployment-agents", "hybrid_deployment_agent", "hybrid_deployment_agent")
}

func connectorMetadataFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyConnectorMetadata, "/v1/metadata/connector-types", "connector_metadata", "connector_metadata")
}

func systemKeysFamily() jsonapi.Family {
	family := fivetranAssetFamily(FamilySystemKeys, "/v1/system-keys", "system_key", "system_key")
	family.Config.RedactPayloadKeys = []string{"key", "secret"}
	return family
}

func transformationsFamily() jsonapi.Family {
	return fivetranAssetFamily(FamilyTransformations, "/v1/transformations", "transformation", "transformation")
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
			ConfigAttributes: map[string]string{scopeParam: scopeParam},
			IdentityKeys:     []string{scopeParam},
			ResourceURNKind:  "fivetran_" + name,
		}),
	})
}

func fivetranAssetFamily(name string, path string, schema string, resourceType string) jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:          name,
		Path:          path,
		URNKind:       "fivetran_" + name,
		IDKeys:        []string{"id", "name", "schema", "service"},
		TimestampKeys: []string{"created_at", "updated_at", "last_sync_completed_at", "last_successful_sync"},
		Attributes: map[string]string{
			"source_event_id": "id|name|schema|service",
			"resource_id":     "id|name|schema|service",
			"resource_name":   "name|schema|service|id",
			"resource_type":   "resource_type",
			"service":         "service",
			"schema":          "schema",
			"group_id":        "group_id",
			"destination_id":  "destination_id|group_id",
			"status":          "status.setup_state|status.sync_state|status",
			"paused":          "paused",
			"sync_frequency":  "sync_frequency|sync_frequency_in_minutes",
			"schedule_type":   "schedule_type",
			"observed_at":     "updated_at|created_at",
		},
		StaticAttributes: fivetranStaticAttributes(schema, "asset", resourceType),
		Config:           fivetranFamilyConfig(jsonapi.FamilyConfig{ResourceURNKind: "fivetran_" + name}),
	})
}

func fivetranConnectionCredentialFamily(name string, path string, credentialType string) jsonapi.Family {
	return fivetranPagedFamily(jsonapi.Family{
		Name:       name,
		Path:       path,
		PathParams: []string{"connection_id"},
		URNKind:    "fivetran_" + name,
		IDKeys:     []string{"id", "hash", "name", "public_key"},
		Attributes: map[string]string{
			"connection_id":   "connection_id",
			"credential_id":   "id|hash|name|public_key",
			"source_event_id": "id|hash|name|public_key",
			"resource_id":     "id|hash|name|public_key",
			"resource_name":   "name|public_key|hash|id",
			"resource_type":   "credential_type",
			"hash":            "hash",
			"public_key":      "public_key",
		},
		StaticAttributes: fivetranStaticAttributes(name, "credential", credentialType),
		Config: fivetranFamilyConfig(jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"connection_id": "connection_id"},
			IdentityKeys:     []string{"connection_id"},
			ResourceURNKind:  "fivetran_" + name,
		}),
	})
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

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
