package auth0api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID                   = "auth0"
	DefaultFamily              = FamilyUsers
	DefaultHealthPath          = "/users"
	DefaultBaseURLTemplate     = "https://${config.domain}/api/v2"
	TokenScheme                = "Bearer"
	oauthTokenURLTemplate      = "https://${config.domain}/oauth/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 60 * time.Second

	FamilyUsers                     = "users"
	FamilyRoles                     = "roles"
	FamilyAuditEvents               = "audit_events"
	FamilyOrganizations             = "organizations"
	FamilyOrganizationMembers       = "organization_members"
	FamilyClients                   = "clients"
	FamilyConnections               = "connections"
	FamilyResourceServers           = "resource_servers"
	FamilyClientGrants              = "client_grants"
	FamilyGrants                    = "grants"
	FamilyUserRoles                 = "user_roles"
	FamilyUserAuthenticationMethods = "user_authentication_methods"
	FamilyGuardianFactors           = "guardian_factors"
)

var templateKeys = []string{"domain", "client_id", "client_secret"}

var oauthScopes = []string{
	"read:client_grants",
	"read:clients",
	"read:connections",
	"read:grants",
	"read:guardian_factors",
	"read:authentication_methods",
	"read:logs",
	"read:organization_member_roles",
	"read:organization_members",
	"read:organizations",
	"read:resource_servers",
	"read:role_members",
	"read:roles",
	"read:users",
}

var oauthTokenParams = map[string]string{"audience": "https://${config.domain}/api/v2/"}

// Families returns Auth0 Management API-backed families with provider paging,
// list keys, and graph-ready attribute mappings.
func Families() []jsonapi.Family {
	return []jsonapi.Family{
		usersFamily(),
		rolesFamily(),
		auditEventsFamily(),
		organizationsFamily(),
		organizationMembersFamily(),
		clientsFamily(),
		connectionsFamily(),
		resourceServersFamily(),
		clientGrantsFamily(),
		grantsFamily(),
		userRolesFamily(),
		userAuthenticationMethodsFamily(),
		guardianFactorsFamily(),
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
	case FamilyOrganizationMembers:
		return "organization_id", configListValues(cfg, "organization_ids", "organization_id")
	case FamilyUserRoles, FamilyUserAuthenticationMethods:
		return "user_id", configListValues(cfg, "user_ids", "user_id")
	default:
		return "", nil
	}
}

func RuntimeConfig(ctx context.Context, cfg sourcecdk.Config, cache *sourcehttp.ClientCredentialsCache, allowLoopback bool) (sourcecdk.Config, error) {
	if err := ValidateDomain(sourcecdk.ConfigValue(cfg, "domain")); err != nil {
		return sourcecdk.Config{}, err
	}
	return sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, sourcehttp.ClientCredentialsRuntimeConfigOptions{
		SourceID:               SourceID,
		DefaultBaseURLTemplate: DefaultBaseURLTemplate,
		TemplateKeys:           templateKeys,
		TokenCache:             cache,
		TokenURLTemplate:       oauthTokenURLTemplate,
		Scopes:                 oauthScopes,
		ScopeSeparator:         oauthScopeSeparator,
		TokenParams:            oauthTokenParams,
		ExpirationBuffer:       oauthTokenExpirationBuffer,
		AllowLoopback:          allowLoopback,
	})
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

func ValidateDomain(value string) error {
	domain := strings.ToLower(strings.TrimSpace(value))
	if domain == "" {
		return fmt.Errorf("%w: %s domain is required", sourcecdk.ErrInvalidConfig, SourceID)
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/?#@") || strings.Contains(domain, ":") {
		return fmt.Errorf("%w: %s domain must be a bare Auth0 hostname", sourcecdk.ErrInvalidConfig, SourceID)
	}
	if !strings.HasSuffix(domain, ".auth0.com") {
		return fmt.Errorf("%w: %s domain must be an Auth0 hostname", sourcecdk.ErrInvalidConfig, SourceID)
	}
	return nil
}

func usersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:                 FamilyUsers,
		Path:                 "/users",
		URNKind:              "runtime_users",
		IDKeys:               []string{"user_id", "name", "id", "email", "primary_email", "login"},
		CursorParam:          "page",
		PageFirstCursor:      "0",
		PageSizeParams:       []string{"per_page"},
		TimestampKeys:        []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
		Attributes:           mergeAttributes(identityUserAttributes(), map[string]string{"mfa_enrolled": "multifactor|mfa_enrolled", "status": "status|state|lifecycle_state|blocked"}),
		StaticAttributes:     map[string]string{"record_class": "identity_user", "resource_type": "identity_user", "schema": "users", "source_system": SourceID},
		Config:               jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_users"},
		IncrementalWatermark: true,
	}
}

func rolesFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:                 FamilyRoles,
		Path:                 "/roles",
		URNKind:              "runtime_roles",
		IDKeys:               []string{"id", "name", "group_id", "group_email", "email"},
		CursorParam:          "page",
		PageFirstCursor:      "0",
		PageSizeParams:       []string{"per_page"},
		TimestampKeys:        []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
		Attributes:           identityGroupAttributes(),
		StaticAttributes:     map[string]string{"record_class": "identity_group", "resource_type": "role", "schema": "roles", "source_system": SourceID},
		Config:               jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_roles"},
		IncrementalWatermark: true,
	}
}

func auditEventsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:                 FamilyAuditEvents,
		Path:                 "/logs",
		URNKind:              "runtime_audit_events",
		IDKeys:               []string{"log_id", "event_id", "id", "uuid", "request_id"},
		CursorParam:          "from",
		PageSizeParams:       []string{"take"},
		TimestampKeys:        []string{"date", "observed_at", "updated_at", "last_seen_at", "created_at"},
		Attributes:           auditEventAttributes(),
		StaticAttributes:     map[string]string{"record_class": "audit_event", "resource_type": "application", "schema": "audit_events", "source_system": SourceID},
		Config:               jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_applications"},
		IncrementalWatermark: true,
	}
}

func organizationsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyOrganizations,
		Path:             "/organizations",
		URNKind:          "runtime_organizations",
		IDKeys:           []string{"id", "name", "display_name"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "observed_at"},
		Attributes:       organizationAttributes(),
		StaticAttributes: map[string]string{"record_class": "organization", "resource_type": "organization", "schema": "organizations", "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_organizations"},
	}
}

func organizationMembersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyOrganizationMembers,
		Path:             "/organizations/{organization_id}/members",
		PathParams:       []string{"organization_id"},
		URNKind:          "runtime_organization_members",
		IDKeys:           []string{"user_id", "id", "email"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "last_login"},
		Attributes:       organizationMemberAttributes(),
		StaticAttributes: map[string]string{"member_type": "user", "record_class": "identity_group_membership", "resource_type": "organization_member", "schema": "organization_members", "source_system": SourceID},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"group_id": "organization_id", "organization_id": "organization_id"},
			ConfigQuery:      map[string]string{"fields": "organization_member_fields"},
			EncodeURNID:      true,
			ResourceURNKind:  "runtime_organization_members",
		},
	}
}

func clientsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyClients,
		Path:             "/clients",
		URNKind:          "runtime_applications",
		IDKeys:           []string{"client_id", "id", "name"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "observed_at"},
		Attributes:       applicationAttributes(),
		StaticAttributes: map[string]string{"record_class": "identity_application", "resource_type": "application", "schema": "clients", "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_applications"},
	}
}

func connectionsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyConnections,
		Path:            "/connections",
		URNKind:         "runtime_connections",
		IDKeys:          []string{"id", "name", "strategy"},
		CursorParam:     "page",
		PageFirstCursor: "0",
		PageSizeParams:  []string{"per_page"},
		TimestampKeys:   []string{"updated_at", "created_at", "observed_at"},
		Attributes: mergeAttributes(applicationAttributes(), map[string]string{
			"app_id":           "id",
			"app_name":         "name",
			"connection_id":    "id",
			"connection_name":  "name",
			"enabled_clients":  "enabled_clients",
			"resource_id":      "id",
			"resource_name":    "name",
			"resource_type":    "connection",
			"strategy":         "strategy",
			"strategy_version": "strategy_version",
		}),
		StaticAttributes: map[string]string{"record_class": "identity_connection", "resource_type": "connection", "schema": "connections", "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_connections"},
	}
}

func resourceServersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyResourceServers,
		Path:             "/resource-servers",
		URNKind:          "runtime_resource_servers",
		IDKeys:           []string{"id", "identifier", "name"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "observed_at"},
		Attributes:       resourceServerAttributes(),
		StaticAttributes: map[string]string{"record_class": "identity_api", "resource_type": "api", "schema": "resource_servers", "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_resource_servers"},
	}
}

func clientGrantsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyClientGrants,
		Path:            "/client-grants",
		URNKind:         "runtime_client_grants",
		IDKeys:          []string{"id", "client_id", "audience"},
		CursorParam:     "page",
		PageFirstCursor: "0",
		PageSizeParams:  []string{"per_page"},
		TimestampKeys:   []string{"updated_at", "created_at", "observed_at"},
		Attributes:      clientGrantAttributes(),
		StaticAttributes: map[string]string{
			"record_class":  "identity_app_assignment",
			"resource_type": "client_grant",
			"schema":        "client_grants",
			"source_system": SourceID,
			"subject_type":  "application",
		},
		Config: jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_client_grants"},
	}
}

func grantsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            FamilyGrants,
		Path:            "/grants",
		URNKind:         "runtime_grants",
		IDKeys:          []string{"id", "user_id", "client_id", "audience"},
		CursorParam:     "page",
		PageFirstCursor: "0",
		PageSizeParams:  []string{"per_page"},
		TimestampKeys:   []string{"updated_at", "created_at", "observed_at"},
		Attributes:      grantAttributes(),
		StaticAttributes: map[string]string{
			"record_class":  "identity_app_assignment",
			"resource_type": "grant",
			"schema":        "grants",
			"source_system": SourceID,
			"subject_type":  "user",
		},
		Config: jsonapi.FamilyConfig{
			ConfigQuery:     map[string]string{"audience": "grant_audience", "client_id": "grant_client_id", "user_id": "grant_user_id"},
			EncodeURNID:     true,
			ResourceURNKind: "runtime_grants",
		},
	}
}

func userRolesFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyUserRoles,
		Path:             "/users/{user_id}/roles",
		PathParams:       []string{"user_id"},
		URNKind:          "runtime_user_roles",
		IDKeys:           []string{"id", "name"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "observed_at"},
		Attributes:       userRoleAttributes(),
		StaticAttributes: map[string]string{"member_type": "user", "record_class": "identity_group_membership", "resource_type": "role_membership", "schema": "user_roles", "source_system": SourceID},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"member_user_id": "user_id", "user_id": "user_id"},
			EncodeURNID:      true,
			ResourceURNKind:  "runtime_user_roles",
		},
	}
}

func userAuthenticationMethodsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyUserAuthenticationMethods,
		Path:             "/users/{user_id}/authentication-methods",
		PathParams:       []string{"user_id"},
		URNKind:          "runtime_authentication_methods",
		IDKeys:           []string{"id", "name", "type"},
		CursorParam:      "page",
		PageFirstCursor:  "0",
		PageSizeParams:   []string{"per_page"},
		TimestampKeys:    []string{"updated_at", "created_at", "last_auth_at", "observed_at"},
		Attributes:       authenticationMethodAttributes(),
		StaticAttributes: map[string]string{"record_class": "identity_credential", "resource_type": "authentication_method", "schema": "user_authentication_methods", "source_system": SourceID},
		Config: jsonapi.FamilyConfig{
			ConfigAttributes: map[string]string{"owner_user_id": "user_id", "user_id": "user_id"},
			EncodeURNID:      true,
			ResourceURNKind:  "runtime_authentication_methods",
		},
	}
}

func guardianFactorsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             FamilyGuardianFactors,
		Path:             "/guardian/factors",
		URNKind:          "runtime_guardian_factors",
		IDKeys:           []string{"name", "id", "type"},
		DisablePageSize:  true,
		TimestampKeys:    []string{"updated_at", "created_at", "observed_at"},
		Attributes:       guardianFactorAttributes(),
		StaticAttributes: map[string]string{"record_class": "identity_credential", "resource_type": "guardian_factor", "schema": "guardian_factors", "source_system": SourceID},
		Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_guardian_factors"},
	}
}

func commonRuntimeAttributes() map[string]string {
	return map[string]string{
		"domain":                   "domain|tenant_domain|organization_domain",
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"observed_at":              "observed_at|updated_at|last_seen_at|created_at",
		"tenant_id":                "tenant_id|metadata.tenant_id",
	}
}

func identityUserAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"created_at":      "created_at|created|profile.created_at",
		"department":      "department|profile.department",
		"display_name":    "display_name|name|nickname|profile.display_name|profile.name",
		"email":           "email|primary_email|profile.email",
		"job_title":       "job_title|title|profile.title",
		"last_login_at":   "last_login_at|last_login|last_seen_at",
		"login":           "login|username|email|profile.login",
		"manager":         "manager|profile.manager",
		"primary_email":   "primary_email|email|profile.email",
		"resource_id":     "resource_id|user_id|id|metadata.resource_id",
		"resource_name":   "name|display_name|nickname|hostname|metadata.resource_name",
		"resource_type":   "resource_type|type|metadata.resource_type",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "event_id|user_id|id|metadata.event_id",
		"status":          "status|state|lifecycle_state",
		"user_id":         "user_id|id|uid",
	})
}

func identityGroupAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"description":     "description|summary",
		"group_email":     "group_email|email",
		"group_id":        "group_id|id",
		"group_name":      "group_name|name|display_name",
		"resource_id":     "resource_id|id|metadata.resource_id",
		"resource_name":   "name|display_name|hostname|metadata.resource_name",
		"resource_type":   "resource_type|type|metadata.resource_type",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "event_id|id|metadata.event_id",
	})
}

func auditEventAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"observed_at":     "observed_at|updated_at|last_seen_at|date",
		"actor_email":     "actor_email|actor.email|email|user.email|user_name",
		"actor_id":        "actor_id|actor.id|actorId|user_id|user.id",
		"actor_name":      "actor_name|actor.name|user.name|user_name",
		"event_type":      "event_type|event_name|action|type",
		"resource_email":  "resource_email|target_email|target.email",
		"resource_id":     "resource_id|target_id|target.id|resource.id|object_id|client_id",
		"resource_name":   "resource_name|target_name|target.name|resource.name|object_name|client_name",
		"resource_type":   "resource_type|target_type|target.type|object_type",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "event_id|log_id|id|metadata.event_id",
	})
}

func organizationAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"display_name":      "display_name|name",
		"metadata":          "metadata",
		"organization_id":   "id",
		"organization_name": "name",
		"resource_id":       "id",
		"resource_name":     "display_name|name",
		"resource_type":     "organization",
		"resource_urn":      "resource_urn|urn|metadata.resource_urn",
		"source_event_id":   "id",
	})
}

func organizationMemberAttributes() map[string]string {
	return mergeAttributes(identityUserAttributes(), map[string]string{
		"group_name":      "organization_name|org_name|organization_id",
		"member_email":    "email|primary_email",
		"member_name":     "name|nickname|email",
		"member_status":   "status|blocked",
		"member_user_id":  "user_id|id",
		"role":            "roles",
		"source_event_id": "user_id|id|email",
	})
}

func applicationAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"allowed_clients":                "allowed_clients",
		"app_id":                         "client_id|id",
		"app_name":                       "name|app_name|client_name",
		"application_type":               "app_type|application_type",
		"client_id":                      "client_id|id",
		"grant_types":                    "grant_types",
		"logo_uri":                       "logo_uri",
		"oauth2":                         "oidc_conformant|oauth2",
		"oauth_client_type":              "app_type|application_type",
		"oauth_public_client":            "is_first_party",
		"post_logout_redirect_uri_hosts": "allowed_logout_urls",
		"redirect_uri_hosts":             "callbacks|allowed_origins|web_origins",
		"resource_id":                    "client_id|id",
		"resource_name":                  "name|app_name|client_name",
		"resource_type":                  "application",
		"resource_urn":                   "resource_urn|urn|metadata.resource_urn",
		"response_types":                 "jwt_configuration.scopes|response_types",
		"sign_on_mode":                   "sso|sign_on_mode",
		"source_event_id":                "client_id|id",
		"status":                         "status|is_first_party",
		"token_endpoint_auth_method":     "token_endpoint_auth_method",
	})
}

func resourceServerAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"allow_offline_access": "allow_offline_access",
		"api_id":               "id",
		"api_identifier":       "identifier",
		"api_name":             "name",
		"app_id":               "identifier|id",
		"app_name":             "name|identifier",
		"resource_id":          "id|identifier",
		"resource_name":        "name|identifier",
		"resource_type":        "api",
		"resource_urn":         "resource_urn|urn|metadata.resource_urn",
		"scopes":               "scopes",
		"source_event_id":      "id|identifier",
		"signing_alg":          "signing_alg",
		"token_lifetime":       "token_lifetime",
	})
}

func clientGrantAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"app_id":          "client_id",
		"audience":        "audience",
		"client_grant_id": "id",
		"client_id":       "client_id",
		"entitlement":     "scope|audience",
		"entitlement_id":  "id",
		"resource_id":     "id",
		"resource_name":   "audience|client_id|id",
		"resource_type":   "client_grant",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"scope":           "scope",
		"source_event_id": "id",
		"subject_id":      "client_id",
		"subject_type":    "application",
	})
}

func grantAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"app_id":          "client_id",
		"audience":        "audience",
		"entitlement":     "scope|audience",
		"entitlement_id":  "id",
		"grant_id":        "id",
		"resource_id":     "id",
		"resource_name":   "audience|client_id|user_id|id",
		"resource_type":   "grant",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"scope":           "scope",
		"source_event_id": "id",
		"subject_id":      "user_id",
		"subject_type":    "user",
		"user_id":         "user_id",
	})
}

func userRoleAttributes() map[string]string {
	return mergeAttributes(identityGroupAttributes(), map[string]string{
		"group_id":        "id",
		"group_name":      "name",
		"member_user_id":  "user_id",
		"role":            "name|id",
		"source_event_id": "id|name",
	})
}

func authenticationMethodAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"credential_id":   "id",
		"credential_type": "type|name",
		"friendly_name":   "name|type",
		"last_used_at":    "last_auth_at|updated_at",
		"owner_user_id":   "user_id",
		"resource_id":     "id",
		"resource_name":   "name|type|id",
		"resource_type":   "authentication_method",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "id",
		"status":          "confirmed|active",
		"user_id":         "user_id",
	})
}

func guardianFactorAttributes() map[string]string {
	return mergeAttributes(commonRuntimeAttributes(), map[string]string{
		"credential_id":   "name|id",
		"credential_name": "name",
		"credential_type": "name|type",
		"enabled":         "enabled",
		"resource_id":     "name|id",
		"resource_name":   "name",
		"resource_type":   "guardian_factor",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "name|id",
		"status":          "enabled",
		"trial_expired":   "trial_expired",
	})
}

func mergeAttributes(base map[string]string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}
