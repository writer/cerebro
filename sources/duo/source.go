package duo

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID       = "duo"
	defaultBaseURL = "https://api.duosecurity.com"
	defaultFamily  = "user"
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "duo_hmac",
		Families: []jsonapi.Family{
			{Name: "user", Path: "/admin/v1/users", URNKind: "duo_user", IDKeys: []string{"user_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created", "last_login"}, Attributes: map[string]string{"user_id": "user_id", "username": "username", "email": "email", "realname": "realname", "status": "status", "last_login_at": "last_login", "is_enrolled": "is_enrolled", "lockout_reason": "lockout_reason", "last_directory_sync": "last_directory_sync"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "group", Path: "/admin/v1/groups", URNKind: "duo_group", IDKeys: []string{"group_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created"}, Attributes: map[string]string{"group_id": "group_id", "name": "name", "description": "desc|description", "status": "status"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "administrator", Path: "/admin/v1/admins", URNKind: "duo_administrator", IDKeys: []string{"admin_id", "email", "name"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created", "last_login"}, Attributes: map[string]string{"admin_id": "admin_id", "user_id": "admin_id", "name": "name", "email": "email", "status": "status", "role": "role", "last_login_at": "last_login", "created_at": "created"}, StaticAttributes: map[string]string{"source_product": "duo", "resource_type": "administrator"}},
			{Name: "endpoint", Path: "/admin/v1/endpoints", URNKind: "duo_endpoint", IDKeys: []string{"endpoint_id", "epkey"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"endpoint_id": "endpoint_id|epkey", "hostname": "hostname", "os": "os", "os_version": "os_version", "browser": "browser", "disk_encryption_status": "disk_encryption_status", "last_seen_at": "last_seen"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "phone", Path: "/admin/v1/phones", URNKind: "duo_phone", IDKeys: []string{"phone_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"phone_id": "phone_id", "name": "name", "number": "number", "platform": "platform", "model": "model", "capabilities": "capabilities", "activated": "activated", "encrypted": "encrypted", "screenlock": "screenlock", "tampered": "tampered", "last_seen_at": "last_seen", "user_id": "user_id"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "token", Path: "/admin/v1/tokens", URNKind: "duo_token", IDKeys: []string{"token_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"token_id": "token_id", "serial": "serial", "type": "type", "totp_step": "totp_step", "last_seen_at": "last_seen", "user_id": "user_id"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{
				Name:          "web_authn_credential", // #nosec G101 - Duo uses credential as an inventory object name, not a secret.
				Path:          "/admin/v1/webauthncredentials",
				URNKind:       "duo_web_authn_credential",
				IDKeys:        []string{"credential_id", "webauthnkey"},
				ListKeys:      []string{"response"},
				TimestampKeys: []string{"created", "last_used"},
				Attributes:    map[string]string{"credential_id": "credential_id|webauthnkey", "label": "label", "credential_name": "credential_name|name", "user_id": "user_id", "last_used_at": "last_used"}, // #nosec G101 - field names, not credentials.
				StaticAttributes: map[string]string{
					"source_product": "duo",
				},
			},
			{Name: "role", Path: "/admin/v1/admin_roles", URNKind: "duo_role", IDKeys: []string{"role_id", "name"}, ListKeys: []string{"response"}, Attributes: map[string]string{"policy_id": "role_id|name", "policy_name": "name", "description": "desc|description"}, StaticAttributes: map[string]string{"source_product": "duo", "resource_type": "administrator_role", "policy_type": "administrator_role"}},
			{Name: "application", Path: "/admin/v3/integrations", FamilyRequest: jsonapi.FamilyRequest{AuthModel: "duo_hmac_v5"}, URNKind: "duo_application", IDKeys: []string{"integration_key", "ikey", "key"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created"}, Attributes: map[string]string{"resource_id": "integration_key|ikey|key", "resource_name": "name", "resource_type": "type|integration_type", "integration_key": "integration_key|ikey|key", "name": "name", "type": "type|integration_type"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "audit_event", Path: "/admin/v2/logs/activity", URNKind: "duo_audit_event", IDKeys: []string{"activity_id", "txid", "id"}, CursorParam: "next_offset", NextCursorKeys: []string{"response.metadata.next_offset"}, ListKeys: []string{"response.items"}, TimestampKeys: []string{"ts", "timestamp"}, Config: jsonapi.FamilyConfig{ConfigQuery: map[string]string{"mintime": "mintime", "maxtime": "maxtime", "sort": "sort"}, RepeatedCursorParam: true}, Attributes: map[string]string{"event_type": "action|eventtype|event_type", "actor_id": "actor.key|actor_id", "actor_name": "actor.name|actor_name", "actor_type": "actor.type|actor_type", "resource_id": "target.key|application.key|resource_id", "resource_name": "target.name|application.name|resource_name", "resource_type": "target.type|application.type|resource_type"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "authentication_log", Path: "/admin/v2/logs/authentication", URNKind: "duo_authentication_log", IDKeys: []string{"txid", "id", "timestamp"}, CursorParam: "next_offset", NextCursorKeys: []string{"response.metadata.next_offset"}, ListKeys: []string{"response.authlogs"}, TimestampKeys: []string{"isotimestamp", "timestamp"}, Config: jsonapi.FamilyConfig{ConfigQuery: map[string]string{"mintime": "mintime", "maxtime": "maxtime", "sort": "sort"}, RepeatedCursorParam: true}, Attributes: map[string]string{"event_type": "event_type|eventtype", "actor_id": "user.key|user_id", "actor_name": "user.name|username", "resource_id": "application.key|integration_key", "resource_name": "application.name|integration", "resource_type": "application.type|application", "factor": "factor", "result": "result", "reason": "reason"}, StaticAttributes: map[string]string{"source_product": "duo"}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, normalizeBaseURLConfig(cfg))
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, normalizeBaseURLConfig(cfg))
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, normalizeBaseURLConfig(cfg), cursor)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func normalizeBaseURLConfig(cfg sourcecdk.Config) sourcecdk.Config {
	values := cfg.Values()
	baseURL := strings.TrimRight(strings.TrimSpace(values["base_url"]), "/")
	if strings.HasSuffix(baseURL, "/admin/v1") {
		values["base_url"] = strings.TrimSuffix(baseURL, "/admin/v1")
	}
	return sourcecdk.NewConfig(values)
}
