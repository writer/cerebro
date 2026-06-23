package duo

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID       = "duo"
	defaultBaseURL = "https://api.duosecurity.com/admin/v1"
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
			{Name: "user", Path: "/users", URNKind: "duo_user", IDKeys: []string{"user_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created", "last_login"}, Attributes: map[string]string{"user_id": "user_id", "username": "username", "email": "email", "realname": "realname", "status": "status", "last_login_at": "last_login", "is_enrolled": "is_enrolled", "lockout_reason": "lockout_reason", "last_directory_sync": "last_directory_sync"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "group", Path: "/groups", URNKind: "duo_group", IDKeys: []string{"group_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"created"}, Attributes: map[string]string{"group_id": "group_id", "name": "name", "description": "desc|description", "status": "status"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "endpoint", Path: "/endpoints", URNKind: "duo_endpoint", IDKeys: []string{"endpoint_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"endpoint_id": "endpoint_id", "hostname": "hostname", "os": "os", "os_version": "os_version", "browser": "browser", "disk_encryption_status": "disk_encryption_status", "last_seen_at": "last_seen"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "phone", Path: "/phones", URNKind: "duo_phone", IDKeys: []string{"phone_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"phone_id": "phone_id", "name": "name", "number": "number", "platform": "platform", "model": "model", "capabilities": "capabilities", "activated": "activated", "encrypted": "encrypted", "screenlock": "screenlock", "tampered": "tampered", "last_seen_at": "last_seen"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{Name: "token", Path: "/tokens", URNKind: "duo_token", IDKeys: []string{"token_id"}, ListKeys: []string{"response"}, TimestampKeys: []string{"last_seen", "created"}, Attributes: map[string]string{"token_id": "token_id", "serial": "serial", "type": "type", "totp_step": "totp_step", "last_seen_at": "last_seen"}, StaticAttributes: map[string]string{"source_product": "duo"}},
			{
				Name:          "web_authn_credential", // #nosec G101 - Duo uses credential as an inventory object name, not a secret.
				Path:          "/webauthncredentials",
				URNKind:       "duo_web_authn_credential",
				IDKeys:        []string{"credential_id"},
				ListKeys:      []string{"response"},
				TimestampKeys: []string{"created", "last_used"},
				Attributes:    map[string]string{"credential_id": "credential_id", "label": "label", "credential_name": "credential_name", "user_id": "user_id", "last_used_at": "last_used"}, // #nosec G101 - field names, not credentials.
				StaticAttributes: map[string]string{
					"source_product": "duo",
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
