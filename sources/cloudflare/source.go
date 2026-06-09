package cloudflare

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "cloudflare"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.cloudflare.com/client/v4",
		DefaultFamily:   "account",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{Name: "account", Path: "/accounts", URNKind: "cloudflare_account", IDKeys: []string{"id"}, Attributes: map[string]string{"account_id": "id", "name": "name", "type": "type"}, StaticAttributes: map[string]string{"source_product": "cloudflare"}},
			{Name: "member", Path: "/accounts/default/members", URNKind: "cloudflare_member", IDKeys: []string{"id"}, TimestampKeys: []string{"created_on", "modified_on"}, Attributes: map[string]string{"member_id": "id", "account_id": "account.id|account_id", "email": "user.email|email", "status": "status", "roles": "roles"}, StaticAttributes: map[string]string{"source_product": "cloudflare"}},
			{Name: "role", Path: "/accounts/default/roles", URNKind: "cloudflare_role", IDKeys: []string{"id"}, Attributes: map[string]string{"role_id": "id", "name": "name", "description": "description", "permissions": "permissions"}, StaticAttributes: map[string]string{"source_product": "cloudflare"}},
			{Name: "zone", Path: "/zones", URNKind: "cloudflare_zone", IDKeys: []string{"id"}, TimestampKeys: []string{"created_on", "modified_on"}, Attributes: map[string]string{"zone_id": "id", "account_id": "account.id|account_id", "name": "name", "status": "status", "type": "type", "paused": "paused"}, StaticAttributes: map[string]string{"source_product": "cloudflare"}},
			{Name: "dns_record", Path: "/zones/default/dns_records", URNKind: "cloudflare_dns_record", IDKeys: []string{"id"}, TimestampKeys: []string{"created_on", "modified_on"}, Attributes: map[string]string{"record_id": "id", "zone_id": "zone_id", "name": "name", "type": "type", "content": "content", "proxied": "proxied"}, StaticAttributes: map[string]string{"source_product": "cloudflare"}},
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
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}
