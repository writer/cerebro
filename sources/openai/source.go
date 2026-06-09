package openai

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

const sourceID = "openai"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.openai.com/v1",
		DefaultFamily:   "user",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{Name: "user", Path: "/organization/users", URNKind: "openai_user", IDKeys: []string{"id"}, TimestampKeys: []string{"added_at"}, Attributes: map[string]string{"user_id": "id", "name": "name", "email": "email", "role": "role", "added_at": "added_at"}, StaticAttributes: map[string]string{"source_product": "openai"}},
			{Name: "project", Path: "/organization/projects", URNKind: "openai_project", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at"}, Attributes: map[string]string{"project_id": "id", "name": "name", "status": "status", "created_at": "created_at", "archived_at": "archived_at"}, StaticAttributes: map[string]string{"source_product": "openai"}},
			{Name: "service_account", Path: "/organization/projects/default/service_accounts", URNKind: "openai_service_account", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at"}, Attributes: map[string]string{"service_account_id": "id", "project_id": "project_id", "name": "name", "role": "role", "created_at": "created_at"}, StaticAttributes: map[string]string{"source_product": "openai"}},
			{Name: "api_key", Path: "/organization/projects/default/api_keys", URNKind: "openai_api_key", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at", "last_used_at"}, Attributes: map[string]string{"api_key_id": "id", "project_id": "project_id", "name": "name", "owner_user_id": "owner.user.id", "owner_service_account_id": "owner.service_account.id", "created_at": "created_at", "last_used_at": "last_used_at"}, StaticAttributes: map[string]string{"source_product": "openai"}},
			{Name: "admin_api_key", Path: "/organization/admin_api_keys", URNKind: "openai_admin_api_key", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at", "last_used_at"}, Attributes: map[string]string{"api_key_id": "id", "name": "name", "owner_user_id": "owner.user.id", "owner_service_account_id": "owner.service_account.id", "created_at": "created_at", "last_used_at": "last_used_at"}, StaticAttributes: map[string]string{"source_product": "openai"}},
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
