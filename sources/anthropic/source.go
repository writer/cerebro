package anthropic

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

const sourceID = "anthropic"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.anthropic.com/v1",
		DefaultFamily:   "user",
		RequireTenantID: true,
		TokenHeader:     "x-api-key",
		StaticHeaders:   map[string]string{"anthropic-version": "2023-06-01"},
		Families: []jsonapi.Family{
			{Name: "user", Path: "/organizations/users", URNKind: "anthropic_user", IDKeys: []string{"id"}, TimestampKeys: []string{"added_at"}, Attributes: map[string]string{"user_id": "id", "name": "name", "email": "email", "role": "role", "added_at": "added_at"}, StaticAttributes: map[string]string{"source_product": "anthropic"}},
			{Name: "workspace", Path: "/organizations/workspaces", URNKind: "anthropic_workspace", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at", "archived_at"}, Attributes: map[string]string{"workspace_id": "id", "name": "name", "display_color": "display_color", "created_at": "created_at", "archived_at": "archived_at"}, StaticAttributes: map[string]string{"source_product": "anthropic"}},
			{Name: "api_key", Path: "/organizations/api_keys", URNKind: "anthropic_api_key", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at"}, Attributes: map[string]string{"api_key_id": "id", "name": "name", "status": "status", "workspace_id": "workspace_id|workspace.id", "owner_user_id": "created_by.id|owner.id", "created_at": "created_at"}, StaticAttributes: map[string]string{"source_product": "anthropic"}},
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
