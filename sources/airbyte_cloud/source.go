package airbyte_cloud

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "airbyte_cloud"
	defaultFamily          = familyOrganizations
	defaultHealthPath      = "/health"
	defaultBaseURLTemplate = "https://api.airbyte.com/v1"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyOrganizations    = "organizations"
	familySources          = "sources"
	familyPermissions      = "permissions"
	familyConnections      = "connections"
)

var templateKeys = []string{"base_url", "token", "organization_id", "workspace_ids", "user_id"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "bearer_token",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/users",
				URNKind:          "airbyte_cloud_users",
				IDKeys:           []string{"id", "email", "name"},
				DisablePageSize:  true,
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				Attributes:       map[string]string{"display_name": "name", "email": "email", "login": "email", "primary_email": "email", "resource_id": "id", "resource_name": "name|email", "resource_type": "airbyte_user", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "airbyte_cloud"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"organizationId": "organization_id"}, ConfigAttributes: map[string]string{"organization_id": "organization_id"}},
			},
			airbyteAssetFamily(familyOrganizations, "/organizations", "airbyte_cloud_organizations", []string{"organizationId", "organizationName", "email"}, "airbyte_organization", map[string]string{"id": "organizationId", "name": "organizationName", "resource_id": "organizationId", "resource_name": "organizationName", "resource_type": "airbyte_organization", "source_event_id": "organizationId", "email": "email"}),
			airbyteAssetFamily(familySources, "/sources", "airbyte_cloud_sources", []string{"sourceId", "name"}, "airbyte_source", map[string]string{"id": "sourceId", "name": "name", "resource_id": "sourceId", "resource_name": "name", "resource_type": "airbyte_source", "source_event_id": "sourceId", "workspace_id": "workspaceId", "source_type": "sourceType", "definition_id": "definitionId"}),
			{
				Name:            familyPermissions,
				Path:            "/permissions",
				URNKind:         "airbyte_cloud_permissions",
				IDKeys:          []string{"permissionId", "userId", "scopeId", "permissionType"},
				DisablePageSize: true,
				PageSizeParams:  []string{"limit"},
				ListKeys:        []string{"data"},
				Attributes: map[string]string{
					"policy_id":       "permissionId",
					"policy_name":     "permissionType",
					"policy_status":   "active",
					"policy_type":     "airbyte_permission",
					"resource_id":     "scopeId",
					"resource_type":   "scope",
					"source_event_id": "permissionId",
					"tenant_id":       "tenant_id|metadata.tenant_id",
					"user_id":         "userId",
				},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "permissions", "source_system": "airbyte_cloud"},
				Config:           airbyteListConfig(),
			},
			airbyteAssetFamily(familyConnections, "/connections", "airbyte_cloud_connections", []string{"connectionId", "name"}, "airbyte_connection", map[string]string{"id": "connectionId", "name": "name", "resource_id": "connectionId", "resource_name": "name", "resource_type": "airbyte_connection", "source_event_id": "connectionId", "source_id": "sourceId", "destination_id": "destinationId", "workspace_id": "workspaceId", "status": "status", "data_residency": "dataResidency"}),
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func airbyteAssetFamily(name, path, urnKind string, idKeys []string, resourceType string, attrs map[string]string) jsonapi.Family {
	family := jsonapi.Family{
		Name:             name,
		Path:             path,
		URNKind:          urnKind,
		IDKeys:           idKeys,
		PageSizeParams:   []string{"limit"},
		ListKeys:         []string{"data"},
		Attributes:       attrs,
		StaticAttributes: map[string]string{"record_class": "asset", "resource_type": resourceType, "schema": name, "source_system": "airbyte_cloud"},
		Config:           airbyteListConfig(),
	}
	if name == familySources || name == familyConnections {
		family.CursorParam = "offset"
		family.PageFirstCursor = "0"
		return family
	}
	family.DisablePageSize = true
	return family
}

func airbyteListConfig() jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{
		ConfigQuery:     map[string]string{"workspaceIds": "workspace_ids"},
		DefaultPageSize: 100,
	}
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
