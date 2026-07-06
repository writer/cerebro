package airfocus

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "airfocus"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/api/team"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyWorkspaces       = "workspaces"
	familyWorkspaceGroups  = "workspace_groups"
	familyLinkTypes        = "link_types"
	familyAPIKeys          = "api_keys"
)

var templateKeys = []string{"base_url", "token"}

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
			airfocusUsersFamily(),
			airfocusSearchAssetFamily(familyWorkspaces, "/api/workspaces/search", "airfocus_workspaces", "workspace", workspaceAttributes()),
			airfocusSearchAssetFamily(familyWorkspaceGroups, "/api/workspaces/groups/search", "airfocus_workspace_groups", "workspace_group", workspaceGroupAttributes()),
			airfocusSearchAssetFamily(familyLinkTypes, "/api/link-types/search", "airfocus_link_types", "link_type", linkTypeAttributes()),
			airfocusAPIKeysFamily(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func airfocusUsersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:          familyUsers,
		Path:          "/api/team/users",
		URNKind:       "airfocus_users",
		IDKeys:        []string{"id", "email", "fullName"},
		ListKeys:      []string{"items"},
		TimestampKeys: []string{"updatedAt", "createdAt", "lastSeenAt"},
		Attributes: map[string]string{
			"created_at":      "createdAt",
			"display_name":    "fullName|name|email",
			"email":           "email",
			"last_login_at":   "lastSeenAt",
			"login":           "email",
			"observed_at":     "updatedAt|lastSeenAt|createdAt",
			"primary_email":   "email",
			"resource_id":     "id",
			"resource_name":   "fullName|email",
			"resource_type":   "user",
			"role":            "role",
			"source_event_id": "id",
			"status":          "disabled",
			"tenant_id":       "tenant_id|metadata.tenant_id",
			"user_id":         "id",
		},
		StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "airfocus"},
	}
}

func airfocusSearchAssetFamily(name, path, urnKind, resourceType string, attrs map[string]string) jsonapi.Family {
	attrs["resource_type"] = resourceType
	return jsonapi.Family{
		Name:           name,
		Path:           path,
		URNKind:        urnKind,
		IDKeys:         []string{"id", "alias", "name", "title"},
		CursorParam:    "offset",
		PageSizeParams: []string{"limit"},
		ListKeys:       []string{"items"},
		TimestampKeys:  []string{"updatedAt", "createdAt"},
		Attributes:     attrs,
		StaticAttributes: map[string]string{
			"record_class":  "asset",
			"resource_type": resourceType,
			"schema":        name,
			"source_system": "airfocus",
		},
		Config: jsonapi.FamilyConfig{
			Method:          http.MethodPost,
			OffsetCursor:    true,
			DefaultPageSize: 100,
			ResourceURNKind: urnKind,
		},
	}
}

func airfocusAPIKeysFamily() jsonapi.Family {
	attrs := assetAttributes()
	attrs["api_key_user_id"] = "userId"
	attrs["api_key_scopes"] = "scopes"
	attrs["last_used_at"] = "lastUsedAt"
	attrs["resource_type"] = "api_key"
	return jsonapi.Family{
		Name:          familyAPIKeys,
		Path:          "/api/profile/api-keys",
		URNKind:       "airfocus_api_keys",
		IDKeys:        []string{"id", "name"},
		ListKeys:      []string{"items"},
		TimestampKeys: []string{"lastUsedAt", "createdAt"},
		Attributes:    attrs,
		StaticAttributes: map[string]string{
			"record_class":  "asset",
			"resource_type": "api_key",
			"schema":        "api_keys",
			"source_system": "airfocus",
		},
		Config: jsonapi.FamilyConfig{ResourceURNKind: "airfocus_api_keys"},
	}
}

func workspaceAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["alias"] = "alias"
	attrs["description"] = "description.markdown|description"
	attrs["workspace_id"] = "id"
	return attrs
}

func workspaceGroupAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["workspace_group_id"] = "id"
	return attrs
}

func linkTypeAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["inward_name"] = "inwardName"
	attrs["outward_name"] = "outwardName"
	return attrs
}

func assetAttributes() map[string]string {
	return map[string]string{
		"created_at":      "createdAt",
		"id":              "id",
		"name":            "name|title|alias|id",
		"observed_at":     "updatedAt|createdAt|lastUsedAt",
		"resource_id":     "id",
		"resource_name":   "name|title|alias|id",
		"source_event_id": "id",
		"tenant_id":       "tenant_id|metadata.tenant_id",
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
