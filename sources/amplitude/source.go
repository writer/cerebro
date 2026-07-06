package amplitude

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
	sourceID               = "amplitude"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/scim/1/Users"
	defaultBaseURLTemplate = "https://core.amplitude.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyGroups           = "groups"
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
			{
				Name:             familyUsers,
				Path:             "/scim/1/Users",
				URNKind:          "amplitude_users",
				IDKeys:           []string{"id", "userName", "emails.0.value"},
				CursorParam:      "startIndex",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"itemsPerPage"},
				ListKeys:         []string{"Resources"},
				TimestampKeys:    []string{"meta.lastModified", "meta.created"},
				Attributes:       map[string]string{"active": "active", "created_at": "meta.created", "display_name": "displayName|name.formatted|userName", "email": "emails.0.value|userName|id", "first_name": "name.givenName", "last_name": "name.familyName", "login": "userName|emails.0.value|id", "observed_at": "meta.lastModified|meta.created", "primary_email": "emails.0.value|userName|id", "resource_id": "id|userName", "resource_name": "displayName|userName|emails.0.value", "resource_type": "amplitude_scim_user", "source_event_id": "id|userName", "status": "active", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id|userName"},
				Config:           jsonapi.FamilyConfig{OffsetCursor: true, OffsetKeys: []string{"startIndex"}, LimitKeys: []string{"itemsPerPage"}, TotalKeys: []string{"totalResults"}, DefaultPageSize: 100},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "amplitude"},
			},
			{
				Name:             familyGroups,
				Path:             "/scim/1/Groups",
				URNKind:          "amplitude_groups",
				IDKeys:           []string{"id", "displayName"},
				CursorParam:      "startIndex",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"itemsPerPage"},
				ListKeys:         []string{"Resources"},
				TimestampKeys:    []string{"meta.lastModified", "meta.created"},
				Attributes:       map[string]string{"created_at": "meta.created", "group_id": "id", "group_name": "displayName", "member_count": "members.#", "observed_at": "meta.lastModified|meta.created", "resource_id": "id", "resource_name": "displayName", "resource_type": "amplitude_scim_group", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				Config:           jsonapi.FamilyConfig{OffsetCursor: true, OffsetKeys: []string{"startIndex"}, LimitKeys: []string{"itemsPerPage"}, TotalKeys: []string{"totalResults"}, DefaultPageSize: 100},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "amplitude"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
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
