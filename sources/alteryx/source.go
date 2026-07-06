package alteryx

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
	sourceID               = "alteryx"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/v3/users"
	defaultBaseURLTemplate = "${config.base_url}/webapi"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyUserGroups       = "usergroups"
	familyWorkflows        = "workflows"
	familyCollections      = "collections"
	familyAuditEvents      = "audit_events"
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
				Path:             "/v3/users",
				URNKind:          "alteryx_users",
				IDKeys:           []string{"id", "email", "user_id"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateCreated", "dateUpdated", "updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "dateCreated|created_at", "display_name": "name|fullName|firstName+lastName|email", "email": "email", "first_name": "firstName", "last_name": "lastName", "last_login_at": "lastLoginDate|last_login_at", "login": "email", "observed_at": "dateUpdated|dateCreated|updated_at|created_at", "resource_id": "id", "resource_name": "name|email|firstName+lastName", "resource_type": "user", "source_event_id": "id", "status": "isActive|status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "alteryx"},
			},
			{
				Name:             familyUserGroups,
				Path:             "/v3/usergroups",
				URNKind:          "alteryx_usergroups",
				IDKeys:           []string{"id", "name"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateCreated", "dateUpdated", "updated_at", "created_at"},
				Attributes:       map[string]string{"description": "description", "group_id": "id", "group_name": "name", "name": "name", "observed_at": "dateUpdated|dateCreated|updated_at|created_at", "resource_id": "id", "resource_name": "name", "resource_type": "usergroup", "role": "role", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "usergroups", "source_system": "alteryx"},
			},
			{
				Name:             familyWorkflows,
				Path:             "/v3/workflows",
				URNKind:          "alteryx_workflows",
				IDKeys:           []string{"id", "sourceAppId", "name"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateCreated", "uploadDate", "updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "dateCreated", "execution_mode": "executionMode", "id": "id", "is_public": "isPublic", "name": "name", "observed_at": "dateCreated|uploadDate|updated_at|created_at", "owner_id": "ownerId", "resource_id": "id", "resource_name": "name", "resource_type": "workflow", "source_app_id": "sourceAppId", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id", "worker_tag": "workerTag"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "workflows", "source_system": "alteryx"},
			},
			{
				Name:             familyCollections,
				Path:             "/v3/collections",
				URNKind:          "alteryx_collections",
				IDKeys:           []string{"id", "collectionId", "name"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateAdded", "dateCreated", "updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "dateAdded|dateCreated", "id": "id|collectionId", "name": "name", "observed_at": "dateAdded|dateCreated|updated_at|created_at", "owner_id": "ownerId", "resource_id": "id|collectionId", "resource_name": "name", "resource_type": "collection", "source_event_id": "id|collectionId", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "collections", "source_system": "alteryx"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/admin/v1/auditlog",
				URNKind:          "alteryx_audit_events",
				IDKeys:           []string{"id"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"timestamp", "observed_at", "created_at"},
				Attributes:       map[string]string{"actor_id": "userId", "event_type": "event", "id": "id", "observed_at": "timestamp", "resource_id": "entityId", "resource_name": "entity", "resource_type": "entity", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "alteryx"},
				Config:           jsonapi.FamilyConfig{StaticQuery: map[string]string{"entity": "User", "page": "1", "pageSize": "100"}},
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
