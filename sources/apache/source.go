package apache

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
	sourceID               = "apache"
	defaultFamily          = familyEventlog
	defaultHealthPath      = "/eventLogs"
	defaultBaseURLTemplate = ""
	familyEventlog         = "eventlog"
	familyRole             = "role"
	familyUser             = "user"
	familyPermission       = "permission"
)

var templateKeys = []string{"password", "username"}

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
		AuthModel:       "basic",
		Families: []jsonapi.Family{
			{
				Name:             familyEventlog,
				Path:             "/eventLogs",
				URNKind:          "apache_eventlog",
				IDKeys:           []string{"event_log_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"event_logs"},
				TimestampKeys:    []string{"when"},
				Attributes:       map[string]string{"actor_id": "owner", "actor_name": "owner", "event_type": "event", "id": "event_log_id", "name": "event", "observed_at": "when", "provider_id": "event_log_id", "resource_id": "dag_id|task_id|run_id", "resource_name": "dag_id|task_id|run_id", "resource_type": "event", "source_event_id": "event_log_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "eventlog", "source_system": "apache"},
			},
			{
				Name:             familyRole,
				Path:             "/roles",
				URNKind:          "apache_role",
				IDKeys:           []string{"name", "group_id", "id", "group_email", "email"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"roles"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"group_id": "name", "group_name": "name", "id": "name", "name": "name", "provider_id": "name", "resource_id": "name", "resource_name": "name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "role", "source_system": "apache"},
			},
			{
				Name:             familyUser,
				Path:             "/users",
				URNKind:          "apache_user",
				IDKeys:           []string{"email", "username", "user_id", "id", "primary_email", "login"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"users"},
				TimestampKeys:    []string{"changed_on", "created_on", "last_login"},
				Attributes:       map[string]string{"created_at": "created_on", "display_name": "username|email|first_name", "email": "email", "id": "username", "last_login_at": "last_login", "login": "username", "name": "username", "primary_email": "email", "provider_id": "username", "resource_id": "username", "resource_name": "username|email", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "username", "status": "active", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "username"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "user", "source_system": "apache"},
			},
			{
				Name:             familyPermission,
				Path:             "/permissions",
				URNKind:          "apache_permission",
				IDKeys:           []string{"name", "id", "urn", "resource_urn"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"actions"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"id": "name", "name": "name", "provider_id": "name", "resource_id": "name", "resource_name": "name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "permission", "schema": "permission", "source_system": "apache"},
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
