package activtrak

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
	sourceID               = "activtrak"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/scim/v1/ping"
	defaultBaseURLTemplate = "https://api.activtrak.com"
	tokenHeader            = "x-api-key"
	tokenScheme            = ""
	familyUsers            = "users"
	familyGroups           = "groups"
	familyClients          = "clients"
	familyConsumers        = "consumers"
	familyActivityLog      = "activity_log"
)

var templateKeys = []string{"base_url", "api_key", "token"}

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
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/scim/v1/users",
				URNKind:          "activtrak_users",
				IDKeys:           []string{"id", "userName", "emails.0.value"},
				CursorParam:      "startIndex",
				PageSizeParams:   []string{"count"},
				PageFirstCursor:  "1",
				ListKeys:         []string{"resources", "Resources"},
				TimestampKeys:    []string{"meta.lastModified", "meta.created"},
				Attributes:       map[string]string{"created_at": "meta.created", "display_name": "displayName|userName", "email": "emails.0.value|userName", "last_login_at": "meta.lastModified", "login": "userName|emails.0.value", "observed_at": "meta.lastModified|meta.created", "primary_email": "emails.0.value|userName", "resource_id": "id", "resource_name": "displayName|userName", "resource_type": "activtrak_user", "source_event_id": "id", "status": "active", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "activtrak"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"totalResults"},
					LimitKeys:       []string{"itemsPerPage"},
					OffsetKeys:      []string{"startIndex"},
					StaticHeaders:   map[string]string{"Content-Type": "application/scim+json"},
				},
			},
			{
				Name:             familyGroups,
				Path:             "/scim/v1/groups",
				URNKind:          "activtrak_groups",
				IDKeys:           []string{"id", "displayName"},
				CursorParam:      "startIndex",
				PageSizeParams:   []string{"count"},
				PageFirstCursor:  "1",
				ListKeys:         []string{"resources", "Resources"},
				TimestampKeys:    []string{"meta.lastModified", "meta.created"},
				Attributes:       map[string]string{"id": "id", "name": "displayName", "observed_at": "meta.lastModified|meta.created", "resource_id": "id", "resource_name": "displayName", "resource_type": "activtrak_group", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "activtrak_group", "schema": "groups", "source_system": "activtrak"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"totalResults"},
					LimitKeys:       []string{"itemsPerPage"},
					OffsetKeys:      []string{"startIndex"},
					StaticHeaders:   map[string]string{"Content-Type": "application/scim+json"},
				},
			},
			{
				Name:                  familyClients,
				Path:                  "/admin/v1/clients",
				URNKind:               "activtrak_clients",
				IDKeys:                []string{"id", "name", "alias"},
				ListKeys:              []string{"clients"},
				TimestampKeys:         []string{"observed_at", "updated_at", "created_at"},
				Attributes:            map[string]string{"domain": "domain", "id": "id", "name": "alias|name", "observed_at": "observed_at|updated_at|created_at", "resource_id": "id", "resource_name": "alias|name", "resource_type": "activtrak_client", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes:      map[string]string{"record_class": "asset", "resource_type": "activtrak_client", "schema": "clients", "source_system": "activtrak"},
				AllowBareDetailRecord: true,
			},
			{
				Name:             familyConsumers,
				Path:             "/admin/v1/consumers",
				URNKind:          "activtrak_consumers",
				IDKeys:           []string{"id", "username", "email"},
				ListKeys:         []string{"consumers"},
				TimestampKeys:    []string{"observed_at", "updated_at", "created_at"},
				Attributes:       map[string]string{"display_name": "firstName+lastName|username", "email": "email|username", "login": "username|email", "observed_at": "observed_at|updated_at|created_at", "primary_email": "email|username", "resource_id": "id", "resource_name": "username|email", "resource_type": "activtrak_consumer", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "consumers", "source_system": "activtrak"},
				Config:           jsonapi.FamilyConfig{StaticQuery: map[string]string{"includeViewableGroups": "true"}},
			},
			{
				Name:             familyActivityLog,
				Path:             "/reports/v2/activitylog",
				URNKind:          "activtrak_activity_log",
				IDKeys:           []string{"logId", "id"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"cursor"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"activity"},
				TimestampKeys:    []string{"time_utc", "time"},
				Attributes:       map[string]string{"actor_email": "user", "actor_id": "clientId|user|computerId", "actor_name": "user", "event_type": "description|executable|website|activity", "id": "logId", "observed_at": "time_utc|time", "resource_id": "computerId|applicationId|websiteId|logId", "resource_name": "computer|titleBar|website|executable", "resource_type": "activity_log", "source_event_id": "logId", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "activity_log", "schema": "activity_log", "source_system": "activtrak"},
				Config: jsonapi.FamilyConfig{
					StaticQuery:     map[string]string{"startDate": "2026-01-01"},
					DefaultPageSize: 150,
				},
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
