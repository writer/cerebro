package airtable

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
	sourceID               = "airtable"
	defaultFamily          = familyBases
	defaultHealthPath      = "/v0/meta/whoami"
	defaultBaseURLTemplate = "https://api.airtable.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyBases            = "bases"
	familyAuditEvents      = "audit_events"
)

var templateKeys = []string{"token"}

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
				Path:             "/v0/meta/enterpriseAccounts/${config.enterprise_account_id}/users",
				URNKind:          "airtable_users",
				IDKeys:           []string{"id", "user_id", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				DisablePageSize:  true,
				ListKeys:         []string{"users"},
				TimestampKeys:    []string{"lastActivityTime", "createdTime"},
				Attributes:       map[string]string{"created_at": "createdTime", "display_name": "name", "email": "email", "last_login_at": "lastActivityTime", "login": "email", "primary_email": "email", "resource_id": "id", "resource_name": "name", "resource_type": "enterprise_user", "source_event_id": "id", "status": "state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"id[]": "user_id"}},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "airtable"},
			},
			{
				Name:             familyBases,
				Path:             "/v0/meta/bases",
				URNKind:          "airtable_bases",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"offset"},
				DisablePageSize:  true,
				ListKeys:         []string{"bases"},
				Attributes:       map[string]string{"resource_id": "id", "resource_name": "name", "resource_type": "base", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "bases", "source_system": "airtable"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/v0/meta/enterpriseAccounts/${config.enterprise_account_id}/auditLogEvents",
				URNKind:          "airtable_audit_events",
				IDKeys:           []string{"id", "event_id", "uuid", "request_id"},
				CursorParam:      "previous",
				NextCursorKeys:   []string{"pagination.previous"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"events"},
				TimestampKeys:    []string{"timestamp"},
				Attributes:       map[string]string{"actor_email": "actor.user.email", "actor_id": "actor.user.id", "actor_name": "actor.user.name", "event_type": "action", "id": "id", "observed_at": "timestamp", "resource_id": "modelId|context.baseId|context.workspaceId", "resource_name": "payload.name", "resource_type": "modelType", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "airtable"},
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
