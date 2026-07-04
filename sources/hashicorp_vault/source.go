package hashicorp_vault

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "hashicorp_vault"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/v1/sys/health"
	defaultBaseURLTemplate = "https://${config.vault_addr}"
	familyUsers            = "users"
	familySecrets          = "secrets"
	familyAuditEvents      = "audit_events"
)

var templateKeys = []string{"vault_addr", "token"}

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
		TokenHeader:     "X-Vault-Token",
		Families: []jsonapi.Family{
			{
				Name:            familyUsers,
				Path:            "/v1/identity/entity/id",
				URNKind:         "runtime_users",
				IDKeys:          []string{"id", "entity.id", "entity.name", "name"},
				DisablePageSize: true,
				MapRecords:      map[string]string{"data.key_info": "entity"},
				Config: jsonapi.FamilyConfig{
					StaticQuery:      map[string]string{"list": "true"},
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
				},
				TimestampKeys: []string{"entity.last_update_time", "entity.creation_time"},
				Attributes: map[string]string{
					"created_at":      "entity.creation_time",
					"display_name":    "entity.name|name",
					"email":           "entity.metadata.email",
					"login":           "entity.metadata.login|entity.name",
					"observed_at":     "entity.last_update_time|entity.creation_time",
					"primary_email":   "entity.metadata.email",
					"resource_id":     "id",
					"resource_name":   "entity.name|name",
					"resource_type":   "resource_type",
					"source_event_id": "id",
					"status":          "entity.metadata.status",
					"user_id":         "id",
				},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "vault_identity_entity", "schema": "users", "source_system": "hashicorp_vault"},
			},
			{
				Name:            familySecrets,
				Path:            "/v1/sys/mounts",
				URNKind:         "runtime_secrets",
				IDKeys:          []string{"id", "name", "mount.accessor"},
				DisablePageSize: true,
				MapRecords:      map[string]string{"data": "mount"},
				Config:          jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
				Attributes: map[string]string{
					"resource_id":     "id",
					"resource_name":   "name",
					"resource_type":   "resource_type",
					"secret_id":       "id",
					"secret_name":     "name",
					"secret_status":   "secret_status",
					"secret_type":     "mount.type",
					"source_event_id": "id",
					"vault_id":        "mount.accessor|id",
				},
				StaticAttributes: map[string]string{"record_class": "secret", "resource_type": "vault_secret_engine", "schema": "secrets", "secret_status": "enabled", "source_system": "hashicorp_vault"},
			},
			{
				Name:            familyAuditEvents,
				Path:            "/v1/sys/audit",
				URNKind:         "runtime_audit_events",
				IDKeys:          []string{"id", "name", "audit_device.type"},
				DisablePageSize: true,
				MapRecords:      map[string]string{"data": "audit_device"},
				Config:          jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
				Attributes: map[string]string{
					"resource_id":     "id",
					"resource_name":   "name",
					"resource_type":   "resource_type",
					"source_event_id": "id",
				},
				StaticAttributes: map[string]string{"actor_id": "vault", "event_type": "vault.audit_device.enabled", "record_class": "audit_event", "resource_type": "vault_audit_device", "schema": "audit_events", "source_system": "hashicorp_vault"},
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

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	_ = ctx
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
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
