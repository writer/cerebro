package hashicorp_vault

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
	sourceID               = "hashicorp_vault"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/v1/sys/health"
	defaultBaseURLTemplate = "https://${config.vault_addr}"
	tokenScheme            = "Bearer"
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
		AuthModel:       "bearer_token",
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/v1/users",
				URNKind:          "runtime_users",
				IDKeys:           []string{"id", "user_id", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "hashicorp_vault"},
			},
			{
				Name:             familySecrets,
				Path:             "/v1/secrets",
				URNKind:          "runtime_secrets",
				IDKeys:           []string{"id", "secret_id", "name", "key", "sid"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "owner_user_id": "owner_id|created_by.id|created_by|user_id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created|date_created", "secret_id": "secret_id|id|key|sid|name", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "secret_name|name|display_name|label|title", "secret_rotation_enabled": "secret_rotation_enabled|rotation_enabled|auto_rotate", "secret_status": "secret_status|status|state", "secret_type": "secret_type|type|kind", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "secrets", "source_system": "hashicorp_vault"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/v1/audit/events",
				URNKind:          "runtime_audit_events",
				IDKeys:           []string{"id", "event_id", "uuid", "request_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "hashicorp_vault"},
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
	values := cfg.Values()
	if strings.TrimSpace(values["base_url"]) == "" && strings.TrimSpace(defaultBaseURLTemplate) != "" {
		baseURL, err := sourcecdk.RenderConfigTemplate(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
		if err != nil {
			return sourcecdk.Config{}, err
		}
		values["base_url"] = baseURL
	}
	return sourcecdk.NewConfig(values), nil
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(configValue(cfg, "health_path"), defaultHealthPath)
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
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
