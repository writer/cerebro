package gitlab

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
	sourceID               = "gitlab"
	defaultFamily          = familyRepositories
	defaultHealthPath      = "/api/v4/user"
	defaultBaseURLTemplate = "https://gitlab.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyRepositories     = "repositories"
	familyUsers            = "users"
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
				Name:                 familyRepositories,
				Path:                 "/api/v4/projects",
				URNKind:              "runtime_repositories",
				IDKeys:               []string{"id", "path_with_namespace", "name"},
				CursorParam:          "page",
				LinkHeader:           "Link",
				PageFirstCursor:      "1",
				PageSizeParams:       []string{"per_page"},
				TimestampKeys:        []string{"last_activity_at", "updated_at", "created_at", "observed_at", "last_seen_at"},
				Attributes:           map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "last_activity_at|updated_at|created_at|observed_at|last_seen_at", "resource_id": "id", "resource_name": "path_with_namespace|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes:     map[string]string{"record_class": "asset", "resource_type": "repository", "schema": "repositories", "source_system": "gitlab"},
				Config:               jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_repositories"},
				IncrementalWatermark: true,
			},
			{
				Name:                 familyUsers,
				Path:                 "/api/v4/users",
				URNKind:              "runtime_users",
				IDKeys:               []string{"id", "username", "email"},
				CursorParam:          "page",
				LinkHeader:           "Link",
				PageFirstCursor:      "1",
				PageSizeParams:       []string{"per_page"},
				TimestampKeys:        []string{"created_at", "last_activity_on", "current_sign_in_at", "observed_at", "updated_at", "last_seen_at"},
				Attributes:           map[string]string{"created_at": "created_at|created|profile.created_at", "department": "organization|department|profile.department", "display_name": "name|display_name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|public_email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "current_sign_in_at|last_activity_on|last_login_at|last_login|last_seen_at", "login": "username|login|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at|created_at", "primary_email": "email|public_email|primary_email|profile.email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|username|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "state|status|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes:     map[string]string{"record_class": "identity_user", "resource_type": "identity_user", "schema": "users", "source_system": "gitlab"},
				Config:               jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_users"},
				IncrementalWatermark: true,
			},
			{
				Name:                 familyAuditEvents,
				Path:                 "/api/v4/audit_events",
				URNKind:              "runtime_audit_events",
				IDKeys:               []string{"id", "event_id", "uuid", "request_id"},
				CursorParam:          "page",
				LinkHeader:           "Link",
				PageFirstCursor:      "1",
				PageSizeParams:       []string{"per_page"},
				TimestampKeys:        []string{"created_at", "observed_at", "updated_at", "last_seen_at"},
				Attributes:           map[string]string{"actor_email": "actor_email|author_email|author.email|email|user.email", "actor_id": "author_id|actor_id|actor.id|actorId|user_id|user.id", "actor_name": "author_name|actor_name|actor.name|user.name", "event_type": "event_type|action|details.custom_message|details.add|details.change|target_type|entity_type|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "created_at|observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "entity_id|target_id|target.id|resource.id|object_id|id", "resource_name": "entity_path|target_details|entity_name|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "entity_type|target_type|target.type|object_type|resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes:     map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "gitlab"},
				IncrementalWatermark: true,
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
