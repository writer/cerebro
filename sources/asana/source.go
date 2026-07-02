package asana

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
	sourceID               = "asana"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/users/me"
	defaultBaseURLTemplate = "https://app.asana.com/api/1.0"
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyProjects         = "projects"
	familyAuditEvents      = "audit_events"
	workspaceGIDConfig     = "workspace_gid"
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
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/users",
				URNKind:          "runtime_users",
				IDKeys:           []string{"gid", "id", "user_id", "email", "primary_email", "login"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"next_page.offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "name|display_name|profile.name|profile.display_name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "resource_id": "resource_id|gid|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|gid|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|gid|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "asana"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"workspace": "workspace_gid"}, ConfigAttributes: map[string]string{"workspace_gid": "workspace_gid"}},
			},
			{
				Name:             familyProjects,
				Path:             "/projects",
				URNKind:          "runtime_projects",
				IDKeys:           []string{"gid", "id", "urn", "resource_urn", "name"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"next_page.offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "modified_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"archived": "archived", "created_at": "created_at", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "modified_at": "modified_at", "observed_at": "observed_at|modified_at|updated_at|last_seen_at", "resource_id": "resource_id|gid|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|gid|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "workspace_gid": "workspace.gid|workspace_gid"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "projects", "source_system": "asana"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"workspace": "workspace_gid"}, ConfigAttributes: map[string]string{"workspace_gid": "workspace_gid"}, ResourceURNKind: "runtime_projects"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/workspaces/{workspace_gid}/audit_log_events",
				PathParams:       []string{"workspace_gid"},
				URNKind:          "runtime_audit_events",
				IDKeys:           []string{"gid", "id", "event_id", "uuid", "request_id"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"next_page.offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.gid|actor.id|actorId|user_id|user.gid|user.id", "actor_name": "actor_name|actor.name|user.name", "created_at": "created_at", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|created_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|resource.gid|target_gid|target_id|target.gid|target.id|resource.id|object_id", "resource_name": "resource_name|resource.name|target_name|target.name|object_name", "resource_type": "resource_type|resource.resource_type|resource.type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|gid|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "workspace_gid": "workspace_gid"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "asana"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"workspace_gid": "workspace_gid"}},
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
