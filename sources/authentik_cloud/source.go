package authentik_cloud

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
	sourceID               = "authentik_cloud"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/api/v3/core/users/me/"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyGroups           = "groups"
	familyRoles            = "roles"
	familyApplications     = "applications"
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
				Path:             "/api/v3/core/users/",
				URNKind:          "authentik_cloud_users",
				IDKeys:           []string{"pk", "uuid", "uid", "username", "email"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"pagination.next", "next"},
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"last_updated", "last_login", "date_joined", "observed_at", "updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "date_joined|created_at|created|profile.created_at", "department": "attributes.department|department|profile.department", "display_name": "name|username", "domain": "path|domain|tenant_domain|organization_domain", "email": "email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "attributes.title|attributes.job_title|job_title|title|profile.title", "last_login_at": "last_login|last_login_at|last_seen_at", "login": "username|email|login|profile.login", "manager": "attributes.manager|manager|profile.manager", "observed_at": "last_updated|observed_at|updated_at|last_seen_at", "primary_email": "email|primary_email|profile.email", "resource_id": "pk|uuid|uid|id|metadata.resource_id", "resource_name": "name|username|display_name|hostname|metadata.resource_name", "resource_type": "type|resource_type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|pk|uuid|uid|id|metadata.event_id", "status": "is_active|status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "pk|uuid|uid|username|id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "authentik_cloud"},
			},
			{
				Name:             familyGroups,
				Path:             "/api/v3/core/groups/",
				URNKind:          "authentik_cloud_groups",
				IDKeys:           []string{"pk", "num_pk", "name", "group_id", "group_email", "email"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"pagination.next", "next"},
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "attributes.description|description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "pk|num_pk|id", "group_name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "pk|num_pk|resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|pk|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "authentik_cloud"},
			},
			{
				Name:             familyRoles,
				Path:             "/api/v3/rbac/roles/",
				URNKind:          "authentik_cloud_roles",
				IDKeys:           []string{"pk", "name", "policy_id", "key", "control_id"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"pagination.next", "next"},
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "policy_created_at": "created_at|created|date_created", "policy_description": "description|summary|body", "policy_id": "pk|id", "policy_name": "name", "policy_severity": "severity|risk|priority", "policy_status": "status", "policy_type": "role", "resource_id": "pk|resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|pk|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "roles", "source_system": "authentik_cloud"},
			},
			{
				Name:             familyApplications,
				Path:             "/api/v3/core/applications/",
				URNKind:          "authentik_cloud_applications",
				IDKeys:           []string{"pk", "slug", "name", "urn", "resource_urn"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"pagination.next", "next"},
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "pk|id", "name": "name|slug", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "pk|slug|id", "resource_name": "name|slug", "resource_type": "application", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|pk|slug|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "applications", "source_system": "authentik_cloud"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/api/v3/events/events/",
				URNKind:          "authentik_cloud_audit_events",
				IDKeys:           []string{"pk", "event_id", "uuid", "request_id"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"pagination.next", "next"},
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"created", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "user.email|actor_email", "actor_id": "user.pk|user.uid|user.username|actor_id", "actor_name": "user.name|user.username|actor_name|actor.name", "event_type": "action|event_type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "pk|id", "observed_at": "created|observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "context.model.pk|context.model_pk|resource_id", "resource_name": "context.name|context.model.name|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "context.model_name|context.model.model_name|resource_type|app", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|pk|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "authentik_cloud"},
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
