package bugsnag

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "bugsnag"
	defaultFamily          = familyProjects
	defaultBaseURLTemplate = "https://api.bugsnag.com"
	tokenHeader            = ""
	tokenScheme            = "Token"
	familyProjects         = "projects"
	familyErrors           = "errors"
	familyAuditEvents      = "audit_events"
)

var templateKeys = []string{"api_key"}

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
				Name:             familyProjects,
				Path:             "/organizations/${config.organization_id}/projects",
				URNKind:          "bugsnag_projects",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				Config:           bugsnagRequestConfig("bugsnag_projects"),
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "projects", "source_system": "bugsnag"},
			},
			{
				Name:             familyErrors,
				Path:             "/projects/${config.project_id}/errors",
				URNKind:          "bugsnag_errors",
				IDKeys:           []string{"id", "finding_id", "resource_urn"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"last_seen", "first_seen", "updated_at", "created_at"},
				Attributes:       map[string]string{"description": "context|message|description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "id", "observed_at": "last_seen|first_seen|updated_at|created_at", "resource_id": "project_id|resource_id|id|metadata.resource_id", "resource_name": "project_id|resource_id|id|metadata.resource_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity|risk|priority", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "error_class|message|title|name|summary"},
				Config:           bugsnagRequestConfig("bugsnag_projects"),
				StaticAttributes: map[string]string{"record_class": "finding", "resource_type": "bugsnag_project", "schema": "errors", "source_system": "bugsnag"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/audit-events",
				URNKind:          "bugsnag_audit_events",
				IDKeys:           []string{"id", "event_id", "uuid", "request_id"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "bugsnag"},
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

func bugsnagRequestConfig(resourceURNKind string) jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{
		ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
		ResourceURNKind:  resourceURNKind,
		StaticHeaders:    map[string]string{"X-Bugsnag-Api": "true", "X-Version": "2"},
	}
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

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
