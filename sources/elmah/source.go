package elmah

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
	sourceID               = "elmah"
	defaultFamily          = familyLog
	defaultHealthPath      = "/v3/logs"
	defaultBaseURLTemplate = "https://${config.api_base_url}"
	tokenHeader            = ""
	tokenScheme            = "Token"
	familyLog              = "log"
	familyDeployment       = "deployment"
	familyUptimecheck      = "uptimecheck"
	familyMessage          = "message"
)

var templateKeys = []string{"api_base_url", "logid", "api_key"}

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
				Name:             familyLog,
				Path:             "/v3/logs",
				URNKind:          "elmah_log",
				IDKeys:           []string{"id", "name", "event_id", "uuid", "request_id"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "log", "source_system": "elmah"},
			},
			{
				Name:             familyDeployment,
				Path:             "/v3/deployments",
				URNKind:          "elmah_deployment",
				IDKeys:           []string{"id", "userName", "deployment_id", "name", "url", "uid"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "created_at|created|date_created", "deployment_environment": "created", "deployment_id": "id", "deployment_name": "userName", "deployment_status": "created", "deployment_updated_at": "updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "userName", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "schema": "deployment", "source_system": "elmah"},
			},
			{
				Name:             familyUptimecheck,
				Path:             "/v3/uptimechecks",
				URNKind:          "elmah_uptimecheck",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name", "resource_type": "uptimecheck", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "uptimecheck", "source_system": "elmah"},
			},
			{
				Name:             familyMessage,
				Path:             "/v3/messages/${config.logid}",
				URNKind:          "elmah_message",
				IDKeys:           []string{"id", "title", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"messages"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "title", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "message", "source_system": "elmah"},
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
