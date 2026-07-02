package cloudflare_workers_ai

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
	sourceID                     = "cloudflare_workers_ai"
	defaultFamily                = familyModelCatalog
	defaultHealthPath            = "/accounts/${config.account_id}/ai/models/search"
	defaultBaseURLTemplate       = "https://api.cloudflare.com/client/v4"
	tokenHeader                  = ""
	tokenScheme                  = "Bearer"
	familyModelCatalog           = "model_catalog"
	familyAiGateways             = "ai_gateways"
	familyGatewayProviderConfigs = "gateway_provider_configs"
	familyGatewayEvaluations     = "gateway_evaluations"
	familyGatewayLogs            = "gateway_logs"
	familyVectorizeIndexes       = "vectorize_indexes"
)

var templateKeys = []string{"account_id", "gateway_id", "token"}

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
				Name:             familyModelCatalog,
				Path:             "/accounts/${config.account_id}/ai/models/search",
				URNKind:          "cloudflare_workers_ai_model_catalog",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "model", "schema": "model_catalog", "source_system": "cloudflare_workers_ai"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					StaticQuery:      map[string]string{"format": "openrouter"},
					EncodeURNID:      true,
					ResourceURNKind:  "cloudflare_workers_ai_model_catalog",
				},
			},
			{
				Name:             familyAiGateways,
				Path:             "/accounts/${config.account_id}/ai-gateway/gateways",
				URNKind:          "cloudflare_workers_ai_ai_gateways",
				IDKeys:           []string{"id", "deployment_id", "name", "url", "uid"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"result"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "created_at|created|date_created", "deployment_environment": "environment|env|stage|target", "deployment_id": "id", "deployment_name": "name", "deployment_status": "status|state|ready", "deployment_updated_at": "updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "resource_type": "ai_gateway", "schema": "ai_gateways", "source_system": "cloudflare_workers_ai"},
				Config:           workersAITenantFamilyConfig("cloudflare_workers_ai_ai_gateways"),
			},
			{
				Name:             familyGatewayProviderConfigs,
				Path:             "/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/provider_configs",
				URNKind:          "cloudflare_workers_ai_gateway_provider_configs",
				IDKeys:           []string{"id", "alias", "secret_id", "name", "key", "sid"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"result"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|alias|hostname|metadata.resource_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created|date_created", "secret_id": "id", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "alias", "secret_rotation_enabled": "secret_rotation_enabled|rotation_enabled|auto_rotate", "secret_status": "secret_status|status|state", "secret_type": "secret_type|type|kind", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "resource_type": "gateway_provider_config", "schema": "gateway_provider_configs", "source_system": "cloudflare_workers_ai"},
				Config:           workersAITenantFamilyConfig("cloudflare_workers_ai_gateway_provider_configs"),
			},
			{
				Name:             familyGatewayEvaluations,
				Path:             "/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/evaluations",
				URNKind:          "cloudflare_workers_ai_gateway_evaluations",
				IDKeys:           []string{"id", "name", "policy_id", "key", "control_id"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"result"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "policy_created_at": "created_at|created|date_created", "policy_description": "description|summary|body", "policy_id": "id", "policy_name": "name", "policy_severity": "severity|risk|priority", "policy_status": "policy_status|status|state|enabled", "policy_type": "policy_type|type|kind|category", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "policy", "resource_type": "gateway_evaluation", "schema": "gateway_evaluations", "source_system": "cloudflare_workers_ai"},
				Config:           workersAITenantFamilyConfig("cloudflare_workers_ai_gateway_evaluations"),
			},
			{
				Name:             familyGatewayLogs,
				Path:             "/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/logs",
				URNKind:          "cloudflare_workers_ai_gateway_logs",
				IDKeys:           []string{"id", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"result"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "id|resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "ai_gateway", "schema": "gateway_logs", "source_system": "cloudflare_workers_ai"},
				Config:           workersAITenantFamilyConfig("cloudflare_workers_ai_gateway_logs"),
			},
			{
				Name:             familyVectorizeIndexes,
				Path:             "/accounts/${config.account_id}/vectorize/v2/indexes",
				URNKind:          "cloudflare_workers_ai_vectorize_indexes",
				IDKeys:           []string{"name", "id", "urn", "resource_urn"},
				DisablePageSize:  true,
				ListKeys:         []string{"result"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id|name", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "vectorize_index", "schema": "vectorize_indexes", "source_system": "cloudflare_workers_ai"},
				Config:           workersAITenantFamilyConfig("cloudflare_workers_ai_vectorize_indexes"),
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

func workersAITenantFamilyConfig(resourceURNKind string) jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{
		ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
		ResourceURNKind:  resourceURNKind,
	}
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
