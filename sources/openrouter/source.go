package openrouter

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
	sourceID                  = "openrouter"
	defaultFamily             = familyOrganizationMembers
	defaultHealthPath         = "/v1/models"
	defaultBaseURLTemplate    = "https://openrouter.ai/api"
	tokenHeader               = ""
	tokenScheme               = "Bearer"
	familyOrganizationMembers = "organization_members"
	familyApiKeys             = "api_keys"
	familyProviderKeys        = "provider_keys"
	familyUsageReports        = "usage_reports"
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
				Name:             familyOrganizationMembers,
				Path:             "/v1/organization/members",
				URNKind:          "openrouter_organization_members",
				IDKeys:           []string{"id", "email"},
				DisablePageSize:  true,
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "display_name": "email|first_name|last_name", "email": "email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "first_name": "first_name", "last_name": "last_name", "login": "email", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "email", "resource_id": "id", "resource_name": "email|id", "resource_urn": "resource_urn|urn|metadata.resource_urn", "role": "role", "source_event_id": "id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "organization_members", "source_system": "openrouter"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "openrouter_organization_members"},
			},
			{
				Name:             familyApiKeys,
				Path:             "/v1/keys",
				URNKind:          "openrouter_api_keys",
				IDKeys:           []string{"hash", "id", "name", "label"},
				DisablePageSize:  true,
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"api_key_disabled": "disabled", "api_key_hash": "hash", "creator_user_id": "creator_user_id", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "expires_at": "expires_at", "label": "label", "limit": "limit", "limit_remaining": "limit_remaining", "limit_reset": "limit_reset", "observed_at": "updated_at|created_at", "resource_id": "hash", "resource_name": "name|label", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at", "secret_id": "hash", "secret_name": "name|label", "source_event_id": "hash", "tenant_id": "tenant_id|metadata.tenant_id", "usage": "usage", "usage_daily": "usage_daily", "usage_monthly": "usage_monthly", "usage_weekly": "usage_weekly", "workspace_id": "workspace_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "api_keys", "secret_type": "openrouter_api_key", "source_system": "openrouter"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "openrouter_api_keys"},
			},
			{
				Name:             familyProviderKeys,
				Path:             "/v1/byok",
				URNKind:          "openrouter_provider_keys",
				IDKeys:           []string{"id", "name", "label"},
				DisablePageSize:  true,
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"allowed_api_key_hashes": "allowed_api_key_hashes", "allowed_models": "allowed_models", "allowed_user_ids": "allowed_user_ids", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "is_fallback": "is_fallback", "label": "label", "observed_at": "created_at", "provider_key_disabled": "disabled", "provider_key_provider": "provider", "resource_id": "id", "resource_name": "name|label|provider", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at", "secret_id": "id", "secret_name": "name|label|provider", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id", "workspace_id": "workspace_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "provider_keys", "secret_type": "byok_provider_credential", "source_system": "openrouter"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "openrouter_provider_keys"},
			},
			{
				Name:             familyUsageReports,
				Path:             "/v1/activity",
				URNKind:          "openrouter_usage_reports",
				IDKeys:           []string{"endpoint_id", "model_permaslug", "model", "date"},
				DisablePageSize:  true,
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "date"},
				Attributes:       map[string]string{"byok_usage_inference": "byok_usage_inference", "completion_tokens": "completion_tokens", "date": "date", "endpoint_id": "endpoint_id", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "model": "model", "model_permaslug": "model_permaslug", "observed_at": "observed_at|updated_at|last_seen_at|date", "prompt_tokens": "prompt_tokens", "provider_name": "provider_name", "reasoning_tokens": "reasoning_tokens", "requests": "requests", "resource_id": "endpoint_id", "resource_name": "model|model_permaslug|endpoint_id", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "endpoint_id", "tenant_id": "tenant_id|metadata.tenant_id", "usage": "usage"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "openrouter_activity_endpoint", "schema": "usage_reports", "source_system": "openrouter"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "openrouter_usage_reports", IdentityKeys: []string{"date"}},
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
