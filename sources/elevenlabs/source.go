package elevenlabs

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
	sourceID                    = "elevenlabs"
	defaultFamily               = familyModelCatalog
	defaultHealthPath           = "/v1/models"
	defaultBaseURLTemplate      = "https://api.elevenlabs.io"
	tokenHeader                 = "xi-api-key"
	tokenScheme                 = "Token"
	familyModelCatalog          = "model_catalog"
	familyVoices                = "voices"
	familyServiceAccounts       = "service_accounts"
	familyServiceAccountApiKeys = "service_account_api_keys"
	familyWebhooks              = "webhooks"
	familyAuthConnections       = "auth_connections"
)

var templateKeys = []string{"service_account_user_id", "api_key"}

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
				Name:             familyModelCatalog,
				Path:             "/v1/models",
				URNKind:          "elevenlabs_model_catalog",
				IDKeys:           []string{"model_id", "name", "id", "urn", "resource_urn"},
				DisablePageSize:  true,
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_model_catalog"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "model_id", "resource_name": "name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id|model_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "model_catalog", "source_system": "elevenlabs"},
			},
			{
				Name:             familyVoices,
				Path:             "/v2/voices",
				URNKind:          "elevenlabs_voices",
				IDKeys:           []string{"voice_id", "name", "id", "urn", "resource_urn"},
				CursorParam:      "next_page_token",
				NextCursorKeys:   []string{"next_page_token"},
				PageSizeParams:   []string{"page_size"},
				ListKeys:         []string{"voices"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_voices"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "voice_id", "resource_name": "name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id|voice_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "voice", "schema": "voices", "source_system": "elevenlabs"},
			},
			{
				Name:             familyServiceAccounts,
				Path:             "/v1/service-accounts",
				URNKind:          "elevenlabs_service_accounts",
				IDKeys:           []string{"service_account_user_id", "name", "user_id", "id", "email", "primary_email", "login"},
				DisablePageSize:  true,
				ListKeys:         []string{"service_accounts", "service-accounts"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_service_accounts"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at", "created_at_unix"},
				Attributes:       map[string]string{"created_at": "created_at|created_at_unix", "display_name": "name", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|created_at|created_at_unix", "resource_id": "service_account_user_id", "resource_name": "name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id|service_account_user_id", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "service_account_user_id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "service_accounts", "source_system": "elevenlabs"},
			},
			{
				Name:             familyServiceAccountApiKeys,
				Path:             "/v1/service-accounts/${config.service_account_user_id}/api-keys",
				URNKind:          "elevenlabs_service_account_api_keys",
				IDKeys:           []string{"key_id", "name", "secret_id", "id", "key", "sid"},
				DisablePageSize:  true,
				ListKeys:         []string{"api_keys", "api-keys"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_service_account_api_keys"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at", "created_at_unix"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|created_at|created_at_unix", "resource_id": "key_id", "resource_name": "name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created_at_unix", "secret_id": "key_id", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "name", "secret_status": "secret_status|status|state", "secret_type": "secret_type|type|kind", "service_account_key_disabled": "is_disabled", "source_event_id": "event_id|id|metadata.event_id|key_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "service_account_api_keys", "source_system": "elevenlabs"},
			},
			{
				Name:             familyWebhooks,
				Path:             "/v1/workspace/webhooks",
				URNKind:          "elevenlabs_webhooks",
				IDKeys:           []string{"webhook_id", "name", "deployment_id", "id", "url", "uid"},
				DisablePageSize:  true,
				ListKeys:         []string{"webhooks"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_webhooks"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_created_at": "created_at", "deployment_id": "webhook_id", "deployment_name": "name", "deployment_status": "status|is_enabled", "deployment_updated_at": "updated_at", "deployment_url": "webhook_url|url", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|created_at", "resource_id": "webhook_id", "resource_name": "name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id|webhook_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "schema": "webhooks", "source_system": "elevenlabs"},
			},
			{
				Name:             familyAuthConnections,
				Path:             "/v1/workspace/auth-connections",
				URNKind:          "elevenlabs_auth_connections",
				IDKeys:           []string{"id", "name", "secret_id", "key", "sid"},
				DisablePageSize:  true,
				ListKeys:         []string{"auth_connections"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "elevenlabs_auth_connections"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|created_at", "resource_id": "id|name", "resource_name": "name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at", "secret_id": "id|name", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "name", "secret_status": "secret_status|status|state", "secret_type": "secret_type|type|kind", "source_event_id": "event_id|id|metadata.event_id|name", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "auth_connections", "source_system": "elevenlabs"},
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
