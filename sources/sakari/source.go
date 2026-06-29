package sakari

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                   = "sakari"
	defaultFamily              = familyWebhook
	defaultHealthPath          = "/v1/accounts/${config.accountid}/webhooks"
	defaultBaseURLTemplate     = "https://api.sakari.io"
	tokenHeader                = ""
	tokenScheme                = "Bearer"
	oauthTokenURLTemplate      = "/oauth2/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 300 * time.Second
	familyWebhook              = "webhook"
	familyCampaign             = "campaign"
	familyContact              = "contact"
	familyConversation         = "conversation"
)

var templateKeys = []string{"accountid", "client_id", "client_secret"}

var oauthScopes = []string{"messages:send"}

var oauthTokenParams = map[string]string{}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
	tokenCache    sourcehttp.ClientCredentialsCache
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:                    sourceID,
		DefaultFamily:               defaultFamily,
		RequireTenantID:             true,
		AuthModel:                   "oauth_client_credentials",
		TokenHeader:                 tokenHeader,
		TokenScheme:                 tokenScheme,
		OAuthTokenURL:               "/oauth2/token",
		OAuthScopes:                 []string{"messages:send"},
		OAuthTokenRequestAuthMethod: "client_secret_basic",
		Families: []jsonapi.Family{
			{
				Name:             familyWebhook,
				Path:             "/v1/accounts/${config.accountid}/webhooks",
				URNKind:          "sakari_webhook",
				IDKeys:           []string{"eventTypes", "url", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "eventTypes", "name": "url", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "eventTypes", "resource_name": "url", "resource_type": "webhook", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "webhook", "source_system": "sakari"},
			},
			{
				Name:             familyCampaign,
				Path:             "/v1/accounts/${config.accountid}/campaigns",
				URNKind:          "sakari_campaign",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "id", "resource_type": "campaign", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "campaign", "source_system": "sakari"},
			},
			{
				Name:             familyContact,
				Path:             "/v1/accounts/${config.accountid}/contacts",
				URNKind:          "sakari_contact",
				IDKeys:           []string{"id", "email", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "email", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "email", "resource_type": "contact", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "contact", "source_system": "sakari"},
			},
			{
				Name:             familyConversation,
				Path:             "/v1/accounts/${config.accountid}/conversations",
				URNKind:          "sakari_conversation",
				IDKeys:           []string{"id", "closed", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "closed", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "closed", "resource_type": "conversation", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "conversation", "source_system": "sakari"},
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
	values := cfg.Values()
	if strings.TrimSpace(values["base_url"]) == "" && strings.TrimSpace(defaultBaseURLTemplate) != "" {
		baseURL, err := sourcecdk.RenderConfigTemplate(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
		if err != nil {
			return sourcecdk.Config{}, err
		}
		values["base_url"] = baseURL
	}
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	token, err := s.tokenCache.Token(ctx, cfg, sourcehttp.ClientCredentialsOptions{
		SourceID:         sourceID,
		TokenURLTemplate: oauthTokenURLTemplate,
		TemplateKeys:     templateKeys,
		Scopes:           oauthScopes,
		ScopeSeparator:   oauthScopeSeparator,
		TokenParams:      oauthTokenParams,
		ExpirationBuffer: oauthTokenExpirationBuffer,
		AllowLoopback:    s.allowLoopback,
	})
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values["token"] = token
	return sourcecdk.NewConfig(values), nil
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
