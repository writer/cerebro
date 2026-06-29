package onetrust

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
	sourceID                   = "onetrust"
	defaultFamily              = familyUsers
	defaultHealthPath          = "/api/access/v1/users"
	defaultBaseURLTemplate     = "https://${config.tenant_url}"
	tokenHeader                = ""
	tokenScheme                = "Bearer"
	oauthTokenURLTemplate      = "https://${config.tenant_url}/oauth/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 60 * time.Second
	familyUsers                = "users"
	familyControls             = "controls"
	familyFindings             = "findings"
)

var templateKeys = []string{"client_id", "client_secret", "tenant_url"}

var oauthScopes = []string{}

var oauthTokenParams = map[string]string{}

var oauthRuntimeConfigOptions = sourcehttp.ClientCredentialsRuntimeConfigOptions{
	SourceID:               sourceID,
	DefaultBaseURLTemplate: defaultBaseURLTemplate,
	TemplateKeys:           templateKeys,
	TokenURLTemplate:       oauthTokenURLTemplate,
	Scopes:                 oauthScopes,
	ScopeSeparator:         oauthScopeSeparator,
	TokenParams:            oauthTokenParams,
	ExpirationBuffer:       oauthTokenExpirationBuffer,
}

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
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "oauth_client_credentials",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		OAuthTokenURL:   "https://${config.tenant_url}/oauth/token",
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/v1/users",
				URNKind:          "onetrust_users",
				IDKeys:           []string{"id", "user_id", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "onetrust"},
			},
			{
				Name:             familyControls,
				Path:             "/v1/controls",
				URNKind:          "onetrust_controls",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "controls", "source_system": "onetrust"},
			},
			{
				Name:             familyFindings,
				Path:             "/v1/findings",
				URNKind:          "onetrust_findings",
				IDKeys:           []string{"id", "finding_id", "resource_urn"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity|risk|priority", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "title|name|summary"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "findings", "source_system": "onetrust"},
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
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	options := oauthRuntimeConfigOptions
	options.TokenCache = &s.tokenCache
	options.AllowLoopback = s.allowLoopback
	return sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, options)
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
