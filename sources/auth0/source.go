package auth0

import (
	"context"
	"embed"
	"fmt"
	"net/http"
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
	sourceID                   = "auth0"
	defaultFamily              = familyUsers
	defaultHealthPath          = "/users"
	defaultBaseURLTemplate     = "https://${config.domain}/api/v2"
	tokenScheme                = "Bearer"
	oauthTokenURLTemplate      = "https://${config.domain}/oauth/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 60 * time.Second
	familyUsers                = "users"
	familyRoles                = "roles"
	familyAuditEvents          = "audit_events"
)

var templateKeys = []string{"domain", "client_id", "client_secret"}

var oauthScopes = []string{"read:logs", "read:roles", "read:users"}

var oauthTokenParams = map[string]string{"audience": "https://${config.domain}/api/v2/"}

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
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:                 familyUsers,
				Path:                 "/users",
				URNKind:              "runtime_users",
				IDKeys:               []string{"user_id", "name", "id", "email", "primary_email", "login"},
				PageSizeParams:       []string{"per_page"},
				TimestampKeys:        []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:           map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes:     map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "auth0"},
				IncrementalWatermark: true,
			},
			{
				Name:                 familyRoles,
				Path:                 "/roles",
				URNKind:              "runtime_roles",
				IDKeys:               []string{"id", "name", "group_id", "group_email", "email"},
				PageSizeParams:       []string{"per_page"},
				TimestampKeys:        []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:           map[string]string{"description": "description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "group_name|name|display_name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes:     map[string]string{"record_class": "identity_group", "schema": "roles", "source_system": "auth0"},
				IncrementalWatermark: true,
			},
			{
				Name:                 familyAuditEvents,
				Path:                 "/logs",
				URNKind:              "runtime_audit_events",
				IDKeys:               []string{"log_id", "event_id", "id", "uuid", "request_id"},
				CursorParam:          "from",
				PageSizeParams:       []string{"take"},
				TimestampKeys:        []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:           map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes:     map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "auth0"},
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

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	values := cfg.Values()
	if strings.TrimSpace(values["base_url"]) == "" && strings.TrimSpace(defaultBaseURLTemplate) != "" {
		baseURL, err := renderTemplate(defaultBaseURLTemplate, cfg)
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
	baseURL, _, err := sourcehttp.NormalizeBaseURL(sourceID, configValue(cfg, "base_url"), s != nil && s.allowLoopback)
	if err != nil {
		return err
	}
	path := firstNonEmpty(configValue(cfg, "health_path"), defaultHealthPath)
	path, err = sourcehttp.NormalizeRequestPath(sourceID, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build %s health request: %w", sourceID, err)
	}
	req.Header.Set("Accept", "application/json")
	if token := strings.TrimSpace(firstNonEmpty(configValue(cfg, "token"), configValue(cfg, "api_token"))); token != "" {
		req.Header.Set("Authorization", tokenScheme+" "+token)
	}
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: sourceID, AllowLoopback: s != nil && s.allowLoopback, Timeout: 10 * time.Second})
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s health endpoint %s returned HTTP %d", sourceID, path, resp.StatusCode)
	}
	return nil
}

func renderTemplate(template string, cfg sourcecdk.Config) (string, error) {
	rendered := strings.TrimSpace(template)
	for _, key := range templateKeys {
		for _, prefix := range []string{"config", "credential", "connection"} {
			placeholder := "${" + prefix + "." + key + "}"
			if !strings.Contains(rendered, placeholder) {
				continue
			}
			value, err := requiredConfigValue(cfg, key)
			if err != nil {
				return "", err
			}
			rendered = strings.ReplaceAll(rendered, placeholder, value)
		}
	}
	if strings.Contains(rendered, "${") {
		return "", fmt.Errorf("%w: %s template %q contains unresolved variable", sourcecdk.ErrInvalidConfig, sourceID, template)
	}
	return rendered, nil
}

func requiredConfigValue(cfg sourcecdk.Config, key string) (string, error) {
	value := strings.TrimSpace(configValue(cfg, key))
	if value == "" {
		return "", fmt.Errorf("%w: %s %s is required", sourcecdk.ErrInvalidConfig, sourceID, key)
	}
	return value, nil
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
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
