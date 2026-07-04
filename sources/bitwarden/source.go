package bitwarden

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
	sourceID               = "bitwarden"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/public/organization/subscription"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyGroups           = "groups"
	familyCollections      = "collections"
	familyPolicies         = "policies"
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
				Path:             "/public/members",
				URNKind:          "bitwarden_users",
				IDKeys:           []string{"id", "userId", "email", "externalId"},
				CursorParam:      "continuationToken",
				NextCursorKeys:   []string{"continuationToken"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "date"},
				Attributes:       map[string]string{"display_name": "name|email", "email": "email", "external_id": "externalId", "login": "email", "member_type": "type", "primary_email": "email", "reset_password_enrolled": "resetPasswordEnrolled", "resource_id": "id", "resource_name": "name|email|externalId|id", "resource_type": "object", "source_event_id": "id", "sso_external_id": "ssoExternalId", "status": "status", "two_factor_enabled": "twoFactorEnabled", "user_id": "id|userId"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "bitwarden"},
			},
			{
				Name:             familyGroups,
				Path:             "/public/groups",
				URNKind:          "bitwarden_groups",
				IDKeys:           []string{"id", "name", "externalId"},
				CursorParam:      "continuationToken",
				NextCursorKeys:   []string{"continuationToken"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "date"},
				Attributes:       map[string]string{"external_id": "externalId", "group_id": "id", "group_name": "name|externalId|id", "resource_id": "id", "resource_name": "name|externalId|id", "resource_type": "object", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "bitwarden"},
			},
			{
				Name:             familyCollections,
				Path:             "/public/collections",
				URNKind:          "bitwarden_collections",
				IDKeys:           []string{"id", "externalId"},
				CursorParam:      "continuationToken",
				NextCursorKeys:   []string{"continuationToken"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "date"},
				Attributes:       map[string]string{"external_id": "externalId", "id": "id", "name": "externalId|id", "resource_id": "id", "resource_name": "externalId|id", "resource_type": "object", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "collections", "source_system": "bitwarden"},
			},
			{
				Name:             familyPolicies,
				Path:             "/public/policies",
				URNKind:          "bitwarden_policies",
				IDKeys:           []string{"id", "type"},
				CursorParam:      "continuationToken",
				NextCursorKeys:   []string{"continuationToken"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "date"},
				Attributes:       map[string]string{"enabled": "enabled", "id": "id", "policy_id": "id", "policy_name": "type|id", "policy_status": "enabled", "policy_type": "type", "resource_id": "id", "resource_name": "type|id", "resource_type": "object", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "policies", "source_system": "bitwarden"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/public/events",
				URNKind:          "bitwarden_audit_events",
				CursorParam:      "continuationToken",
				NextCursorKeys:   []string{"continuationToken"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"date", "observed_at", "updated_at", "last_seen_at"},
				Attributes:       map[string]string{"actor_id": "actingUserId", "event_type": "type", "observed_at": "date", "resource_id": "itemId|collectionId|groupId|policyId|memberId|secretId|projectId|serviceAccountId", "resource_type": "object", "source_event_id": "_record_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "bitwarden"},
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
