package mastodon

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
	sourceID               = "mastodon"
	defaultFamily          = familyAccount
	defaultHealthPath      = "/api/v1/lists/${config.id}/accounts"
	defaultBaseURLTemplate = "http://mastodon.local"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyAccount          = "account"
	familyActivity         = "activity"
	familyVerifyCredential = "verify_credential"
	familyNotification     = "notification"
)

var templateKeys = []string{"id", "token"}

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
				Name:             familyAccount,
				Path:             "/api/v1/lists/${config.id}/accounts",
				URNKind:          "mastodon_account",
				IDKeys:           []string{"id", "display_name", "user_id", "email", "primary_email", "login"},
				CursorParam:      "max_id",
				LinkHeader:       "Link",
				PageSizeParams:   []string{"limit"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "display_name": "display_name|username|acct", "id": "id", "login": "acct|username", "name": "display_name|username|acct", "provider_id": "id", "resource_id": "id", "resource_name": "display_name|username|acct", "source_event_id": "id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "account", "schema": "account", "source_system": "mastodon"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
			},
			{
				Name:             familyActivity,
				Path:             "/api/v1/instance/activity",
				URNKind:          "mastodon_activity",
				IDKeys:           []string{"week"},
				TimestampKeys:    []string{"week"},
				Attributes:       map[string]string{"id": "week", "logins": "logins", "name": "week", "observed_at": "week", "provider_id": "week", "registrations": "registrations", "resource_id": "week", "source_event_id": "week", "statuses": "statuses"},
				StaticAttributes: map[string]string{"actor_id": "mastodon_instance", "actor_name": "Mastodon instance", "event_type": "instance_activity", "record_class": "audit_event", "resource_type": "instance_activity", "schema": "activity", "source_system": "mastodon"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
				DisablePageSize:  true,
			},
			{
				Name:             familyVerifyCredential,
				Path:             "/api/v1/accounts/verify_credentials",
				URNKind:          "mastodon_verify_credential",
				IDKeys:           []string{"id"},
				TimestampKeys:    []string{"created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "display_name": "display_name|username|acct", "id": "id", "login": "acct|username", "name": "display_name|username|acct", "provider_id": "id", "resource_id": "id", "resource_name": "display_name|username|acct", "source_event_id": "id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "account", "schema": "verify_credential", "source_system": "mastodon"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
				DisablePageSize:  true,
				Singleton:        true,
			},
			{
				Name:             familyNotification,
				Path:             "/api/v1/notifications",
				URNKind:          "mastodon_notification",
				IDKeys:           []string{"id"},
				CursorParam:      "max_id",
				LinkHeader:       "Link",
				PageSizeParams:   []string{"limit"},
				TimestampKeys:    []string{"created_at"},
				Attributes:       map[string]string{"alert_fired_at": "created_at", "alert_id": "id", "alert_name": "type|group_key", "alert_source": "status.url|account.url", "alert_type": "type", "id": "id", "name": "type|group_key", "observed_at": "created_at", "provider_id": "id", "resource_id": "status.id|account.id|id", "resource_name": "status.url|account.acct|type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"alert_status": "unread", "record_class": "alert", "resource_type": "notification", "schema": "notification", "source_system": "mastodon"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
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
