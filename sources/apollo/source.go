package apollo

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "apollo"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/users/api_profile"
	defaultBaseURLTemplate = "https://api.apollo.io/api/v1"
	tokenHeader            = "x-api-key"
	tokenScheme            = ""
	familyUsers            = "users"
	familyAccounts         = "accounts"
	familyContacts         = "contacts"
)

var templateKeys = []string{"base_url", "token", "api_key"}

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
			apolloUsersFamily(),
			apolloAccountsFamily(),
			apolloContactsFamily(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func apolloUsersFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyUsers,
		Path:            "/users/search",
		URNKind:         "apollo_users",
		IDKeys:          []string{"id", "user_id", "email"},
		CursorParam:     "page",
		PageFirstCursor: "1",
		PageSizeParams:  []string{"per_page"},
		ListKeys:        []string{"users"},
		TimestampKeys:   []string{"updated_at", "created_at", "notification_last_read_at", "notification_last_created_at"},
		Attributes: map[string]string{
			"created_at":      "created_at",
			"display_name":    "name|email|id",
			"email":           "email",
			"job_title":       "title",
			"login":           "email|id",
			"observed_at":     "updated_at|notification_last_read_at|created_at",
			"primary_email":   "email",
			"resource_id":     "id",
			"resource_name":   "name|email|id",
			"resource_type":   "apollo_user",
			"source_event_id": "id",
			"status":          "deleted|territory_is_active",
			"tenant_id":       "tenant_id|metadata.tenant_id",
			"user_id":         "id",
		},
		Config:           jsonapi.FamilyConfig{DefaultPageSize: 100, ResourceURNKind: "apollo_users"},
		StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "apollo"},
	}
}

func apolloAccountsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyAccounts,
		Path:            "/accounts/search",
		URNKind:         "apollo_accounts",
		IDKeys:          []string{"id", "name", "domain", "organization_id"},
		CursorParam:     "page",
		PageFirstCursor: "1",
		PageSizeParams:  []string{"per_page"},
		ListKeys:        []string{"accounts"},
		TimestampKeys:   []string{"updated_at", "created_at", "last_activity_date"},
		Attributes: map[string]string{
			"account_stage_id": "account_stage_id",
			"created_at":       "created_at",
			"domain":           "domain",
			"observed_at":      "updated_at|last_activity_date|created_at",
			"organization_id":  "organization_id",
			"owner_id":         "owner_id",
			"resource_id":      "id",
			"resource_name":    "name|domain|id",
			"resource_type":    "apollo_account",
			"source_event_id":  "id",
			"tenant_id":        "tenant_id|metadata.tenant_id",
		},
		Config:           jsonapi.FamilyConfig{Method: http.MethodPost, DefaultPageSize: 100, ResourceURNKind: "apollo_accounts"},
		StaticAttributes: map[string]string{"record_class": "asset", "schema": "accounts", "source_system": "apollo"},
	}
}

func apolloContactsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyContacts,
		Path:            "/contacts/search",
		URNKind:         "apollo_contacts",
		IDKeys:          []string{"id", "person_id", "email", "crm_id"},
		CursorParam:     "page",
		PageFirstCursor: "1",
		PageSizeParams:  []string{"per_page"},
		ListKeys:        []string{"contacts"},
		TimestampKeys:   []string{"updated_at", "created_at", "last_activity_date"},
		Attributes: map[string]string{
			"account_id":      "account_id|account.id",
			"created_at":      "created_at",
			"display_name":    "name|email|id",
			"email":           "email",
			"job_title":       "title",
			"login":           "email|id",
			"observed_at":     "updated_at|last_activity_date|created_at",
			"organization_id": "organization_id|organization.id",
			"primary_email":   "email",
			"resource_id":     "id",
			"resource_name":   "name|email|id",
			"resource_type":   "apollo_contact",
			"source_event_id": "id",
			"status":          "email_status|existence_level",
			"tenant_id":       "tenant_id|metadata.tenant_id",
			"user_id":         "id|person_id|email",
		},
		Config:           jsonapi.FamilyConfig{Method: http.MethodPost, DefaultPageSize: 100, ResourceURNKind: "apollo_contacts"},
		StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "contacts", "source_system": "apollo"},
	}
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
