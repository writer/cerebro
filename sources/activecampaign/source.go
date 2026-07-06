package activecampaign

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
	sourceID               = "activecampaign"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/api/3/users/me"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = "Api-Token"
	tokenScheme            = ""
	familyUsers            = "users"
	familyAccounts         = "accounts"
	familyContacts         = "contacts"
	familyCampaigns        = "campaigns"
	familyAutomations      = "automations"
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
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/api/3/users",
				URNKind:          "activecampaign_users",
				IDKeys:           []string{"id", "username", "email"},
				CursorParam:      "offset",
				PageSizeParams:   []string{"limit"},
				PageFirstCursor:  "0",
				ListKeys:         []string{"users"},
				TimestampKeys:    []string{"updatedTimestamp", "mdate", "udate", "cdate", "createdTimestamp"},
				Attributes:       map[string]string{"display_name": "name|username", "email": "email", "first_name": "firstName", "last_name": "lastName", "login": "username|email", "phone": "phone", "primary_email": "email", "resource_id": "id", "resource_name": "name|username", "resource_type": "activecampaign_user", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "activecampaign"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"meta.total"},
					LimitKeys:       []string{"meta.page_input.limit"},
					OffsetKeys:      []string{"meta.page_input.offset"},
				},
			},
			{
				Name:             familyAccounts,
				Path:             "/api/3/accounts",
				URNKind:          "activecampaign_accounts",
				IDKeys:           []string{"id", "name"},
				CursorParam:      "offset",
				PageSizeParams:   []string{"limit"},
				PageFirstCursor:  "0",
				ListKeys:         []string{"accounts"},
				TimestampKeys:    []string{"updatedTimestamp", "createdTimestamp"},
				Attributes:       map[string]string{"contact_count": "contactCount", "deal_count": "dealCount", "id": "id", "name": "name", "observed_at": "updatedTimestamp|createdTimestamp", "resource_id": "id", "resource_name": "name", "resource_type": "activecampaign_account", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "activecampaign_account", "schema": "accounts", "source_system": "activecampaign"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"meta.total"},
					LimitKeys:       []string{"meta.page_input.limit"},
					OffsetKeys:      []string{"meta.page_input.offset"},
				},
			},
			{
				Name:             familyContacts,
				Path:             "/api/3/contacts",
				URNKind:          "activecampaign_contacts",
				IDKeys:           []string{"id", "email", "hash"},
				CursorParam:      "offset",
				PageSizeParams:   []string{"limit"},
				PageFirstCursor:  "0",
				ListKeys:         []string{"contacts"},
				TimestampKeys:    []string{"udate", "cdate", "adate", "edate"},
				Attributes:       map[string]string{"email": "email", "first_name": "firstName", "id": "id", "last_name": "lastName", "name": "name|email", "observed_at": "udate|cdate", "phone": "phone", "resource_id": "id", "resource_name": "email|firstName", "resource_type": "activecampaign_contact", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "activecampaign_contact", "schema": "contacts", "source_system": "activecampaign"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"meta.total"},
					LimitKeys:       []string{"meta.page_input.limit"},
					OffsetKeys:      []string{"meta.page_input.offset"},
				},
			},
			{
				Name:             familyCampaigns,
				Path:             "/api/3/campaigns",
				URNKind:          "activecampaign_campaigns",
				IDKeys:           []string{"id", "name"},
				CursorParam:      "offset",
				PageSizeParams:   []string{"limit"},
				PageFirstCursor:  "0",
				ListKeys:         []string{"campaigns"},
				TimestampKeys:    []string{"updated_timestamp", "created_timestamp", "mdate", "cdate", "sdate", "ldate"},
				Attributes:       map[string]string{"id": "id", "name": "name", "observed_at": "updated_timestamp|mdate|created_timestamp|cdate", "resource_id": "id", "resource_name": "name", "resource_type": "activecampaign_campaign", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "type": "type", "user_id": "userid|user"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "activecampaign_campaign", "schema": "campaigns", "source_system": "activecampaign"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"meta.total"},
					LimitKeys:       []string{"meta.page_input.limit"},
					OffsetKeys:      []string{"meta.page_input.offset"},
				},
			},
			{
				Name:             familyAutomations,
				Path:             "/api/3/automations",
				URNKind:          "activecampaign_automations",
				IDKeys:           []string{"id", "name"},
				CursorParam:      "offset",
				PageSizeParams:   []string{"limit"},
				PageFirstCursor:  "0",
				ListKeys:         []string{"automations"},
				TimestampKeys:    []string{"mdate", "cdate"},
				Attributes:       map[string]string{"id": "id", "name": "name", "observed_at": "mdate|cdate", "resource_id": "id", "resource_name": "name", "resource_type": "activecampaign_automation", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "userid"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "activecampaign_automation", "schema": "automations", "source_system": "activecampaign"},
				Config: jsonapi.FamilyConfig{
					DefaultPageSize: 100,
					TotalKeys:       []string{"meta.total"},
					LimitKeys:       []string{"meta.page_input.limit"},
					OffsetKeys:      []string{"meta.page_input.offset"},
				},
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
