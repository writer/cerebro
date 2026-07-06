package aircall

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
	sourceID               = "aircall"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/ping"
	defaultBaseURLTemplate = "https://api.aircall.io/v1"
	tokenHeader            = ""
	tokenScheme            = "Basic"
	familyUsers            = "users"
	familyTeams            = "teams"
	familyCalls            = "calls"
	familyContacts         = "contacts"
	familyNumbers          = "numbers"
)

var templateKeys = []string{"base_url"}

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
		AuthModel:       "basic",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/users",
				URNKind:          "aircall_users",
				IDKeys:           []string{"id", "email", "name"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"meta.next_page_link"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"users"},
				TimestampKeys:    []string{"updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "display_name": "name", "email": "email", "extension": "extension", "last_login_at": "last_login_at", "login": "email", "observed_at": "updated_at|created_at", "primary_email": "email", "resource_id": "id", "resource_name": "name", "resource_type": "aircall_user", "source_event_id": "id", "status": "availability_status|status", "tenant_id": "tenant_id|metadata.tenant_id", "time_zone": "time_zone", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "aircall"},
			},
			{
				Name:             familyTeams,
				Path:             "/teams",
				URNKind:          "aircall_teams",
				IDKeys:           []string{"id", "name"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"meta.next_page_link"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"teams"},
				TimestampKeys:    []string{"updated_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "description": "description", "group_id": "id", "group_name": "name", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "name", "resource_type": "aircall_team", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "teams", "source_system": "aircall"},
			},
			{
				Name:             familyCalls,
				Path:             "/calls",
				URNKind:          "aircall_calls",
				IDKeys:           []string{"id", "sid"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"meta.next_page_link"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"calls"},
				TimestampKeys:    []string{"ended_at", "answered_at", "started_at", "updated_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "user.email", "actor_id": "user.id", "actor_name": "user.name", "call_direction": "direction", "call_status": "status", "event_type": "direction", "observed_at": "ended_at|answered_at|started_at", "raw_digits": "raw_digits", "resource_id": "id", "resource_name": "sid|raw_digits", "resource_type": "aircall_call", "sid": "sid", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "calls", "source_system": "aircall"},
			},
			{
				Name:             familyContacts,
				Path:             "/contacts",
				URNKind:          "aircall_contacts",
				IDKeys:           []string{"id", "email", "first_name", "last_name", "company_name"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"meta.next_page_link"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"contacts"},
				TimestampKeys:    []string{"updated_at", "created_at"},
				Attributes:       map[string]string{"company_name": "company_name", "created_at": "created_at", "first_name": "first_name", "last_name": "last_name", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "company_name|first_name|last_name", "resource_type": "aircall_contact", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id", "updated_at": "updated_at"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "contacts", "source_system": "aircall"},
			},
			{
				Name:             familyNumbers,
				Path:             "/numbers",
				URNKind:          "aircall_numbers",
				IDKeys:           []string{"id", "digits", "name"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"meta.next_page_link"},
				PageSizeParams:   []string{"per_page"},
				ListKeys:         []string{"numbers"},
				TimestampKeys:    []string{"updated_at", "created_at"},
				Attributes:       map[string]string{"availability_status": "availability_status", "country": "country", "created_at": "created_at", "digits": "digits", "name": "name", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "name|digits", "resource_type": "aircall_number", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id", "time_zone": "time_zone"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "numbers", "source_system": "aircall"},
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
