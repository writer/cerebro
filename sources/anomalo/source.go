package anomalo

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
	sourceID                = "anomalo"
	defaultFamily           = familyWarehouses
	defaultHealthPath       = "/ping"
	defaultBaseURLTemplate  = "${config.base_url}"
	tokenHeader             = ""
	tokenScheme             = "Bearer"
	familyWarehouses        = "warehouses"
	familyTables            = "tables"
	familyChecks            = "checks"
	familyNotificationChans = "notification_channels"
	familyOrganizations     = "organizations"
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
				Name:            familyWarehouses,
				Path:            "/list_warehouses",
				URNKind:         "anomalo_warehouses",
				IDKeys:          []string{"id", "name"},
				ListKeys:        []string{"warehouses"},
				DisablePageSize: true,
				Attributes: map[string]string{
					"id":              "id",
					"name":            "name",
					"resource_id":     "id",
					"resource_name":   "name",
					"resource_type":   "warehouse_type",
					"resource_urn":    "resource_urn|urn|metadata.resource_urn",
					"source_event_id": "event_id|id",
					"tenant_id":       "tenant_id|metadata.tenant_id",
					"warehouse_type":  "warehouse_type",
					"is_active":       "is_active",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "warehouses", "source_system": "anomalo"},
			},
			{
				Name:            familyTables,
				Path:            "/get_table_information",
				URNKind:         "anomalo_tables",
				IDKeys:          []string{"id", "full_name", "table_name"},
				Singleton:       true,
				DisablePageSize: true,
				Config:          jsonapi.FamilyConfig{ConfigQuery: map[string]string{"table_id": "table_id", "table_name": "table_name", "warehouse_id": "warehouse_id"}},
				Attributes: map[string]string{
					"id":                      "id",
					"name":                    "full_name|name|table_name",
					"resource_id":             "id",
					"resource_name":           "full_name|name|table_name",
					"resource_type":           "table",
					"resource_urn":            "resource_urn|urn|metadata.resource_urn",
					"source_event_id":         "event_id|id",
					"tenant_id":               "tenant_id|metadata.tenant_id",
					"warehouse_id":            "warehouse.id|warehouse_id",
					"warehouse_name":          "warehouse.name|warehouse_name",
					"monitored":               "monitored",
					"check_cadence_type":      "config.check_cadence_type",
					"notification_channel_id": "config.notification_channel_id",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "tables", "source_system": "anomalo"},
			},
			{
				Name:            familyChecks,
				Path:            "/get_checks_for_table",
				URNKind:         "anomalo_checks",
				IDKeys:          []string{"check_static_id", "check_id", "ref"},
				ListKeys:        []string{"checks"},
				DisablePageSize: true,
				Config:          jsonapi.FamilyConfig{ConfigQuery: map[string]string{"table_id": "table_id"}, StaticQuery: map[string]string{"exclude_disabled": "true"}},
				Attributes: map[string]string{
					"policy_id":          "check_static_id|check_id|ref",
					"policy_name":        "ref|config._metadata.check_message|check_type",
					"policy_status":      "triage_status",
					"policy_type":        "check_type|config._metadata.check_type",
					"policy_description": "config._metadata.description|config._metadata.check_message",
					"policy_severity":    "config._metadata.priority_level",
					"resource_id":        "table_id",
					"resource_type":      "table_check",
					"resource_urn":       "resource_urn|urn|metadata.resource_urn",
					"source_event_id":    "event_id|check_static_id|check_id|ref",
					"tenant_id":          "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "checks", "source_system": "anomalo"},
			},
			{
				Name:            familyNotificationChans,
				Path:            "/list_notification_channels",
				URNKind:         "anomalo_notification_channels",
				IDKeys:          []string{"id", "ref", "description"},
				ListKeys:        []string{"notification_channels"},
				DisablePageSize: true,
				Attributes: map[string]string{
					"id":              "id",
					"name":            "ref|description",
					"resource_id":     "id",
					"resource_name":   "ref|description",
					"resource_type":   "notification_channel",
					"resource_urn":    "resource_urn|urn|metadata.resource_urn",
					"source_event_id": "event_id|id|ref",
					"tenant_id":       "tenant_id|metadata.tenant_id",
					"channel_type":    "channel_type",
					"description":     "description",
					"ref":             "ref",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "notification_channels", "source_system": "anomalo"},
			},
			{
				Name:            familyOrganizations,
				Path:            "/organizations",
				URNKind:         "anomalo_organizations",
				IDKeys:          []string{"id", "name"},
				DisablePageSize: true,
				Attributes: map[string]string{
					"id":              "id",
					"name":            "name",
					"resource_id":     "id",
					"resource_name":   "name",
					"resource_type":   "organization",
					"resource_urn":    "resource_urn|urn|metadata.resource_urn",
					"source_event_id": "event_id|id",
					"tenant_id":       "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "organizations", "source_system": "anomalo"},
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
