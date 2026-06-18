package pagerduty

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "pagerduty"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.pagerduty.com",
		DefaultFamily:   "user",
		RequireTenantID: true,
		TokenScheme:     "Token token=",
		Families: []jsonapi.Family{
			{Name: "user", Path: "/users", URNKind: "pagerduty_user", IDKeys: []string{"id"}, Attributes: map[string]string{"user_id": "id", "name": "name", "email": "email", "role": "role", "time_zone": "time_zone", "job_title": "job_title"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "team", Path: "/teams", URNKind: "pagerduty_team", IDKeys: []string{"id"}, Attributes: map[string]string{"team_id": "id", "name": "name", "description": "description"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "service", Path: "/services", URNKind: "pagerduty_service", IDKeys: []string{"id"}, TimestampKeys: []string{"created_at"}, Attributes: map[string]string{"service_id": "id", "name": "name", "summary": "summary", "status": "status", "html_url": "html_url", "escalation_policy_id": "escalation_policy.id", "escalation_policy_name": "escalation_policy.summary|escalation_policy.name"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "schedule", Path: "/schedules", URNKind: "pagerduty_schedule", IDKeys: []string{"id"}, Attributes: map[string]string{"schedule_id": "id", "name": "name", "summary": "summary", "time_zone": "time_zone", "html_url": "html_url"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "escalation_policy", Path: "/escalation_policies", URNKind: "pagerduty_escalation_policy", IDKeys: []string{"id"}, ListKeys: []string{"escalation_policies"}, Attributes: map[string]string{"escalation_policy_id": "id", "name": "name", "summary": "summary", "num_loops": "num_loops", "html_url": "html_url"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "integration", Path: "/services/{service_id}/integrations", PathParams: []string{"service_id"}, URNKind: "pagerduty_integration", IDKeys: []string{"id"}, Attributes: map[string]string{"integration_id": "id", "name": "name", "summary": "summary", "service_id": "service.id|service_id", "service_name": "service.summary|service.name", "vendor_id": "vendor.id", "vendor_name": "vendor.summary|vendor.name"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
			{Name: "vendor", Path: "/vendors", URNKind: "pagerduty_vendor", IDKeys: []string{"id"}, Attributes: map[string]string{"vendor_id": "id", "name": "name", "summary": "summary", "website_url": "website_url"}, StaticAttributes: map[string]string{"source_product": "pagerduty"}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
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
