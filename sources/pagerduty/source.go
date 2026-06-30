package pagerduty

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                  = "pagerduty"
	defaultFamily             = familyUser
	familyUser                = "user"
	familyTeam                = "team"
	familyService             = "service"
	familySchedule            = "schedule"
	familyEscalationPolicy    = "escalation_policy"
	familyIntegration         = "integration"
	familyVendor              = "vendor"
	pagerDutySourceProduct    = "pagerduty"
	pagerDutyCursorParam      = "offset"
	pagerDutyHasMoreKey       = "more"
	pagerDutyPageSizeParam    = "limit"
	pagerDutyServiceIDConfig  = "service_id"
	pagerDutyServiceIDsConfig = "service_ids"
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.pagerduty.com",
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Token token=",
		Families:        pagerDutyFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if sourcecdk.ConfigValue(cfg, "family") == familyIntegration {
		if serviceIDs := pagerDutyIntegrationServiceIDs(cfg); len(serviceIDs) > 0 {
			return s.inner.CheckPathParamValues(ctx, cfg, pagerDutyServiceIDConfig, serviceIDs)
		}
	}
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if sourcecdk.ConfigValue(cfg, "family") == familyIntegration {
		if serviceIDs := pagerDutyIntegrationServiceIDs(cfg); len(serviceIDs) > 0 {
			return s.inner.DiscoverPathParamValues(ctx, cfg, pagerDutyServiceIDConfig, serviceIDs)
		}
	}
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if sourcecdk.ConfigValue(cfg, "family") == familyIntegration {
		if serviceIDs := pagerDutyIntegrationServiceIDs(cfg); len(serviceIDs) > 0 {
			return s.inner.ReadPathParamValues(ctx, cfg, cursor, pagerDutyServiceIDConfig, serviceIDs)
		}
	}
	return s.inner.Read(ctx, cfg, cursor)
}
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	if sourcecdk.ConfigValue(cfg, "family") == familyIntegration {
		if serviceIDs := pagerDutyIntegrationServiceIDs(cfg); len(serviceIDs) > 0 {
			return s.inner.ReadPathParamValues(ctx, cfg, cursor, pagerDutyServiceIDConfig, serviceIDs)
		}
	}
	return s.inner.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func pagerDutyFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		pagerDutyUserFamily(),
		pagerDutyTeamFamily(),
		pagerDutyServiceFamily(),
		pagerDutyScheduleFamily(),
		pagerDutyEscalationPolicyFamily(),
		pagerDutyIntegrationFamily(),
		pagerDutyVendorFamily(),
	}
}

func pagerDutyUserFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:    familyUser,
		Path:    "/users",
		URNKind: "pagerduty_user",
		IDKeys:  []string{"id"},
		Attributes: map[string]string{
			"user_id":   "id",
			"name":      "name",
			"email":     "email",
			"role":      "role",
			"time_zone": "time_zone",
			"job_title": "job_title",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyTeamFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:    familyTeam,
		Path:    "/teams",
		URNKind: "pagerduty_team",
		IDKeys:  []string{"id"},
		Attributes: map[string]string{
			"team_id":     "id",
			"name":        "name",
			"description": "description",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyServiceFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:          familyService,
		Path:          "/services",
		URNKind:       "pagerduty_service",
		IDKeys:        []string{"id"},
		TimestampKeys: []string{"created_at"},
		Attributes: map[string]string{
			"service_id":             "id",
			"name":                   "name",
			"summary":                "summary",
			"status":                 "status",
			"html_url":               "html_url",
			"escalation_policy_id":   "escalation_policy.id",
			"escalation_policy_name": "escalation_policy.summary|escalation_policy.name",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyScheduleFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:    familySchedule,
		Path:    "/schedules",
		URNKind: "pagerduty_schedule",
		IDKeys:  []string{"id"},
		Attributes: map[string]string{
			"schedule_id": "id",
			"name":        "name",
			"summary":     "summary",
			"time_zone":   "time_zone",
			"html_url":    "html_url",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyEscalationPolicyFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:     familyEscalationPolicy,
		Path:     "/escalation_policies",
		URNKind:  "pagerduty_escalation_policy",
		IDKeys:   []string{"id"},
		ListKeys: []string{"escalation_policies"},
		Attributes: map[string]string{
			"escalation_policy_id": "id",
			"name":                 "name",
			"summary":              "summary",
			"num_loops":            "num_loops",
			"html_url":             "html_url",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyIntegrationFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:       familyIntegration,
		Path:       "/services/{service_id}/integrations",
		PathParams: []string{pagerDutyServiceIDConfig},
		URNKind:    "pagerduty_integration",
		IDKeys:     []string{"id"},
		Attributes: map[string]string{
			"integration_id": "id",
			"name":           "name",
			"summary":        "summary",
			"service_name":   "service.summary|service.name",
			"vendor_id":      "vendor.id",
			"vendor_name":    "vendor.summary|vendor.name",
		},
		Config: jsonapi.FamilyConfig{ConfigAttributes: map[string]string{
			"service_id": pagerDutyServiceIDConfig,
		}},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyVendorFamily() jsonapi.Family {
	return pagerDutyPagedFamily(jsonapi.Family{
		Name:    familyVendor,
		Path:    "/vendors",
		URNKind: "pagerduty_vendor",
		IDKeys:  []string{"id"},
		Attributes: map[string]string{
			"vendor_id":   "id",
			"name":        "name",
			"summary":     "summary",
			"website_url": "website_url",
		},
		StaticAttributes: pagerDutyStaticAttributes(),
	})
}

func pagerDutyPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = pagerDutyCursorParam
	family.HasMoreKey = pagerDutyHasMoreKey
	family.PageSizeParams = []string{pagerDutyPageSizeParam}
	return family
}

func pagerDutyStaticAttributes() map[string]string {
	return map[string]string{"source_product": pagerDutySourceProduct}
}

func pagerDutyIntegrationServiceIDs(cfg sourcecdk.Config) []string {
	if values := splitConfigList(sourcecdk.ConfigValue(cfg, pagerDutyServiceIDsConfig)); len(values) > 0 {
		return values
	}
	return splitConfigList(sourcecdk.ConfigValue(cfg, pagerDutyServiceIDConfig))
}

func splitConfigList(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}
