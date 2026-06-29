package pagerduty

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic PagerDuty source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{
		familyUser,
		familyTeam,
		familyService,
		familySchedule,
		familyEscalationPolicy,
		familyIntegration,
		familyVendor,
	} {
		urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover_"+family+".json")
		if err != nil {
			return nil, err
		}
		events, err := sourcecdk.LoadFixtureEvents(fixtureFS, "testdata/read_"+family+".json")
		if err != nil {
			return nil, err
		}
		families = append(families, sourcecdk.FixtureFamily{Name: family, URNs: urns, Events: events})
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          spec,
		DefaultFamily: defaultFamily,
		Check:         checkFixtureConfig,
		ResolveFamily: resolveFixtureFamily,
		Families:      families,
	})
}

func checkFixtureConfig(_ context.Context, cfg sourcecdk.Config) error {
	if fixtureTenantID(cfg) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	return nil
}

func resolveFixtureFamily(cfg sourcecdk.Config) (string, error) {
	if fixtureTenantID(cfg) == "" {
		return "", fmt.Errorf("tenant_id is required")
	}
	family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family"))
	if family == "" {
		family = defaultFamily
	}
	if family == familyIntegration && strings.TrimSpace(sourcecdk.ConfigValue(cfg, pagerDutyServiceIDConfig)) == "" {
		return "", fmt.Errorf("%s is required for %s", pagerDutyServiceIDConfig, familyIntegration)
	}
	return family, nil
}

func fixtureTenantID(cfg sourcecdk.Config) string {
	return strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
}
