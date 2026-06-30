package anthropic

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic anthropic source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{"analytics_cost", "api_key", "compliance_activity", "compliance_group", "compliance_group_member", "compliance_organization", "compliance_organization_setting", "compliance_organization_user", "compliance_project", "compliance_project_collaborator", "compliance_role", "compliance_role_permission", "cost_report", "external_key", "federation_issuer", "federation_rule", "invite", "organization", "rate_limit", "service_account", "spend_limit", "spend_limit_increase_request", "usage_report_claude_code", "usage_report_message", "user", "workspace", "workspace_member", "workspace_rate_limit"} {
		urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover_"+family+".json")
		if err != nil {
			return nil, err
		}
		events, err := sourcecdk.LoadFixtureEventsWithContracts(fixtureFS, "testdata/read_"+family+".json", catalog.EventContracts)
		if err != nil {
			return nil, err
		}
		families = append(families, sourcecdk.FixtureFamily{Name: family, URNs: urns, Events: events})
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          catalog.Spec,
		Contracts:     catalog.EventContracts,
		DefaultFamily: "user",
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
		return "user", nil
	}
	return family, nil
}

func fixtureTenantID(cfg sourcecdk.Config) string {
	return strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
}
