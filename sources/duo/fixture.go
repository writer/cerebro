// Hand-maintained fixture source for Duo's HMAC-backed runtime.
package duo

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

var duoFixtureFamilies = []string{
	"user",
	"group",
	"administrator",
	"endpoint",
	"phone",
	"token",
	"web_authn_credential",
	"role",
	"application",
	"audit_event",
	"authentication_log",
}

func NewFixture() (sourcecdk.Source, error) {
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	families := make([]sourcecdk.FixtureFamily, 0, len(duoFixtureFamilies))
	for _, family := range duoFixtureFamilies {
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
		return defaultFamily, nil
	}
	return family, nil
}

func fixtureTenantID(cfg sourcecdk.Config) string {
	return strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
}
