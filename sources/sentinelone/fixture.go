package sentinelone

import (
	"context"
	"embed"
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic SentinelOne source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, name := range []string{
		familyActivity, familyAgent, familyApplication, familyExclusion, familyGroup, familySite, familyThreat,
	} {
		urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover_"+name+".json")
		if err != nil {
			return nil, err
		}
		events, err := sourcecdk.LoadFixtureEvents(fixtureFS, "testdata/read_"+name+".json")
		if err != nil {
			return nil, err
		}
		families = append(families, sourcecdk.FixtureFamily{Name: name, URNs: urns, Events: events})
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
	_, err := parseSettings(cfg, false)
	return err
}

func resolveFixtureFamily(cfg sourcecdk.Config) (string, error) {
	settings, err := parseSettings(cfg, false)
	if err != nil {
		return "", fmt.Errorf("parse sentinelone fixture settings: %w", err)
	}
	return settings.family, nil
}
