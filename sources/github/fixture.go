package github

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic GitHub source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover.json")
	if err != nil {
		return nil, err
	}
	events, err := sourcecdk.LoadFixtureEvents(fixtureFS, "testdata/read.json")
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          spec,
		DefaultFamily: defaultFamily,
		Check:         checkFixtureToken,
		Families: []sourcecdk.FixtureFamily{{
			Name:   defaultFamily,
			URNs:   urns,
			Events: events,
		}},
	})
}

func checkFixtureToken(_ context.Context, cfg sourcecdk.Config) error {
	token, ok := cfg.Lookup("token")
	if !ok || strings.TrimSpace(token) == "" {
		return fmt.Errorf("github token is required")
	}
	return nil
}
