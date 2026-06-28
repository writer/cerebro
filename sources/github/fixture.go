package github

import (
	"context"
	"embed"
	"encoding/json"
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
	families, err := loadFixtureFamilies(familyAudit, familyDependabot, familyOrgInventory, familyPullRequest, familyRepository, familySecretScanning)
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          spec,
		DefaultFamily: defaultFamily,
		Check:         checkFixtureToken,
		Families:      families,
	})
}

func loadFixtureFamilies(names ...string) ([]sourcecdk.FixtureFamily, error) {
	families := make([]sourcecdk.FixtureFamily, 0, len(names))
	for _, name := range names {
		urns, err := loadFixtureURNs(name)
		if err != nil {
			return nil, err
		}
		events, err := sourcecdk.LoadFixtureEvents(fixtureFS, "testdata/read_"+name+".json")
		if err != nil {
			return nil, err
		}
		families = append(families, sourcecdk.FixtureFamily{
			Name:   name,
			URNs:   urns,
			Events: events,
		})
	}
	return families, nil
}

func loadFixtureURNs(family string) ([]sourcecdk.URN, error) {
	path := "testdata/discover_" + family + ".json"
	if family != familyOrgInventory && family != familySecretScanning {
		return sourcecdk.LoadFixtureURNs(fixtureFS, path)
	}
	urnBytes, err := fixtureFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rawURNs []string
	if err := json.Unmarshal(urnBytes, &rawURNs); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	urns := make([]sourcecdk.URN, 0, len(rawURNs))
	for _, rawURN := range rawURNs {
		urns = append(urns, sourcecdk.URN(rawURN))
	}
	return urns, nil
}

func checkFixtureToken(_ context.Context, cfg sourcecdk.Config) error {
	token, ok := cfg.Lookup("token")
	if !ok || strings.TrimSpace(token) == "" {
		return fmt.Errorf("github token is required")
	}
	return nil
}
