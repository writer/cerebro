package googleworkspace

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic Google Workspace source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser} {
		records, err := loadRawFixture("testdata/read_" + family + ".json")
		if err != nil {
			return nil, err
		}
		settings := settings{
			family:      family,
			domain:      "writer.com",
			customerID:  "C01",
			token:       "test-token",
			baseURL:     defaultBaseURL,
			groupKey:    "security@writer.com",
			application: "admin",
			perPage:     1,
		}
		urns := []sourcecdk.URN{}
		events := []*cerebrov1.EventEnvelope{}
		for _, record := range records {
			event, err := sourceEvent(settings, record)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
			urn, err := discoverURN(settings, record)
			if err == nil && urn != "" {
				urns = append(urns, urn)
			}
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

func loadRawFixture(path string) ([]json.RawMessage, error) {
	content, err := fixtureFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var records []json.RawMessage
	if err := json.Unmarshal(content, &records); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return records, nil
}

func checkFixtureConfig(_ context.Context, cfg sourcecdk.Config) error {
	_, err := parseSettings(cfg)
	return err
}

func resolveFixtureFamily(cfg sourcecdk.Config) (string, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return "", fmt.Errorf("parse google_workspace fixture settings: %w", err)
	}
	return settings.family, nil
}
