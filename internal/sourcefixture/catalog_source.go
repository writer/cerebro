package sourcefixture

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

// NewCatalogSource loads a deterministic fixture source directly from a source
// package's catalog and checked-in read/discover fixtures. It replaces the
// generated fixture adapter that previously repeated this wiring per source.
func NewCatalogSource(sourceDir string, defaultFamily string) (sourcecdk.Source, error) {
	sourceDir = strings.TrimSpace(sourceDir)
	if sourceDir == "" {
		sourceDir = "."
	}
	fixtureFS := os.DirFS(sourceDir)
	catalogBytes, err := fs.ReadFile(fixtureFS, "catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	defaultFamily = strings.TrimSpace(defaultFamily)
	if defaultFamily == "" && len(catalog.RuntimeFamilies) > 0 {
		defaultFamily = catalog.RuntimeFamilies[0]
	}
	fixtureFamilies, err := catalogFixtureFamilies(fixtureFS)
	if err != nil {
		return nil, err
	}
	families := make([]sourcecdk.FixtureFamily, 0, len(fixtureFamilies))
	for _, family := range fixtureFamilies {
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
		Check: func(_ context.Context, cfg sourcecdk.Config) error {
			if fixtureTenantID(cfg) == "" {
				return fmt.Errorf("tenant_id is required")
			}
			return nil
		},
		ResolveFamily: func(cfg sourcecdk.Config) (string, error) {
			if fixtureTenantID(cfg) == "" {
				return "", fmt.Errorf("tenant_id is required")
			}
			family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family"))
			if family == "" {
				return defaultFamily, nil
			}
			return family, nil
		},
		Families: families,
	})
}

func catalogFixtureFamilies(fixtureFS fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fixtureFS, "testdata")
	if err != nil {
		return nil, fmt.Errorf("read testdata: %w", err)
	}
	var families []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "read_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		family := strings.TrimSuffix(strings.TrimPrefix(name, "read_"), ".json")
		if _, err := fs.Stat(fixtureFS, "testdata/discover_"+family+".json"); err != nil {
			return nil, fmt.Errorf("fixture family %s discover pair: %w", family, err)
		}
		families = append(families, family)
	}
	if len(families) == 0 {
		return nil, fmt.Errorf("testdata has no read/discover fixture pairs")
	}
	return families, nil
}

func fixtureTenantID(cfg sourcecdk.Config) string {
	return strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
}
