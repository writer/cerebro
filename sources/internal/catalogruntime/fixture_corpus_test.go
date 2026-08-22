package catalogruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestCatalogRuntimeRetainsRetiredProviderFixtureCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	validated := 0
	err := sourcefixture.WalkBundles(root, func(bundle sourcefixture.Bundle) error {
		if _, err := os.Stat(filepath.Join(root, "sources", bundle.Manifest.SourceID, "source.go")); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		entry, found, err := connectorcatalog.BuiltinEntry(bundle.Manifest.SourceID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("fixture source %q is missing from the connector catalog", bundle.Manifest.SourceID)
		}
		family, found := definitionFamily(entry.Definition, bundle.Manifest.Family)
		if !found {
			return fmt.Errorf("fixture family %s/%s is missing from the connector definition", bundle.Manifest.SourceID, bundle.Manifest.Family)
		}
		source, err := New(entry)
		if err != nil {
			return fmt.Errorf("construct catalog-runtime source for %s: %w", bundle.ManifestPath, err)
		}
		if source.Spec() == nil {
			return fmt.Errorf("catalog-runtime source for %s has no portable spec", bundle.ManifestPath)
		}
		wantKind := familyEventKind(entry.Definition.SourceID, family)
		if !slices.Contains(source.Spec().EmittedKinds, wantKind) {
			return fmt.Errorf("catalog-runtime source for %s does not emit %q", bundle.ManifestPath, wantKind)
		}
		validated++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if validated == 0 {
		t.Fatal("catalog-runtime fixture corpus validated no retired provider bundles")
	}
}

func definitionFamily(definition connectordefinitions.Definition, familyID string) (connectordefinitions.ResourceFamily, bool) {
	for _, family := range definition.ResourceFamilies {
		if family.ID == familyID {
			return family, true
		}
	}
	return connectordefinitions.ResourceFamily{}, false
}
