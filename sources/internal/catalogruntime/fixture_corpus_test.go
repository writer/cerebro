package catalogruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcefixture"
)

var retiredStaticLoaderFixtureSources = []string{
	"acunetix",
	"adobe_workfront",
	"aircall",
	"airfocus",
	"backstage",
	"beezup",
	"bitwarden",
	"box",
	"datadog",
	"duo",
	"fivetran",
	"openai",
}

func TestRetiredStaticLoaderFixturesAreDeterministicCatalogRuntimeInputs(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open repository root: %v", err)
	}
	t.Cleanup(func() {
		_ = repoRoot.Close()
	})
	for _, sourceID := range retiredStaticLoaderFixtureSources {
		t.Run(sourceID, func(t *testing.T) {
			entry, found, err := connectorcatalog.BuiltinEntry(sourceID)
			if err != nil {
				t.Fatalf("BuiltinEntry(%s) error = %v", sourceID, err)
			}
			if !found || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
				t.Fatalf("BuiltinEntry(%s) is not supported by the catalog runtime", sourceID)
			}
			paths, err := filepath.Glob(filepath.Join(root, "sources", sourceID, "testdata", "read_*.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != len(entry.Definition.ResourceFamilies) {
				t.Fatalf("%s read fixture count = %d, want %d runtime families", sourceID, len(paths), len(entry.Definition.ResourceFamilies))
			}
			for _, path := range paths {
				familyID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "read_"), ".json")
				family, found := definitionFamily(entry.Definition, familyID)
				if !found {
					t.Fatalf("fixture family %s/%s is missing from the connector definition", sourceID, familyID)
				}
				relativePath, err := filepath.Rel(root, path)
				if err != nil {
					t.Fatal(err)
				}
				body, err := repoRoot.ReadFile(filepath.ToSlash(relativePath))
				if err != nil {
					t.Fatal(err)
				}
				first, err := ReadDefinitionFixture(t.Context(), entry.Definition, familyID, body)
				if err != nil {
					t.Fatalf("ReadDefinitionFixture(%s/%s) error = %v", sourceID, familyID, err)
				}
				second, err := ReadDefinitionFixture(t.Context(), entry.Definition, familyID, body)
				if err != nil {
					t.Fatalf("repeat ReadDefinitionFixture(%s/%s) error = %v", sourceID, familyID, err)
				}
				if !reflect.DeepEqual(first, second) {
					t.Fatalf("%s/%s catalog fixture output is nondeterministic: %#v != %#v", sourceID, familyID, first, second)
				}
				if first.EventCount == 0 || first.EventCount != len(first.EventKinds) || first.EventCount != len(first.SchemaRefs) {
					t.Fatalf("%s/%s fixture result = %#v, want nonempty contract-complete events", sourceID, familyID, first)
				}
				wantKind := familyEventKind(sourceID, family)
				for index := range first.EventKinds {
					if first.EventKinds[index] != wantKind || first.SchemaRefs[index] != family.Event.SchemaRef {
						t.Fatalf("%s/%s event %d contract = %q/%q, want %q/%q", sourceID, familyID, index, first.EventKinds[index], first.SchemaRefs[index], wantKind, family.Event.SchemaRef)
					}
				}
			}
		})
	}
}

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
