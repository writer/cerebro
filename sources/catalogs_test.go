package sourcecatalogs

import (
	"slices"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestBuiltinCatalogLoadsPortableCatalogWithoutProviderPackage(t *testing.T) {
	payload, err := BuiltinCatalog("docker_hub")
	if err != nil {
		t.Fatalf("BuiltinCatalog() error = %v", err)
	}
	if !strings.Contains(string(payload), "id: docker_hub") {
		t.Fatalf("BuiltinCatalog() did not return the Docker Hub catalog")
	}
}

func TestBuiltinCatalogCorpusIsCompleteUniqueAndDeterministic(t *testing.T) {
	ids, err := BuiltinCatalogKeys()
	if err != nil {
		t.Fatalf("BuiltinCatalogKeys() error = %v", err)
	}
	if len(ids) == 0 || !slices.IsSorted(ids) {
		t.Fatalf("BuiltinCatalogKeys() = %#v", ids)
	}
	seenCatalogIDs := make(map[string]string, len(ids))
	for _, sourceID := range ids {
		payload, err := BuiltinCatalog(sourceID)
		if err != nil {
			t.Fatalf("BuiltinCatalog(%q) error = %v", sourceID, err)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			t.Fatalf("LoadSourceCatalog(%q) error = %v", sourceID, err)
		}
		if catalog.Spec == nil || catalog.Spec.Id == "" {
			t.Fatalf("catalog path %q contains an empty source id", sourceID)
		}
		if prior, ok := seenCatalogIDs[catalog.Spec.Id]; ok {
			t.Fatalf("catalog id %q conflicts between %q and %q", catalog.Spec.Id, prior, sourceID)
		}
		seenCatalogIDs[catalog.Spec.Id] = sourceID
	}
	second, err := BuiltinCatalogKeys()
	if err != nil {
		t.Fatalf("second BuiltinCatalogKeys() error = %v", err)
	}
	if !slices.Equal(ids, second) {
		t.Fatalf("BuiltinCatalogKeys() is not deterministic")
	}
}

func TestBuiltinCatalogRejectsInvalidOrUnknownSource(t *testing.T) {
	for _, sourceID := range []string{"../docker_hub", "missing_source"} {
		if _, err := BuiltinCatalog(sourceID); err == nil {
			t.Fatalf("BuiltinCatalog(%q) error = nil", sourceID)
		}
	}
}
