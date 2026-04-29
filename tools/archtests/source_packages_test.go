package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcePackagesHaveCatalogFixturesAndTests(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "sources"))
	if err != nil {
		t.Fatalf("ReadDir(sources): %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceDir := filepath.Join("..", "..", "sources", entry.Name())
		if _, err := os.Stat(filepath.Join(sourceDir, "catalog.yaml")); err != nil {
			t.Fatalf("%s missing catalog.yaml: %v", entry.Name(), err)
		}
		files, err := os.ReadDir(sourceDir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", sourceDir, err)
		}
		hasTest := false
		for _, file := range files {
			if strings.HasSuffix(file.Name(), "_test.go") {
				hasTest = true
				break
			}
		}
		if !hasTest {
			t.Fatalf("%s missing replay/unit test", entry.Name())
		}
		testdata, err := os.ReadDir(filepath.Join(sourceDir, "testdata"))
		if err != nil {
			t.Fatalf("%s missing testdata: %v", entry.Name(), err)
		}
		if len(testdata) == 0 {
			t.Fatalf("%s testdata is empty", entry.Name())
		}
	}
}
