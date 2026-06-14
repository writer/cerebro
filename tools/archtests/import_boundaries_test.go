package archtests

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceConnectorsStayInSourceLayer(t *testing.T) {
	root := repoRoot(t)
	forEachProductionGoFile(t, filepath.Join(root, "sources"), func(path string, imports []string) {
		if strings.Contains(path, string(filepath.Separator)+"sources"+string(filepath.Separator)+"internal"+string(filepath.Separator)) {
			return
		}
		for _, importPath := range imports {
			for _, forbidden := range []string{
				"github.com/writer/cerebro/internal/bootstrap",
				"github.com/writer/cerebro/internal/statestore",
				"github.com/writer/cerebro/internal/graphstore",
				"github.com/writer/cerebro/internal/findings",
				"github.com/writer/cerebro/internal/sourceprojection",
				"github.com/writer/cerebro/internal/appendlog",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("%s imports %s; source connectors must stay in the source layer", shortPath(root, path), importPath)
				}
			}
		}
	})
}

func TestSourcePackagesAreOnlyRegisteredBySourceRegistry(t *testing.T) {
	root := repoRoot(t)
	forEachProductionGoFile(t, root, func(path string, imports []string) {
		rel := filepath.ToSlash(shortPath(root, path))
		if rel == "internal/sourceregistry/registry.go" || strings.HasPrefix(rel, "sources/") {
			return
		}
		for _, importPath := range imports {
			if strings.HasPrefix(importPath, "github.com/writer/cerebro/sources/") &&
				!strings.HasPrefix(importPath, "github.com/writer/cerebro/sources/internal/") {
				t.Fatalf("%s imports %s; concrete source connectors should be registered only by internal/sourceregistry", rel, importPath)
			}
		}
	})
}

func TestBootstrapDoesNotFlowBackIntoInternalServices(t *testing.T) {
	root := repoRoot(t)
	forEachProductionGoFile(t, root, func(path string, imports []string) {
		rel := filepath.ToSlash(shortPath(root, path))
		if strings.HasPrefix(rel, "cmd/cerebro/") {
			return
		}
		for _, importPath := range imports {
			if importPath == "github.com/writer/cerebro/internal/bootstrap" ||
				strings.HasPrefix(importPath, "github.com/writer/cerebro/internal/bootstrap/") {
				t.Fatalf("%s imports %s; bootstrap must remain an outer wiring layer", rel, importPath)
			}
		}
	})
}

func TestConcreteStoresStayAtWiringBoundary(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		"cmd/cerebro/closeout_production.go": true,
		"cmd/cerebro/vulndb.go":              true,
		"internal/bootstrap/dependencies.go": true,
	}
	forEachProductionGoFile(t, root, func(path string, imports []string) {
		rel := filepath.ToSlash(shortPath(root, path))
		if allowed[rel] {
			return
		}
		for _, importPath := range imports {
			for _, concrete := range []string{
				"github.com/writer/cerebro/internal/statestore/postgres",
				"github.com/writer/cerebro/internal/graphstore/neo4j",
				"github.com/writer/cerebro/internal/appendlog/jetstream",
			} {
				if importPath == concrete || strings.HasPrefix(importPath, concrete+"/") {
					t.Fatalf("%s imports %s; concrete stores should stay at the wiring boundary", rel, importPath)
				}
			}
		}
	})
}

func TestPlatformSecurityNamespaceBoundary(t *testing.T) {
	root := repoRoot(t)
	routes, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "routes.go"))
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	for _, forbidden := range []string{"/platform/security", "/security/platform"} {
		if strings.Contains(string(routes), forbidden) {
			t.Fatalf("routes.go contains %q; platform and security namespaces must stay separate", forbidden)
		}
	}
}

func forEachProductionGoFile(t *testing.T, root string, visit func(path string, imports []string)) {
	t.Helper()
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "gen", "tmp", "testdata":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		imports := make([]string, 0, len(file.Imports))
		for _, importSpec := range file.Imports {
			imports = append(imports, strings.Trim(importSpec.Path.Value, `"`))
		}
		visit(path, imports)
		return nil
	}); err != nil {
		t.Fatalf("scan imports under %s: %v", root, err)
	}
}
