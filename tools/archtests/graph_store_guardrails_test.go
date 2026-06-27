package archtests

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var forbiddenGraphBackendMarkers = []string{
	"arango",
	"cayley",
	"dgraph",
	"gremlin",
	"janusgraph",
	"kuzu",
	"memgraph",
	"nebula",
}

var forbiddenGraphBackendEnvMarkers = []string{
	"CEREBRO_GRAPH_BACKEND",
	"CEREBRO_DGRAPH_",
	"CEREBRO_ARANGO_",
	"CEREBRO_GREMLIN_",
	"CEREBRO_KUZU_",
	"CEREBRO_MEMGRAPH_",
	"CEREBRO_NEBULA_",
}

func TestGraphStoreImplementationsAreApproved(t *testing.T) {
	root := repoRoot(t)
	graphStoreDir := filepath.Join(root, "internal", "graphstore")
	entries, err := os.ReadDir(graphStoreDir)
	if err != nil {
		t.Fatalf("ReadDir(internal/graphstore): %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() != "neo4j" {
			t.Fatalf("unexpected graph store implementation package %q; only Neo4j is approved as a graph backend", entry.Name())
		}
	}
}

func TestGraphStoreImportsUseApprovedImplementationsOnly(t *testing.T) {
	root := repoRoot(t)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, importSpec := range file.Imports {
			importPath := strings.Trim(importSpec.Path.Value, `"`)
			if strings.HasPrefix(importPath, "github.com/writer/cerebro/internal/graphstore/") &&
				importPath != "github.com/writer/cerebro/internal/graphstore/neo4j" {
				t.Fatalf("%s imports unsupported graph store implementation %q", shortPath(root, path), importPath)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan graph store imports: %v", err)
	}
}

func TestGraphStoreDependenciesUseApprovedBackendsOnly(t *testing.T) {
	root := repoRoot(t)
	for _, name := range []string{"go.mod", "go.sum"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, modulePath := range graphDependencyModulePaths(name, string(body)) {
			lower := strings.ToLower(modulePath)
			for _, marker := range forbiddenGraphBackendMarkers {
				if strings.Contains(lower, marker) {
					t.Fatalf("%s contains forbidden graph backend dependency marker %q in module path %q", name, marker, modulePath)
				}
			}
		}
	}
}

func TestGraphDependencyModulePathsIgnoresChecksums(t *testing.T) {
	paths := graphDependencyModulePaths("go.sum", "golang.org/x/net v0.55.0/go.mod h1:L5U2KuzuChecksumOnly\n")
	if strings.Join(paths, ",") != "golang.org/x/net" {
		t.Fatalf("graphDependencyModulePaths() = %#v, want only module path", paths)
	}
}

func TestGraphDependencyModulePathsIncludesReplacements(t *testing.T) {
	paths := graphDependencyModulePaths("go.mod", `
module github.com/writer/cerebro

require(
	example.com/required v1.0.0
)

replace github.com/kuzudb/kuzu-go => ./internal/teststub
replace( // grouped replacements
	example.com/old v1.2.3 => example.com/new v1.2.4
)
`)
	want := "example.com/required,github.com/kuzudb/kuzu-go,example.com/old,example.com/new"
	if strings.Join(paths, ",") != want {
		t.Fatalf("graphDependencyModulePaths() = %#v, want %s", paths, want)
	}
}

func graphDependencyModulePaths(name string, body string) []string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	paths := []string{}
	inRequireBlock := false
	inReplaceBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if commentStart := strings.Index(line, "//"); commentStart >= 0 {
			line = strings.TrimSpace(line[:commentStart])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if name == "go.sum" {
			paths = append(paths, fields[0])
			continue
		}
		if line == "require (" || line == "require(" {
			inRequireBlock = true
			continue
		}
		if line == "replace (" || line == "replace(" {
			inReplaceBlock = true
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			paths = append(paths, fields[0])
			continue
		}
		if inReplaceBlock {
			if line == ")" {
				inReplaceBlock = false
				continue
			}
			paths = append(paths, replaceModulePaths(fields)...)
			continue
		}
		if fields[0] == "require" && len(fields) >= 2 {
			paths = append(paths, fields[1])
		}
		if fields[0] == "replace" && len(fields) >= 2 {
			paths = append(paths, replaceModulePaths(fields[1:])...)
		}
	}
	return paths
}

func replaceModulePaths(fields []string) []string {
	paths := []string{}
	if len(fields) == 0 {
		return paths
	}
	paths = append(paths, fields[0])
	for i, field := range fields {
		if field != "=>" || i+1 >= len(fields) {
			continue
		}
		replacement := fields[i+1]
		if strings.HasPrefix(replacement, ".") || strings.HasPrefix(replacement, "/") {
			return paths
		}
		paths = append(paths, replacement)
		return paths
	}
	return paths
}

func TestGraphStoreProductionEnvVarsUseApprovedBackendsOnly(t *testing.T) {
	root := repoRoot(t)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "docs":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, string(filepath.Separator)+"tools"+string(filepath.Separator)+"archtests"+string(filepath.Separator)) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range forbiddenGraphBackendEnvMarkers {
			if bytes.Contains(body, []byte(marker)) {
				if allowedLegacyGraphBackendEnvRejection(root, path, marker, body) {
					continue
				}
				t.Fatalf("%s contains forbidden graph backend env var marker %q", shortPath(root, path), marker)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan graph store env vars: %v", err)
	}
}

func allowedLegacyGraphBackendEnvRejection(root string, path string, marker string, body []byte) bool {
	return marker == "CEREBRO_KUZU_" &&
		shortPath(root, path) == filepath.Join("internal", "config", "config.go") &&
		bytes.Contains(body, []byte("CEREBRO_KUZU_PATH is no longer supported"))
}

func TestGraphStoreDriverConstantsAreApproved(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "config", "config.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}
	var graphDrivers []string
	ast.Inspect(file, func(node ast.Node) bool {
		valueSpec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range valueSpec.Names {
			if strings.HasPrefix(name.Name, "GraphStoreDriver") {
				graphDrivers = append(graphDrivers, name.Name)
			}
		}
		return true
	})
	want := []string{"GraphStoreDriverNeo4j"}
	if strings.Join(graphDrivers, ",") != strings.Join(want, ",") {
		t.Fatalf("graph store drivers = %v, want %v", graphDrivers, want)
	}
}

func TestGraphStoreConfigExposesApprovedFields(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "config", "config.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}
	var fields []string
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "GraphStoreConfig" {
			return true
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			t.Fatalf("GraphStoreConfig is not a struct")
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				fields = append(fields, name.Name)
			}
		}
		return false
	})
	want := []string{
		"Driver",
		"Neo4jURI",
		"Neo4jUsername",
		"Neo4jPassword",
		"Neo4jDatabase",
		"Neo4jQueryTimeout",
		"Neo4jProjectionBatchSize",
		"Neo4jProjectionWriteConcurrency",
	}
	if strings.Join(fields, ",") != strings.Join(want, ",") {
		t.Fatalf("GraphStoreConfig fields = %v, want exactly %v", fields, want)
	}
}

func shortPath(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
