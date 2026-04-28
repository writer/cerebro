package archtests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGraphStoreImplementationIsKuzuOnly(t *testing.T) {
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
		if entry.Name() != "kuzu" {
			t.Fatalf("unexpected graph store implementation package %q; Kuzu is the only supported graph backend", entry.Name())
		}
	}
}

func TestGraphStoreImportsUseKuzuImplementationOnly(t *testing.T) {
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
				importPath != "github.com/writer/cerebro/internal/graphstore/kuzu" {
				t.Fatalf("%s imports unsupported graph store implementation %q", shortPath(root, path), importPath)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan graph store imports: %v", err)
	}
}

func TestGraphStoreConfigExposesOnlyKuzuFields(t *testing.T) {
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
	want := []string{"Driver", "KuzuPath"}
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
