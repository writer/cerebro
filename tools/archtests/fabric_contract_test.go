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

func TestSourceProjectionRelationConstantsUseFabricContract(t *testing.T) {
	root := repoRoot(t)
	sourceProjectionDir := filepath.Join(root, "internal", "sourceprojection")
	if err := filepath.WalkDir(sourceProjectionDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST {
				return true
			}
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valueSpec.Names {
					if !strings.HasPrefix(name.Name, "relation") {
						continue
					}
					if filepath.Base(path) != "projector.go" {
						t.Fatalf("%s defines %s; sourceprojection relation constants must live in projector.go and alias internal/fabriccontract", path, name.Name)
					}
					if i >= len(valueSpec.Values) || !selectorFromPackage(valueSpec.Values[i], "fabriccontract") {
						t.Fatalf("%s defines %s without aliasing internal/fabriccontract", path, name.Name)
					}
				}
			}
			return true
		})
		return nil
	}); err != nil {
		t.Fatalf("walk sourceprojection: %v", err)
	}
}

func TestWorkflowRelationConstantsUseFabricContract(t *testing.T) {
	root := repoRoot(t)
	for _, relativePath := range []string{
		filepath.Join("internal", "knowledge", "service.go"),
		filepath.Join("internal", "workflowprojection", "projector.go"),
	} {
		path := filepath.Join(root, relativePath)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST {
				return true
			}
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valueSpec.Names {
					if !strings.HasPrefix(name.Name, "relation") {
						continue
					}
					if i >= len(valueSpec.Values) || !selectorFromPackage(valueSpec.Values[i], "fabriccontract") {
						t.Fatalf("%s defines %s without aliasing internal/fabriccontract", path, name.Name)
					}
				}
			}
			return true
		})
	}
}

func selectorFromPackage(expr ast.Expr, packageName string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == packageName
}
