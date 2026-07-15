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

func TestComplianceMonitorProjectionIsNotAnApplicationWritePath(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		"internal/compliancemonitor/service.go":   true,
		"internal/compliancemonitor/projector.go": true,
	}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(shortPath(root, path))
		if allowed[rel] {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "ProjectComplianceMonitor" {
				t.Errorf("%s calls ProjectComplianceMonitor; monitor writes must append through internal/compliancemonitor.Service", rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal packages: %v", err)
	}
}
