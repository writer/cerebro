package archtests

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternalPackagesDoNotStartRawFunctionGoroutines(t *testing.T) {
	root := repoRoot(t)
	internalRoot := filepath.Join(root, "internal")
	var violations []string
	err := filepath.WalkDir(internalRoot, func(fileName string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(fileName, ".go") || strings.HasSuffix(fileName, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, fileName, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			statement, ok := node.(*ast.GoStmt)
			if !ok {
				return true
			}
			if _, rawFunction := statement.Call.Fun.(*ast.FuncLit); rawFunction {
				relative, relErr := filepath.Rel(root, fileName)
				if relErr != nil {
					relative = fileName
				}
				position := fileSet.Position(statement.Pos())
				violations = append(violations, filepath.ToSlash(relative)+":"+fmt.Sprint(position.Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("inspect internal Go files: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf(
			"internal packages start raw function goroutines; use panicsafe.Go:\n- %s",
			strings.Join(violations, "\n- "),
		)
	}
}
