package nopanicprod

import (
	"go/ast"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const doc = `forbid panic outside tests, init, and panicsafe

Production code should return typed errors or explicitly terminate at the edge.`

var Analyzer = &analysis.Analyzer{
	Name: "nopanicprod",
	Doc:  doc,
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	if packageAllowed(pass.Pkg.Path()) {
		return nil, nil
	}
	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				return false
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "panic" {
				return true
			}
			if enclosingFuncName(stack) == "init" {
				return true
			}
			pass.Report(analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: "panic is forbidden outside tests, init, and panicsafe; return an error or terminate at the edge instead. (see PLAN.md §7 sin #9)",
			})
			return true
		})
	}
	return nil, nil
}

func enclosingFuncName(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		decl, ok := stack[i].(*ast.FuncDecl)
		if ok && decl.Name != nil {
			return decl.Name.Name
		}
	}
	return ""
}

func packageAllowed(path string) bool {
	path = strings.TrimSpace(path)
	return path == "panicsafe" || strings.HasSuffix(path, "/panicsafe")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
