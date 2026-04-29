package nobackgroundctx

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid context.Background / context.TODO outside cmd/ and tests

Contexts should flow from the caller so cancellation and deadlines remain
visible at the boundary.`

var Analyzer = &analysis.Analyzer{
	Name:     "nobackgroundctx",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		if fileAllowed(pass, call.Pos()) {
			return
		}
		report := func(name string) {
			pass.Report(analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: "context." + name + " is forbidden outside cmd/ and tests; accept a context from the caller instead. (see PLAN.md §7 sin #12)",
			})
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			pkgIdent, ok := fun.X.(*ast.Ident)
			if !ok {
				return
			}
			pkgName, ok := pass.TypesInfo.Uses[pkgIdent].(*types.PkgName)
			if !ok || pkgName.Imported() == nil || pkgName.Imported().Path() != "context" {
				return
			}
			switch fun.Sel.Name {
			case "Background", "TODO":
				report(fun.Sel.Name)
			}
		case *ast.Ident:
			fn, ok := pass.TypesInfo.Uses[fun].(*types.Func)
			if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "context" {
				return
			}
			switch fn.Name() {
			case "Background", "TODO":
				report(fn.Name())
			}
		}
	})
	return nil, nil
}

func fileAllowed(pass *analysis.Pass, pos token.Pos) bool {
	return isTestFile(pass, pos) || isCmdFile(pass, pos)
}

func isCmdFile(pass *analysis.Pass, pos token.Pos) bool {
	name := filepath.ToSlash(pass.Fset.Position(pos).Filename)
	return strings.Contains(name, "/cmd/") || strings.HasPrefix(name, "cmd/")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
