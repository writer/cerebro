package noenvoutsidecmd

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid os.Getenv / os.LookupEnv outside cmd/ and config

Configuration should be read once at the edge, normalized, and threaded through
typed inputs.`

var Analyzer = &analysis.Analyzer{
	Name:     "noenvoutsidecmd",
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
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return
		}
		switch sel.Sel.Name {
		case "Getenv", "LookupEnv":
			pass.Report(analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: "os." + sel.Sel.Name + " is forbidden outside cmd/ and config; thread configuration through typed inputs instead. (see PLAN.md §7 sin #11)",
			})
		}
	})
	return nil, nil
}

func fileAllowed(pass *analysis.Pass, pos token.Pos) bool {
	return isTestFile(pass, pos) || isCmdFile(pass, pos) || isConfigPackage(pass)
}

func isCmdFile(pass *analysis.Pass, pos token.Pos) bool {
	name := filepath.ToSlash(pass.Fset.Position(pos).Filename)
	return strings.Contains(name, "/cmd/") || strings.HasPrefix(name, "cmd/")
}

func isConfigPackage(pass *analysis.Pass) bool {
	path := strings.TrimSpace(pass.Pkg.Path())
	return path == "config" || strings.HasSuffix(path, "/config")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
