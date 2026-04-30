package nopanicprod

import (
	"go/ast"
	"go/token"
	"go/types"
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
	panicAliases := collectPanicAliases(pass)
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
			if !isPanicCall(pass, call) && !isPanicAliasCall(pass, call, panicAliases) {
				return true
			}
			if enclosingIsPackageInit(stack) {
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

// collectPanicAliases returns variables in this package that alias `log.Panic`/`log.Panicf`/`log.Panicln`
// or any logger method named `Panic`/`Panicf`/`Panicln`. This catches indirect calls such as
// `p := log.Panicf; p("...")` that would otherwise slip past the analyzer.
func collectPanicAliases(pass *analysis.Pass) map[types.Object]struct{} {
	aliases := map[types.Object]struct{}{}
	addAlias := func(lhs ast.Expr, rhs ast.Expr) {
		if !isPanicReference(pass, rhs) {
			return
		}
		ident, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		obj := pass.TypesInfo.Defs[ident]
		if obj == nil {
			obj = pass.TypesInfo.Uses[ident]
		}
		if obj == nil {
			return
		}
		aliases[obj] = struct{}{}
	}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.AssignStmt:
				if len(decl.Lhs) != len(decl.Rhs) {
					return true
				}
				for i := range decl.Rhs {
					addAlias(decl.Lhs[i], decl.Rhs[i])
				}
			case *ast.ValueSpec:
				if len(decl.Names) != len(decl.Values) {
					return true
				}
				for i := range decl.Values {
					addAlias(decl.Names[i], decl.Values[i])
				}
			}
			return true
		})
	}
	return aliases
}

func isPanicReference(pass *analysis.Pass, expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		switch v.Sel.Name {
		case "Panic", "Panicf", "Panicln":
		default:
			return false
		}
		fn, ok := pass.TypesInfo.Uses[v.Sel].(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == "log"
	case *ast.Ident:
		switch v.Name {
		case "Panic", "Panicf", "Panicln":
		default:
			return false
		}
		fn, ok := pass.TypesInfo.Uses[v].(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == "log"
	}
	return false
}

func isPanicAliasCall(pass *analysis.Pass, call *ast.CallExpr, aliases map[types.Object]struct{}) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	obj := pass.TypesInfo.Uses[ident]
	if obj == nil {
		return false
	}
	_, ok = aliases[obj]
	return ok
}

func isPanicCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if fun.Name == "panic" {
			return true
		}
		fn, ok := pass.TypesInfo.Uses[fun].(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "log" {
			return false
		}
		switch fn.Name() {
		case "Panic", "Panicf", "Panicln":
			return true
		default:
			return false
		}
	case *ast.SelectorExpr:
		switch fun.Sel.Name {
		case "Panic", "Panicf", "Panicln":
		default:
			return false
		}
		fn, ok := pass.TypesInfo.Uses[fun.Sel].(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == "log"
	default:
		return false
	}
}

func enclosingIsPackageInit(stack []ast.Node) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch fn := stack[i].(type) {
		case *ast.FuncLit:
			return false
		case *ast.FuncDecl:
			if fn.Name != nil {
				return fn.Recv == nil && fn.Name.Name == "init"
			}
		}
	}
	return false
}

func packageAllowed(path string) bool {
	path = strings.TrimSpace(path)
	return path == "panicsafe" || strings.HasSuffix(path, "/panicsafe")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
