package noinmemorydb

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid embedded or in-memory database usage in production code

The rewrite uses durable external stores only; test-only SQLite is fine, but it
must never leak into non-test builds.`

var embeddedDBImports = map[string]bool{
	"github.com/glebarez/sqlite":  true,
	"github.com/mattn/go-sqlite3": true,
	"modernc.org/sqlite":          true,
	"zombiezen.com/go/sqlite":     true,
}

var Analyzer = &analysis.Analyzer{
	Name:     "noinmemorydb",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	reported := map[token.Pos]struct{}{}
	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err == nil && embeddedDBImports[path] {
				report(pass, reported, spec.Pos(), spec.End())
			}
		}
	}

	// Pre-pass: collect variables that alias database/sql.Open / OpenDB so later calls through
	// the alias (e.g. `open := sql.Open; open("sqlite", ...)`) still trip the analyzer.
	sqlAliases := collectSQLOpenAliases(pass)

	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		if isTestFile(pass, call.Pos()) {
			return
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			if (ident.Name == "Open" || ident.Name == "OpenDB") && len(call.Args) > 0 && isDatabaseSQLFunc(pass, ident) && isSQLiteDriverLiteral(pass, call.Args[0]) {
				report(pass, reported, call.Args[0].Pos(), call.Args[0].End())
			}
			if obj, ok := pass.TypesInfo.Uses[ident].(*types.Var); ok {
				if _, aliased := sqlAliases[obj]; aliased && len(call.Args) > 0 && isSQLiteDriverLiteral(pass, call.Args[0]) {
					report(pass, reported, call.Args[0].Pos(), call.Args[0].End())
				}
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if isEmbeddedDBPackageSelector(pass, sel) {
				report(pass, reported, call.Pos(), call.End())
			}
			if (sel.Sel.Name == "Open" || sel.Sel.Name == "OpenDB") && len(call.Args) > 0 && isDatabaseSQLSelector(pass, sel) && isSQLiteDriverLiteral(pass, call.Args[0]) {
				report(pass, reported, call.Args[0].Pos(), call.Args[0].End())
			}
		}
		for _, arg := range call.Args {
			if isInMemoryLiteral(pass, arg) {
				report(pass, reported, arg.Pos(), arg.End())
			}
		}
	})
	return nil, nil
}

// collectSQLOpenAliases scans the pass for variable declarations and short var assignments whose
// right-hand side is `database/sql.Open` or `database/sql.OpenDB`, returning the set of variable
// objects that alias those functions. This lets the analyzer detect indirect calls through the
// alias (e.g. `open := sql.Open; open("sqlite", ...)`).
func collectSQLOpenAliases(pass *analysis.Pass) map[types.Object]struct{} {
	aliases := map[types.Object]struct{}{}
	addIfSQLOpen := func(lhs ast.Expr, rhs ast.Expr) {
		if !isSQLOpenReference(pass, rhs) {
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
					addIfSQLOpen(decl.Lhs[i], decl.Rhs[i])
				}
			case *ast.ValueSpec:
				if len(decl.Names) != len(decl.Values) {
					return true
				}
				for i := range decl.Values {
					addIfSQLOpen(decl.Names[i], decl.Values[i])
				}
			}
			return true
		})
	}
	return aliases
}

func isSQLOpenReference(pass *analysis.Pass, expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		return (v.Sel.Name == "Open" || v.Sel.Name == "OpenDB") && isDatabaseSQLSelector(pass, v)
	case *ast.Ident:
		if v.Name != "Open" && v.Name != "OpenDB" {
			return false
		}
		return isDatabaseSQLFunc(pass, v)
	}
	return false
}

func isEmbeddedDBPackageSelector(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := pass.TypesInfo.Uses[ident].(*types.PkgName)
	return ok && pkgName.Imported() != nil && embeddedDBImports[pkgName.Imported().Path()]
}

func isDatabaseSQLSelector(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := pass.TypesInfo.Uses[ident].(*types.PkgName)
	return ok && pkgName.Imported() != nil && pkgName.Imported().Path() == "database/sql"
}

func isDatabaseSQLFunc(pass *analysis.Pass, ident *ast.Ident) bool {
	fn, ok := pass.TypesInfo.Uses[ident].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "database/sql"
}

func report(pass *analysis.Pass, reported map[token.Pos]struct{}, pos, end token.Pos) {
	if _, ok := reported[pos]; ok {
		return
	}
	reported[pos] = struct{}{}
	pass.Report(analysis.Diagnostic{
		Pos:     pos,
		End:     end,
		Message: "embedded or in-memory database usage is forbidden in production code; use durable external stores instead. (see PLAN.md §7 sin #10)",
	})
}

func isSQLiteDriverLiteral(pass *analysis.Pass, expr ast.Expr) bool {
	value, ok := stringValue(pass, expr)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sqlite", "sqlite3":
		return true
	default:
		return false
	}
}

func isInMemoryLiteral(pass *analysis.Pass, expr ast.Expr) bool {
	value, ok := stringValue(pass, expr)
	if !ok {
		return false
	}
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, ":memory:") || strings.Contains(value, "mode=memory")
}

func stringValue(pass *analysis.Pass, expr ast.Expr) (string, bool) {
	if pass != nil && pass.TypesInfo != nil {
		if value := pass.TypesInfo.Types[expr].Value; value != nil && value.Kind() == constant.String {
			return constant.StringVal(value), true
		}
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
