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

	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		if isTestFile(pass, call.Pos()) {
			return
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
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

func isDatabaseSQLSelector(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := pass.TypesInfo.Uses[ident].(*types.PkgName)
	return ok && pkgName.Imported() != nil && pkgName.Imported().Path() == "database/sql"
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
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "", false
		}
		return value, true
	}
	if pass != nil {
		if tv, ok := pass.TypesInfo.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), true
		}
	}
	return "", false
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
