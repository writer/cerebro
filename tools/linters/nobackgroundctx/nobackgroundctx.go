package nobackgroundctx

import (
	"go/ast"
	"go/token"
	"go/types"
	"path"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
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
	aliases := map[types.Object]string{}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				updateAliases(pass, aliases, node.Names, node.Values)
			case *ast.AssignStmt:
				updateAssignmentAliases(pass, aliases, node)
			case *ast.CallExpr:
				if fileAllowed(pass, node.Pos()) {
					return true
				}
				name, ok := forbiddenContextFunc(pass, aliases, node.Fun)
				if !ok {
					return true
				}
				pass.Report(analysis.Diagnostic{
					Pos:     node.Pos(),
					End:     node.End(),
					Message: "context." + name + " is forbidden outside cmd/ and tests; accept a context from the caller instead. (see PLAN.md §7 sin #12)",
				})
			}
			return true
		})
	}
	return nil, nil
}

func updateAliases(pass *analysis.Pass, aliases map[types.Object]string, names []*ast.Ident, values []ast.Expr) {
	for i, ident := range names {
		if ident == nil || ident.Name == "_" {
			continue
		}
		obj := pass.TypesInfo.ObjectOf(ident)
		if obj == nil {
			continue
		}
		if i < len(values) {
			if name, ok := forbiddenContextFunc(pass, aliases, values[i]); ok {
				aliases[obj] = name
				continue
			}
		}
		delete(aliases, obj)
	}
}

func updateAssignmentAliases(pass *analysis.Pass, aliases map[types.Object]string, assign *ast.AssignStmt) {
	if assign == nil || len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		obj := pass.TypesInfo.ObjectOf(ident)
		if obj == nil {
			continue
		}
		if name, ok := forbiddenContextFunc(pass, aliases, assign.Rhs[i]); ok {
			aliases[obj] = name
			continue
		}
		delete(aliases, obj)
	}
}

func forbiddenContextFunc(pass *analysis.Pass, aliases map[types.Object]string, expr ast.Expr) (string, bool) {
	switch fun := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		pkgIdent, ok := fun.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		pkgName, ok := pass.TypesInfo.Uses[pkgIdent].(*types.PkgName)
		if !ok || pkgName.Imported() == nil || pkgName.Imported().Path() != "context" {
			return "", false
		}
		switch fun.Sel.Name {
		case "Background", "TODO":
			return fun.Sel.Name, true
		default:
			return "", false
		}
	case *ast.Ident:
		if fn, ok := pass.TypesInfo.Uses[fun].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "context" {
			switch fn.Name() {
			case "Background", "TODO":
				return fn.Name(), true
			}
		}
		obj := pass.TypesInfo.ObjectOf(fun)
		if obj == nil {
			return "", false
		}
		name, ok := aliases[obj]
		return name, ok
	default:
		return "", false
	}
}

func fileAllowed(pass *analysis.Pass, pos token.Pos) bool {
	return isTestFile(pass, pos) || isCmdFile(pass, pos)
}

func isCmdFile(pass *analysis.Pass, pos token.Pos) bool {
	_ = pos
	if pass == nil || pass.Pkg == nil {
		return false
	}
	pkgPath := path.Clean(strings.TrimSpace(pass.Pkg.Path()))
	return pkgPath == "cmd" || strings.HasPrefix(pkgPath, "cmd/") || strings.Contains(pkgPath, "/cmd/")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
