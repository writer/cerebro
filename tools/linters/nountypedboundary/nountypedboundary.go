// Package nountypedboundary forbids exported functions and methods
// from accepting or returning untyped bags (map[string]any,
// interface{}, []any), which are how schemas and types erode across
// the codebase.
//
// Sin #6 in PLAN.md §7.
package nountypedboundary

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid map[string]any / interface{} / []any in exported function signatures

Define a typed message. Every boundary is a contract.`

const allowMarker = "cerebro:lint:allow nountypedboundary"

var Analyzer = &analysis.Analyzer{
	Name:     "nountypedboundary",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.FuncDecl)(nil)}

	ins.Preorder(nodeFilter, func(n ast.Node) {
		fd := n.(*ast.FuncDecl)
		if fd.Name == nil || !fd.Name.IsExported() {
			return
		}
		if hasAllowMarker(fd.Doc) {
			return
		}
		// Skip test files.
		if strings.HasSuffix(pass.Fset.Position(fd.Pos()).Filename, "_test.go") {
			return
		}
		// Skip methods on unexported types (they can't be called from outside).
		if fd.Recv != nil && !receiverExported(fd.Recv) {
			return
		}

		inspectFields(pass, fd, fd.Type.Params, "parameter")
		if fd.Type.Results != nil {
			inspectFields(pass, fd, fd.Type.Results, "return value")
		}
	})
	return nil, nil
}

func receiverExported(recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) == 0 {
		return false
	}
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	// Handle generic receivers: T[X] -> take T.
	if idxl, ok := t.(*ast.IndexListExpr); ok {
		t = idxl.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok {
		t = idx.X
	}
	ident, ok := t.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.IsExported()
}

func inspectFields(pass *analysis.Pass, fd *ast.FuncDecl, list *ast.FieldList, kind string) {
	if list == nil {
		return
	}
	for _, field := range list.List {
		if reason, bad := untypedShape(field.Type); bad {
			pass.Report(analysis.Diagnostic{
				Pos:     field.Type.Pos(),
				End:     field.Type.End(),
				Message: "exported func " + fd.Name.Name + " has " + kind + " of forbidden untyped shape (" + reason + "); declare a named struct or interface. (see PLAN.md §7 sin #6)",
			})
		}
	}
}

// untypedShape returns (reason, true) if expr is one of:
//
//	interface{}           -> "interface{}"
//	any                   -> "any"
//	map[string]interface{}-> "map[string]any"
//	map[string]any        -> "map[string]any"
//	[]interface{}         -> "[]any"
//	[]any                 -> "[]any"
func untypedShape(expr ast.Expr) (string, bool) {
	switch t := expr.(type) {
	case *ast.InterfaceType:
		// Only the empty interface is forbidden; named interfaces are fine.
		if t.Methods == nil || len(t.Methods.List) == 0 {
			return "interface{}", true
		}
	case *ast.Ident:
		if t.Name == "any" {
			return "any", true
		}
	case *ast.MapType:
		if isAnyExpr(t.Value) {
			return "map[...]any", true
		}
	case *ast.ArrayType:
		if isAnyExpr(t.Elt) {
			return "[]any", true
		}
	case *ast.StarExpr:
		return untypedShape(t.X)
	}
	return "", false
}

func isAnyExpr(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.InterfaceType:
		return t.Methods == nil || len(t.Methods.List) == 0
	case *ast.Ident:
		return t.Name == "any"
	}
	return false
}

func hasAllowMarker(g *ast.CommentGroup) bool {
	if g == nil {
		return false
	}
	for _, c := range g.List {
		if strings.Contains(c.Text, allowMarker) {
			return true
		}
	}
	return false
}
