// Package noerrstringmatch forbids matching on an error's string
// representation:
//
//	strings.Contains(err.Error(), "not found")
//	strings.HasPrefix(err.Error(), "…")
//	err.Error() == "…"
//
// These patterns are fragile: upstream rewording silently breaks
// control flow, and they skip typed-error tooling (errors.Is/As).
//
// Sin #5 in PLAN.md §7.
package noerrstringmatch

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid matching on err.Error()'s content

Use errors.Is / errors.As with typed sentinels.`

var Analyzer = &analysis.Analyzer{
	Name:     "noerrstringmatch",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// stringsFuncs names the strings.* calls we forbid when applied to
// err.Error().
var stringsFuncs = map[string]bool{
	"Contains":     true,
	"HasPrefix":    true,
	"HasSuffix":    true,
	"Index":        true,
	"Count":        true,
	"EqualFold":    true,
	"ContainsAny":  true,
	"IndexAny":     true,
	"LastIndex":    true,
	"LastIndexAny": true,
	"ContainsRune": true,
	"IndexRune":    true,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
		(*ast.BinaryExpr)(nil),
	}

	ins.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.CallExpr:
			checkCall(pass, node)
		case *ast.BinaryExpr:
			checkBinary(pass, node)
		}
	})
	return nil, nil
}

func checkCall(pass *analysis.Pass, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	if ident.Name != "strings" {
		return
	}
	if !stringsFuncs[sel.Sel.Name] {
		return
	}
	for _, arg := range call.Args {
		if isErrDotError(pass, arg) {
			pass.Report(analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: "matching on err.Error() is forbidden; use errors.Is / errors.As with a typed sentinel. (see PLAN.md §7 sin #5)",
			})
			return
		}
	}
}

func checkBinary(pass *analysis.Pass, bin *ast.BinaryExpr) {
	switch bin.Op.String() {
	case "==", "!=":
	default:
		return
	}
	if isErrDotError(pass, bin.X) || isErrDotError(pass, bin.Y) {
		pass.Report(analysis.Diagnostic{
			Pos:     bin.Pos(),
			End:     bin.End(),
			Message: "comparing err.Error() to a string is forbidden; use errors.Is / errors.As with a typed sentinel. (see PLAN.md §7 sin #5)",
		})
	}
}

// isErrDotError returns true if expr is `x.Error()` where x has a type
// that implements the error interface.
func isErrDotError(pass *analysis.Pass, expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name != "Error" {
		return false
	}
	// receiver must implement `error` (have method Error() string).
	t := pass.TypesInfo.TypeOf(sel.X)
	if t == nil {
		return false
	}
	return implementsError(t)
}

func implementsError(t types.Type) bool {
	// `error` is a predeclared interface: has exactly one method
	// `Error() string`. We check structurally to avoid importing go/types'
	// Universe and dragging in more surface than we need.
	ms := types.NewMethodSet(t)
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i).Obj()
		if m.Name() != "Error" {
			continue
		}
		sig, ok := m.Type().(*types.Signature)
		if !ok {
			continue
		}
		if sig.Params().Len() == 0 && sig.Results().Len() == 1 {
			rt := sig.Results().At(0).Type()
			if basic, ok := rt.(*types.Basic); ok && basic.Kind() == types.String {
				return true
			}
		}
	}
	// Pointer receivers: check the pointer's underlying method set too.
	if ptr, ok := t.(*types.Pointer); ok {
		return implementsError(ptr.Elem())
	}
	return false
}
