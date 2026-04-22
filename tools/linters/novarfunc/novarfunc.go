// Package novarfunc forbids package-level function values bound to
// a var so that they can be monkey-patched from tests.
//
//	var doThing = func(...) error { ... }
//
// This pattern is the single most common source of spooky action at
// a distance in the existing Cerebro codebase. Test seams must use
// explicit dependency injection (a parameter or a field on a struct
// that a test can replace) instead.
//
// Sin #3 in PLAN.md §7.
package novarfunc

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid package-level var X = func(...) ...

Use an explicit dependency-injection parameter or a field on a struct
for test seams. Overridable package-level function vars make code
ordering, race-freedom, and audit impossible.`

const allowMarker = "cerebro:lint:allow novarfunc"

var Analyzer = &analysis.Analyzer{
	Name:     "novarfunc",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.File)(nil)}

	ins.Preorder(nodeFilter, func(n ast.Node) {
		f := n.(*ast.File)
		if isTestFile(pass, f) {
			return
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok.String() != "var" {
				continue
			}
			if hasAllowMarker(gd.Doc) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if hasAllowMarker(vs.Doc) {
					continue
				}
				if isOverridableFuncSpec(vs) {
					for _, name := range vs.Names {
						pass.Report(analysis.Diagnostic{
							Pos: name.Pos(),
							End: name.End(),
							Message: "package-level var '" + name.Name +
								"' is bound to a function literal; " +
								"use explicit dependency injection instead of a mutable hook. " +
								"(see PLAN.md §7 sin #3)",
						})
					}
				}
			}
		}
	})
	return nil, nil
}

// isOverridableFuncSpec returns true when the ValueSpec is either
//
//	var x = func(...) ... { ... }
//	var x func(...) ...      // declared but assigned-later -> still a hook
//	var x SomeFuncType       // possibly — handled via type name check
func isOverridableFuncSpec(vs *ast.ValueSpec) bool {
	// case: var x = func(...) {...}
	for _, v := range vs.Values {
		if _, ok := v.(*ast.FuncLit); ok {
			return true
		}
	}
	// case: var x func(...)
	if _, ok := vs.Type.(*ast.FuncType); ok {
		return true
	}
	return false
}

func isTestFile(pass *analysis.Pass, f *ast.File) bool {
	if f == nil {
		return false
	}
	name := pass.Fset.Position(f.Pos()).Filename
	return strings.HasSuffix(name, "_test.go")
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
