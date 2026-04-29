// Package nosleep forbids time.Sleep and time.After outside tests.
//
// Sleep and After are almost always a symptom of a missing contract:
// waiting for a lifecycle event, retrying a flaky dependency, throttling
// the agent-y part of the system. Each case has a better, testable
// primitive — an explicit context, an errgroup, a backoff from the
// `runtime/backoff` package, or a subscription.
//
// Sin #4 in PLAN.md §7.
package nosleep

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const doc = `forbid time.Sleep / time.After outside tests and runtime/backoff

Use context deadlines, errgroups, channels, or the backoff package.`

// Packages that may legitimately use time.Sleep/After. Matched as a
// suffix against the package import path, e.g. "runtime/backoff"
// matches "github.com/writer/cerebro/runtime/backoff".
var allowedPackageSuffixes = []string{
	"/runtime/backoff",
	"/runtime/panicsafe",
}

var Analyzer = &analysis.Analyzer{
	Name: "nosleep",
	Doc:  doc,
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	if packageAllowed(pass.Pkg.Path()) {
		return nil, nil
	}
	for _, f := range pass.Files {
		fname := pass.Fset.Position(f.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "time" {
				return true
			}
			switch sel.Sel.Name {
			case "Sleep":
				pass.Report(analysis.Diagnostic{
					Pos:     call.Pos(),
					End:     call.End(),
					Message: "time.Sleep is forbidden outside tests; use a context deadline, an errgroup, or runtime/backoff. (see PLAN.md §7 sin #4)",
				})
			case "After":
				pass.Report(analysis.Diagnostic{
					Pos:     call.Pos(),
					End:     call.End(),
					Message: "time.After leaks timers; use ctx.Done() with a deadline, or time.NewTimer. (see PLAN.md §7 sin #4)",
				})
			}
			return true
		})
	}
	return nil, nil
}

func packageAllowed(path string) bool {
	for _, suffix := range allowedPackageSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
