// Command cerebrolint is a multichecker binary that runs every
// analyzer in Cerebro's custom linter suite.
//
//	go run ./cerebrolint ../../...
//
// Each analyzer is deliberately small and self-contained; see
// PLAN.md §7 for the full list of architectural invariants it
// enforces.
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/writer/cerebro/tools/linters/maxfields"
	"github.com/writer/cerebro/tools/linters/maxmutex"
	"github.com/writer/cerebro/tools/linters/noerrstringmatch"
	"github.com/writer/cerebro/tools/linters/nosleep"
	"github.com/writer/cerebro/tools/linters/nountypedboundary"
	"github.com/writer/cerebro/tools/linters/novarfunc"
)

func main() {
	multichecker.Main(
		maxmutex.Analyzer,
		maxfields.Analyzer,
		novarfunc.Analyzer,
		nosleep.Analyzer,
		noerrstringmatch.Analyzer,
		nountypedboundary.Analyzer,
	)
}
