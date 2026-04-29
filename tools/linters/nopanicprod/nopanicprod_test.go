package nopanicprod_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/nopanicprod"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), nopanicprod.Analyzer, "a", "panicsafe")
}
