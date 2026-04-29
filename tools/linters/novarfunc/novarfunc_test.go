package novarfunc_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/novarfunc"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), novarfunc.Analyzer, "a")
}
