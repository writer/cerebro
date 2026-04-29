package maxfields_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/maxfields"
)

func TestAnalyzer(t *testing.T) {
	// Use the default limit of 24 in testdata.
	analysistest.Run(t, analysistest.TestData(), maxfields.Analyzer, "a")
}
