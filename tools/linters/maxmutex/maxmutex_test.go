package maxmutex_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/maxmutex"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), maxmutex.Analyzer, "a")
}
