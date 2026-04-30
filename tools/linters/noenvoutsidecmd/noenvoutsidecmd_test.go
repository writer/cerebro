package noenvoutsidecmd_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/noenvoutsidecmd"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), noenvoutsidecmd.Analyzer, "a", "cmd/tool", "config")
}
