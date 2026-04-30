package nobackgroundctx_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/nobackgroundctx"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), nobackgroundctx.Analyzer, "a", "cmd/tool")
}
