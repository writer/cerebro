package noinmemorydb_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/noinmemorydb"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), noinmemorydb.Analyzer, "a")
}
