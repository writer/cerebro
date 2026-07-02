package noidentityemail_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/writer/cerebro/tools/linters/noidentityemail"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), noidentityemail.Analyzer, "github.com/writer/cerebro/internal/mcpoauth")
}
