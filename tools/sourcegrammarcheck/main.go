// Command sourcegrammarcheck proves that every declared generic connector
// grammar feature can be rendered by sourcegen.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen/grammarproof"
)

func main() {
	jsonOut := flag.String("json-out", "", "write the grammar proof report to this path")
	flag.Parse()

	root, err := os.MkdirTemp("", "cerebro-sourcegen-grammar-proof-")
	if err != nil {
		fail(err)
	}
	defer func() { _ = os.RemoveAll(root) }()

	report, err := grammarproof.Prove(root, connectordefinitions.DefaultGrammar())
	if err != nil {
		fail(err)
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail(err)
	}
	payload = append(payload, '\n')
	if *jsonOut != "" {
		if err := os.WriteFile(*jsonOut, payload, 0o600); err != nil {
			fail(err)
		}
	}
	fmt.Printf("sourcegrammarcheck: grammar=%s declared=%d proven=%d failed=%d pairwise=%d interactions_proven=%d interactions_failed=%d\n", report.GrammarVersion, report.DeclaredFeatures, report.ProvenFeatures, report.FailedFeatures, report.PairwiseWitnesses, report.ProvenInteractions, report.FailedInteractions)
	if *jsonOut == "" {
		fmt.Print(string(payload))
	}
	if report.FailedFeatures > 0 || report.FailedInteractions > 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sourcegrammarcheck:", err)
	os.Exit(1)
}
