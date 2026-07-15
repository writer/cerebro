// Command sourcegenreprocheck proves sourcegen output invariance and mutation
// rejection against minimal connector definitions.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/writer/cerebro/internal/sourcegen/reproproof"
)

func main() {
	jsonOutput := flag.Bool("json", false, "write the complete reproducibility proof report")
	flag.Parse()
	root, err := os.MkdirTemp("", "cerebro-sourcegen-repro-proof-")
	if err != nil {
		fail(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	report, err := reproproof.Prove(root)
	if err != nil {
		fail(err)
	}
	if *jsonOutput {
		payload, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fail(err)
		}
		fmt.Println(string(payload))
	} else {
		fmt.Printf("sourcegen-repro: cases=%d passed=%d failed=%d\n", len(report.Cases), report.Passed, report.Failed)
		for _, proof := range report.Cases {
			if proof.Status == reproproof.ProofStatusFailed {
				fmt.Printf("failed case=%s transformation=%q error=%q\n", proof.ID, proof.Transformation, proof.Error)
			}
		}
	}
	if report.Failed != 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
