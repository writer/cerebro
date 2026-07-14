// Command sourceproofcheck verifies a generated source against its manifest,
// proof bundle, current outputs, and provider contract lock.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/sourcegen"
)

func main() {
	var sourceID string
	var outputDir string
	var providerContractLock string
	flag.StringVar(&sourceID, "source-id", "", "generated source id (required)")
	flag.StringVar(&outputDir, "output-dir", ".", "repository or generation output root")
	flag.StringVar(&providerContractLock, "provider-contract-lock", "", "provider contract lock path; defaults to the generated source directory")
	flag.Parse()
	if strings.TrimSpace(sourceID) == "" {
		fail(fmt.Errorf("-source-id is required"))
	}
	result, err := sourcegen.VerifyProofBundle(sourcegen.ProofVerificationRequest{
		SourceID:             sourceID,
		OutputDir:            outputDir,
		ProviderContractLock: providerContractLock,
	})
	if err != nil {
		fail(err)
	}
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(payload))
	if result.Status == sourcegen.VerificationStatusBlocked {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
