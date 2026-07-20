// Command wasmartifactmanifest generates or verifies the embedded Wasm
// artifact manifest.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/writer/cerebro/internal/wasmartifacts"
)

func main() {
	var repoRoot string
	var write bool
	flag.StringVar(&repoRoot, "repo", ".", "repository root")
	flag.BoolVar(&write, "write", false, "write the manifest instead of checking it")
	flag.Parse()

	var err error
	if write {
		err = wasmartifacts.Write(repoRoot)
	} else {
		err = wasmartifacts.Check(repoRoot)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasmartifactmanifest: %v\n", err)
		os.Exit(1)
	}
}
