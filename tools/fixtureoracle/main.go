package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/writer/cerebro/internal/sourceruntime"
)

func main() {
	root := flag.String("root", ".", "repository root")
	write := flag.Bool("write", false, "write the generated oracle")
	flag.Parse()

	matrix, err := sourceruntime.BuildGoFixtureOracleMatrix(*root)
	if err != nil {
		fatalf("build fixture oracle: %v", err)
	}
	payload, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		fatalf("encode fixture oracle: %v", err)
	}
	payload = append(payload, '\n')
	path := filepath.Join(*root, "crates", "source-runtime-next", "testdata", "go_fixture_oracle.json")
	if *write {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			fatalf("write fixture oracle: %v", err)
		}
		return
	}

	// #nosec G304 -- path is the fixed generated artifact under an operator-selected repository root.
	current, err := os.ReadFile(path)
	if err != nil {
		fatalf("read fixture oracle: %v", err)
	}
	if !bytes.Equal(current, payload) {
		fatalf("fixture oracle drifted; run go run ./tools/fixtureoracle -root . -write")
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
