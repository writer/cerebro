// Command openapitsgen generates TypeScript type definitions from the Cerebro
// OpenAPI spec. It reads api/openapi.yaml and writes generated types to the
// specified output path.
//
// Usage:
//
//	go run ./tools/openapitsgen/cmd -spec api/openapi.yaml -out sdk/typescript/src/generated/openapi-types.ts
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/tools/openapitsgen"
)

func main() {
	var specPath string
	var outPath string
	var check bool
	flag.StringVar(&specPath, "spec", "api/openapi.yaml", "OpenAPI spec path")
	flag.StringVar(&outPath, "out", "", "output TypeScript file path; stdout when empty")
	flag.BoolVar(&check, "check", false, "check mode: verify output matches existing file")
	flag.Parse()

	specPayload, err := os.ReadFile(strings.TrimSpace(specPath)) // #nosec G304 -- operator path.
	if err != nil {
		fail(fmt.Errorf("read spec: %w", err))
	}
	result, err := openapitsgen.Generate(specPayload)
	if err != nil {
		fail(err)
	}

	if check && strings.TrimSpace(outPath) != "" {
		existing, err := os.ReadFile(strings.TrimSpace(outPath)) // #nosec G304 -- operator path.
		if err != nil {
			fail(fmt.Errorf("read existing output for check: %w", err))
		}
		if string(existing) != result.TypeScript {
			fail(fmt.Errorf("generated TypeScript types are stale; run 'make openapi-ts-generate' to update"))
		}
		fmt.Fprintf(os.Stderr, "openapitsgen: %d types up-to-date in %s\n", result.TypeCount, outPath)
		return
	}

	if strings.TrimSpace(outPath) == "" {
		fmt.Print(result.TypeScript)
		fmt.Fprintf(os.Stderr, "openapitsgen: generated %d types\n", result.TypeCount)
		return
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		fail(err)
	}
	if err := os.WriteFile(outPath, []byte(result.TypeScript), 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "openapitsgen: wrote %d types to %s\n", result.TypeCount, outPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
